package keyvault

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// 委託拓撲的服務層守衛。
//
// 本層要守的是三件事，每一件的失效後果都直接落在「上鎖的資料金鑰送去哪裡解」上：
//
//	(1) 原子性：一次更新全有全無，不得留下半套目的地；
//	(2) 驗證的方向：非法值整筆拒絕且**既有值維持原值**（不是部分套用、也不是清空）；
//	(3) 金鑰識別只有一份事實：既有部署沿金鑰列的 kek_id，拓撲表不另存副本。

func setupTopologyDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	// 單一連線：`:memory:` 在連線池下每條連線各自一個獨立資料庫，
	// 多連線會讓「寫進去的列讀不到」表現為偶發失敗（既有教訓）。
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.KEKTopology{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func validVaultInput() KEKTopologyInput {
	return KEKTopologyInput{
		Provider: TopologyProviderVault, Address: "https://vault.example:8200",
		TransitKeyName: "custodexa-kek", RoleID: "role-fixture", UpdatedBy: "admin",
	}
}

// TestKEKTopologyUnsetIsNotAnError 未設定是正常的初始狀態，不是錯誤狀態。
//
// 全新安裝在解封頁完成設定之前即為此。呼叫端 SHALL NOT 以此為由非零退出——
// 委託部署此時停在已封存等待人工設定，那是本版刻意的語義。
func TestKEKTopologyUnsetIsNotAnError(t *testing.T) {
	db := setupTopologyDB(t)
	row, err := LoadKEKTopology(db)
	if !errors.Is(err, ErrKEKTopologyNotConfigured) {
		t.Fatalf("未設定時應回 ErrKEKTopologyNotConfigured，得 row=%v err=%v", row, err)
	}
}

// TestKEKTopologySaveAndLoad 首次設定與再次更新皆回得出前後值。
func TestKEKTopologySaveAndLoad(t *testing.T) {
	db := setupTopologyDB(t)
	before, after, err := SaveKEKTopology(db, validVaultInput())
	if err != nil {
		t.Fatalf("首次設定失敗: %v", err)
	}
	if before != nil {
		t.Fatalf("首次設定的前值應為 nil，得 %+v", before)
	}
	if after == nil || after.Address != "https://vault.example:8200" || after.RoleID != "role-fixture" {
		t.Fatalf("後值不符: %+v", after)
	}

	next := validVaultInput()
	next.Address = "https://vault-2.example:8200"
	before2, after2, err := SaveKEKTopology(db, next)
	if err != nil {
		t.Fatalf("更新失敗: %v", err)
	}
	if before2 == nil || before2.Address != "https://vault.example:8200" {
		t.Fatalf("更新的前值應為舊位址，得 %+v", before2)
	}
	if after2.Address != "https://vault-2.example:8200" {
		t.Fatalf("更新的後值不符: %+v", after2)
	}

	// 單列：更新不得新增第二列（兩列並存時「送去哪裡解」取決於讀取順序）。
	var count int64
	if err := db.Model(&model.KEKTopology{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("拓撲表應恆為單列，得 %d 列", count)
	}
}

// TestKEKTopologyPartialInvalidKeepsExistingValue 位址合法但角色識別缺 → 整筆拒絕且原值未變。
//
// 這正是單列表存在的理由：key-value 形態下這一筆會留下「位址已改、角色未改」的
// 半套目的地，而半套目的地是本表要防的那件事。
func TestKEKTopologyPartialInvalidKeepsExistingValue(t *testing.T) {
	db := setupTopologyDB(t)
	if _, _, err := SaveKEKTopology(db, validVaultInput()); err != nil {
		t.Fatalf("前置設定失敗: %v", err)
	}

	bad := validVaultInput()
	bad.Address = "https://vault-3.example:8200" // 合法
	bad.RoleID = ""                              // 缺項
	_, _, err := SaveKEKTopology(db, bad)
	var verr *KEKTopologyValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("缺角色識別應回驗證錯誤，得 %v", err)
	}
	if len(verr.Fields) != 1 || verr.Fields[0] != "role_id" {
		t.Fatalf("錯誤應指出缺少的欄位名，得 %v", verr.Fields)
	}
	// 錯誤只列欄位名，不回顯值。
	if msg := verr.Error(); contains(msg, "vault-3.example") {
		t.Fatalf("錯誤訊息不得回顯企圖值: %s", msg)
	}

	row, err := LoadKEKTopology(db)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.Address != "https://vault.example:8200" || row.RoleID != "role-fixture" {
		t.Fatalf("被拒的更新不得改動既有值，得 %+v", row)
	}
}

// TestKEKTopologyRejectsPlaintextAddress 非 HTTPS 位址被拒（不以警告後放行的方式接受）。
//
// 那條連線上走的是解包後的資料金鑰材料：明文傳輸等於把 DEK 交給路徑上的任何人。
func TestKEKTopologyRejectsPlaintextAddress(t *testing.T) {
	db := setupTopologyDB(t)
	for _, addr := range []string{
		"http://vault.example:8200",   // 明文
		"vault.example:8200",          // 無 scheme
		"https://",                    // 無主機
		" https://vault.example:8200", // 前導空白
		"https://u:p@vault.example",   // 帶使用者資訊
		"https://vault.example?x=1",   // 帶查詢字串
	} {
		in := validVaultInput()
		in.Address = addr
		_, _, err := SaveKEKTopology(db, in)
		var verr *KEKTopologyValidationError
		if !errors.As(err, &verr) {
			t.Fatalf("位址 %q 應被拒，得 %v", addr, err)
		}
	}
	if _, err := LoadKEKTopology(db); !errors.Is(err, ErrKEKTopologyNotConfigured) {
		t.Fatalf("全部被拒之後不得留下任何列，得 %v", err)
	}
}

// TestKEKTopologyAWSRequiresRegion AWS 分支要求服務區域且須為正規形式。
func TestKEKTopologyAWSRequiresRegion(t *testing.T) {
	db := setupTopologyDB(t)
	for _, region := range []string{"", "AP-NORTHEAST-1", "ap-northeast", "东京"} {
		_, _, err := SaveKEKTopology(db, KEKTopologyInput{
			Provider: TopologyProviderAWS, Region: region, UpdatedBy: "admin"})
		var verr *KEKTopologyValidationError
		if !errors.As(err, &verr) {
			t.Fatalf("區域 %q 應被拒，得 %v", region, err)
		}
	}
	if _, _, err := SaveKEKTopology(db, KEKTopologyInput{
		Provider: TopologyProviderAWS, Region: "ap-northeast-1", UpdatedBy: "admin"}); err != nil {
		t.Fatalf("合法區域應被接受: %v", err)
	}
}

// TestKEKTopologyGCPHasNoEditableFields GCP 沒有可編輯的拓撲欄位。
//
// 其完整 CryptoKey 資源名沿金鑰列的 kek_id，服務區域對 GCP 不生效；
// 開放編輯只會多出一份可與 kek_id 分歧的識別。
func TestKEKTopologyGCPHasNoEditableFields(t *testing.T) {
	if fields := EditableTopologyFields(TopologyProviderGCP); len(fields) != 0 {
		t.Fatalf("GCP 不應有可編輯欄位，得 %v", fields)
	}
	db := setupTopologyDB(t)
	_, _, err := SaveKEKTopology(db, KEKTopologyInput{Provider: TopologyProviderGCP, UpdatedBy: "admin"})
	if !errors.Is(err, ErrKEKTopologyNotEditable) {
		t.Fatalf("GCP 的拓撲更新應回 ErrKEKTopologyNotEditable，得 %v", err)
	}
}

// TestKEKTopologyDigestBindsEveryField 摘要涵蓋每一個欄位與金鑰識別。
//
// 摘要是解封頁「核對之後拓撲被改動即拒」的唯一判準：任何一欄改了而摘要不變，
// 就等於舊核對結果可以授權送往新目的地。
func TestKEKTopologyDigestBindsEveryField(t *testing.T) {
	base := &model.KEKTopology{Provider: "vault", Address: "https://a.example",
		TransitKeyName: "k", RoleID: "r", Region: ""}
	want := TopologyDigest(base, "kek-1")
	if want == "" {
		t.Fatal("摘要不得為空")
	}
	mutations := map[string]*model.KEKTopology{
		"provider":         {Provider: "aws", Address: "https://a.example", TransitKeyName: "k", RoleID: "r"},
		"address":          {Provider: "vault", Address: "https://b.example", TransitKeyName: "k", RoleID: "r"},
		"transit_key_name": {Provider: "vault", Address: "https://a.example", TransitKeyName: "k2", RoleID: "r"},
		"role_id":          {Provider: "vault", Address: "https://a.example", TransitKeyName: "k", RoleID: "r2"},
		"region":           {Provider: "vault", Address: "https://a.example", TransitKeyName: "k", RoleID: "r", Region: "ap-northeast-1"},
	}
	for field, m := range mutations {
		if TopologyDigest(m, "kek-1") == want {
			t.Errorf("改動 %s 之後摘要未變——核對綁定漏了這一欄", field)
		}
	}
	if TopologyDigest(base, "kek-2") == want {
		t.Error("改動金鑰識別之後摘要未變——核對綁定漏了金鑰識別")
	}
	// 欄位邊界不得有歧義：長度前綴使 `a|bc` 與 `ab|c` 不會雜湊到同一輸入。
	left := &model.KEKTopology{Provider: "va", Address: "ult"}
	right := &model.KEKTopology{Provider: "v", Address: "ault"}
	if TopologyDigest(left, "") == TopologyDigest(right, "") {
		t.Error("欄位邊界歧義：兩組不同的拓撲雜湊到同一值")
	}
}

// TestCurrentKEKIDIsTheOnlyKeyIdentity 金鑰識別的事實源是金鑰列，不是拓撲表。
func TestCurrentKEKIDIsTheOnlyKeyIdentity(t *testing.T) {
	db := setupTopologyDB(t)
	// 空金鑰表：回空字串而非錯誤（全新安裝的正常狀態）。
	id, err := CurrentKEKID(db)
	if err != nil || id != "" {
		t.Fatalf("空金鑰表應回空字串且無錯誤，得 %q / %v", id, err)
	}

	rows := []model.DataKey{
		{Purpose: "data", Version: 1, KEKID: "kek-current", WrappedKey: "x"},
		{Purpose: "audit_integrity", Version: 1, KEKID: "kek-current", WrappedKey: "y"},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err = CurrentKEKID(db)
	if err != nil || id != "kek-current" {
		t.Fatalf("應回現行代表列的 kek_id，得 %q / %v", id, err)
	}

	// 兩個相異引用並存＝換鑰精靈的中途狀態（新舊兩組現行列並存至切換完成）。
	// 此時本部署實際要用來解的是**新的**那一把；回錯會讓解封頁在一次正常的
	// 換鑰中途完全打不開，而那正是最需要它的時候。
	if err := db.Create(&model.DataKey{Purpose: "other", Version: 1, KEKID: "kek-next", WrappedKey: "z"}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err = CurrentKEKID(db)
	if err != nil {
		t.Fatalf("相異 kek_id 並存不應回錯: %v", err)
	}
	if id != "kek-next" {
		t.Fatalf("並存時應取最新建立的那一把，得 %q", id)
	}

	// 已退役的列不計入。
	if err := db.Model(&model.DataKey{}).Where("kek_id = ?", "kek-next").
		Update("kek_retired_at", time.Now()).Error; err != nil {
		t.Fatalf("retire: %v", err)
	}
	id, err = CurrentKEKID(db)
	if err != nil || id != "kek-current" {
		t.Fatalf("退役列不計入，應回 kek-current，得 %q / %v", id, err)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
