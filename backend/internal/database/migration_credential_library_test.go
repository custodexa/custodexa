package database

import (
	"context"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 存量搬移與隱性共用關係合併的行為面測試。
//
// **在 sqlite 上跑而非 pg**：受測對象是資料轉換的**語義**（誰得到哪一筆憑證、
// 明文一致才合併、失敗整批回滾），不是 DDL 的方言。結構面（建表、索引、Down／Up）
// 由同名 _pg_test.go 的整合測試承擔，兩層各守一半。
//
// 金鑰一律用真的 KeyManager 而非假的 codec：合併的判定依賴 AAD 綁定
// （表|欄）正確，假 codec 會讓「ref 傳錯」這種缺陷靜默通過。

func newCredentialLibraryDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// :memory: 連線池陷阱：多條連線各自是一個空庫，寫在 A 讀在 B 會偶發查無資料
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	// 信封目標表一併建出：金鑰服務的殘餘掃描逐表計數，缺表即整個掃描失敗
	// （測試環境產物，非受測邏輯）
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.User{},
		&model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{},
		&model.LDAPDirectory{}, &model.NotificationChannel{}, &model.AuditLog{},
		&model.DataKey{}, &model.ChangeSecretCandidate{}, &model.ClipboardEvent{},
		&model.OffsiteProfile{},
		&model.Credential{}, &model.CredentialSecretVersion{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// schema_migrations 屬 repository 層，測試以等價表建立（marker 的落點）
	if err := db.Exec(
		"CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	// 生產等價索引語義（唯一索引轉 partial，退役列不阻擋同 KEK 重試）
	for _, stmt := range []string{
		"DROP INDEX IF EXISTS idx_data_keys_purpose_version_kek",
		"CREATE UNIQUE INDEX idx_data_keys_purpose_version_kek ON data_keys (purpose, version, kek_id) WHERE kek_retired_at IS NULL",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("partial index: %v", err)
		}
	}
	seedLegacyAccountColumns(t, db)
	return db
}

// seedLegacyAccountColumns 補回帳號列在憑證化之前的三個欄位。
//
// **受測對象正是這個形狀**：存量搬移要讀的就是帳號自持的密文與群組識別。
// model 已不再宣告它們（密文兩欄的資料庫欄位亦已卸下，群組識別欄則只剩解封後
// 轉換一個讀者），AutoMigrate 因此建不出來，故由測試自行補齊。
func seedLegacyAccountColumns(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, stmt := range []string{
		`ALTER TABLE asset_accounts ADD COLUMN password_enc text`,
		`ALTER TABLE asset_accounts ADD COLUMN private_key_enc text`,
		`ALTER TABLE asset_accounts ADD COLUMN credential_group varchar(36)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("補回憑證化之前的帳號欄位失敗（%s）: %v", stmt, err)
		}
	}
}

func newCredentialLibraryKM(t *testing.T, db *gorm.DB) *keyvault.KeyManagerService {
	t.Helper()
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i + 1)
	}
	kek, err := crypto.NewEnvKEKProvider(material)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	return km
}

// seedAsset 建一台資產並回傳 id
func seedAsset(t *testing.T, db *gorm.DB, name string, protocol model.ProtocolType) uint {
	t.Helper()
	asset := model.Asset{Name: name, Host: "10.0.0.1", Port: 22, Protocol: protocol}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatalf("seed 資產 %s: %v", name, err)
	}
	return asset.ID
}

// seedAccount 建一筆帶密文的帳號列（憑證化之前的形狀）
func seedAccount(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService,
	assetID uint, username, password, group string) uint {
	t.Helper()
	enc := ""
	if password != "" {
		var err error
		enc, err = km.EncryptFor(context.Background(), keyvault.RefAccountPassword, password)
		if err != nil {
			t.Fatalf("加密帳號密碼: %v", err)
		}
	}
	acc := model.AssetAccount{
		AssetID:    assetID,
		Username:   username,
		IsDefault:  true,
		AuthMethod: "sql",
	}
	if err := db.Create(&acc).Error; err != nil {
		t.Fatalf("seed 帳號 %s: %v", username, err)
	}
	// 密文與群組識別走原生 SQL：兩者已不在 model 上（見 seedLegacyAccountColumns）
	if err := db.Exec(`UPDATE asset_accounts SET password_enc = ?, credential_group = ? WHERE id = ?`,
		enc, group, acc.ID).Error; err != nil {
		t.Fatalf("seed 帳號 %s 的舊欄位: %v", username, err)
	}
	return acc.ID
}

func countRows(t *testing.T, db *gorm.DB, sql string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(sql, args...).Scan(&n).Error; err != nil {
		t.Fatalf("計數失敗（%s）: %v", sql, err)
	}
	return n
}

// TestCredentialLibraryMigrationConvertsAccounts 既有帳號逐筆轉專用憑證，
// 密文原樣搬、就位版本直指 v1，且沒有任何帳號失去憑證。
func TestCredentialLibraryMigrationConvertsAccounts(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	sshAsset := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	rdpAsset := seedAsset(t, db, "win-a", model.ProtocolRDP)
	withSecret := seedAccount(t, db, km, sshAsset, "root", "p@ss-a", "")
	windows := seedAccount(t, db, km, rdpAsset, "Administrator", "p@ss-b", "")
	// 無任何密文的帳號：轉換後仍要有憑證，但**不得**憑空生出一個空的就位版本
	noSecret := seedAccount(t, db, km, sshAsset, "ops", "", "")

	var beforeEnc string
	if err := db.Raw(`SELECT password_enc FROM asset_accounts WHERE id = ?`, withSecret).
		Scan(&beforeEnc).Error; err != nil {
		t.Fatalf("讀取轉換前密文: %v", err)
	}

	converted, err := convertAccountsToDedicatedCredentials(db)
	if err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	if converted.Live != 3 || converted.Retired != 0 {
		t.Fatalf("轉換筆數 = 存活 %d 筆／隨已移除資產一併移除 %d 筆, want 3／0",
			converted.Live, converted.Retired)
	}

	if n := countRows(t, db, `SELECT count(*) FROM asset_accounts WHERE credential_id = 0`); n != 0 {
		t.Fatalf("仍有 %d 筆帳號沒有憑證：轉換的第一條不變式就是「無任何帳號失去憑證」", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ?`,
		model.CredentialScopeDedicated); n != 3 {
		t.Fatalf("專用憑證數 = %d, want 3", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE name IS NOT NULL`); n != 0 {
		t.Fatalf("有 %d 筆專用憑證帶名稱：專用的顯示名是計算值，不落庫", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credential_secret_versions`); n != 2 {
		t.Fatalf("密文版本數 = %d, want 2（無密文的帳號不建版本）", n)
	}

	// 密文原樣搬：段 1 沒有 codec，不解密重加密，故字串逐字相同。
	// **它此刻仍帶帳號表的欄位身分**——改綁是解封後轉換的第一步（見下方斷言）
	var version model.CredentialSecretVersion
	if err := db.Joins("JOIN asset_accounts a ON a.effective_version_id = credential_secret_versions.id").
		Where("a.id = ?", withSecret).First(&version).Error; err != nil {
		t.Fatalf("讀取就位版本: %v", err)
	}
	if version.PasswordEnc != beforeEnc {
		t.Fatalf("密文未原樣搬移：轉換後 %q，轉換前 %q", version.PasswordEnc, beforeEnc)
	}
	if version.VersionNo != 1 || version.CreatedReason != model.CredentialVersionReasonMigration {
		t.Fatalf("v1 版本的序號／原因不符: %+v", version)
	}
	plain, err := km.DecryptFor(context.Background(), keyvault.RefCredentialVersionPassword, version.PasswordEnc)
	if err == nil {
		t.Fatalf("以新表身分解封剛搬入的密文竟成功（%q）：AAD 綁 表|欄，搬表後身分必然改變。"+
			"此處成功代表 AAD 綁定失效——而那會讓解封後轉換的改綁步驟變成一個沒有作用的空操作", plain)
	}

	// 就位版本必屬同一憑證
	var cred model.Credential
	if err := db.Joins("JOIN asset_accounts a ON a.credential_id = credentials.id").
		Where("a.id = ?", withSecret).First(&cred).Error; err != nil {
		t.Fatalf("讀取憑證: %v", err)
	}
	if cred.CurrentVersionID == nil || *cred.CurrentVersionID != version.ID {
		t.Fatalf("憑證的現行版本 = %v, want %d", cred.CurrentVersionID, version.ID)
	}
	if cred.ProtocolFamily != model.ProtocolFamilySSH {
		t.Fatalf("ssh 資產的協定族 = %q, want %q", cred.ProtocolFamily, model.ProtocolFamilySSH)
	}

	var winCred model.Credential
	if err := db.Joins("JOIN asset_accounts a ON a.credential_id = credentials.id").
		Where("a.id = ?", windows).First(&winCred).Error; err != nil {
		t.Fatalf("讀取 rdp 資產的憑證: %v", err)
	}
	if winCred.ProtocolFamily != model.ProtocolFamilyWindows {
		t.Fatalf("rdp 資產的協定族 = %q, want %q", winCred.ProtocolFamily, model.ProtocolFamilyWindows)
	}

	var noSecretAcc model.AssetAccount
	if err := db.First(&noSecretAcc, noSecret).Error; err != nil {
		t.Fatalf("讀取無密文帳號: %v", err)
	}
	if noSecretAcc.CredentialID == 0 {
		t.Fatal("無密文的帳號也必須有憑證：帳號名屬憑證，掛載列不再自持")
	}
	if noSecretAcc.EffectiveVersionID != nil {
		t.Fatalf("無密文的帳號不得有就位版本（實得 %d）：就位版本為空正是"+
			"「該掛載尚未取得任何密文」的唯一表達", *noSecretAcc.EffectiveVersionID)
	}
}

// TestCredentialLibraryMigrationRebindsCiphertextToVersionTable 段 1 原樣搬入的密文
// 於解封後轉換改綁到密文版本表的欄位身分。
//
// **不改綁會壞兩件事**：信封盤點清單以 表|欄 為身分逐欄解密重加密，整批舊身分的值
// 會在 DEK 輪替與退役金鑰引用掃描時逐筆失敗；取密路徑也得永遠記得「這一版是舊身分」。
func TestCredentialLibraryMigrationRebindsCiphertextToVersionTable(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	asset := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	seedAccount(t, db, km, asset, "root", "p@ss-a", "")
	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}

	var before model.CredentialSecretVersion
	if err := db.First(&before).Error; err != nil {
		t.Fatalf("讀取搬入的版本: %v", err)
	}
	if _, err := km.DecryptFor(context.Background(), keyvault.RefCredentialVersionPassword, before.PasswordEnc); err == nil {
		t.Fatal("前提不成立：剛搬入的密文不應以版本表身分解得開，否則本測試證明不了改綁真的發生")
	}

	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}

	var after model.CredentialSecretVersion
	if err := db.First(&after, before.ID).Error; err != nil {
		t.Fatalf("讀取改綁後的版本: %v", err)
	}
	plain, err := km.DecryptFor(context.Background(), keyvault.RefCredentialVersionPassword, after.PasswordEnc)
	if err != nil || plain != "p@ss-a" {
		t.Fatalf("改綁後應以版本表身分解回原明文，實得 %q err=%v", plain, err)
	}
	if after.PasswordEnc == before.PasswordEnc {
		t.Fatal("密文字串未改變：改綁沒有真的重加密")
	}
	if _, err := km.DecryptFor(context.Background(), keyvault.RefAccountPassword, after.PasswordEnc); err == nil {
		t.Fatal("改綁後仍以帳號表身分解得開：舊身分沒有退場")
	}
	// 帳號列的舊密文欄在本 migration 內原樣保留（卸下是收縮階段的事），且仍是帳號表身分
	var accountEnc string
	if err := db.Raw(`SELECT password_enc FROM asset_accounts LIMIT 1`).Scan(&accountEnc).Error; err != nil {
		t.Fatalf("讀取帳號列密文: %v", err)
	}
	if accountEnc != before.PasswordEnc {
		t.Fatal("帳號列的密文欄被動到了：本 migration 只擴不縮，舊欄應原樣保留")
	}
}

// TestCredentialLibraryMigrationMergesIdenticalGroup 明文一致的隱性群組合併為
// 一筆具名共用憑證，成員的專用憑證與版本一併刪除。
func TestCredentialLibraryMigrationMergesIdenticalGroup(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
	accA := seedAccount(t, db, km, assetA, "ops", "same-secret", "group-1")
	accB := seedAccount(t, db, km, assetB, "ops", "same-secret", "group-1")

	// 前提條件：兩筆密文**不相等**（各自的隨機 nonce），故合併判定非解密不可
	var encA, encB string
	_ = db.Raw(`SELECT password_enc FROM asset_accounts WHERE id = ?`, accA).Scan(&encA).Error
	_ = db.Raw(`SELECT password_enc FROM asset_accounts WHERE id = ?`, accB).Scan(&encB).Error
	if encA == "" || encA == encB {
		t.Fatalf("前提不成立：同明文的兩份密文應不相等（A=%q B=%q），"+
			"否則本測試無法證明合併走的是解密比對", encA, encB)
	}

	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}

	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE deleted_at IS NULL`); n != 1 {
		t.Fatalf("合併後憑證數 = %d, want 1（兩筆專用併為一筆共用）", n)
	}
	var shared model.Credential
	if err := db.First(&shared).Error; err != nil {
		t.Fatalf("讀取共用憑證: %v", err)
	}
	if shared.Scope != model.CredentialScopeShared {
		t.Fatalf("範圍 = %q, want %q", shared.Scope, model.CredentialScopeShared)
	}
	if shared.Name == nil || *shared.Name != sharedCredentialAutoNamePrefix+"1" {
		t.Fatalf("自動命名 = %v, want %q", shared.Name, sharedCredentialAutoNamePrefix+"1")
	}
	if n := countRows(t, db, `SELECT count(*) FROM credential_secret_versions`); n != 1 {
		t.Fatalf("合併後密文版本數 = %d, want 1（成員的專用版本一併刪除）", n)
	}
	for _, id := range []uint{accA, accB} {
		var acc model.AssetAccount
		if err := db.First(&acc, id).Error; err != nil {
			t.Fatalf("讀取帳號 #%d: %v", id, err)
		}
		if acc.CredentialID != shared.ID {
			t.Fatalf("帳號 #%d 的憑證 = %d, want %d", id, acc.CredentialID, shared.ID)
		}
		if acc.EffectiveVersionID == nil || shared.CurrentVersionID == nil ||
			*acc.EffectiveVersionID != *shared.CurrentVersionID {
			t.Fatalf("帳號 #%d 的就位版本未指向共用憑證的現行版本", id)
		}
	}
	// 合併後的密文以**版本表的欄位身分**解得開：轉換的第一步已把段 1 原樣搬入的
	// 值逐筆改綁，合併時的複製才是同表同欄的列間複製
	var merged model.CredentialSecretVersion
	if err := db.First(&merged).Error; err != nil {
		t.Fatalf("讀取合併後版本: %v", err)
	}
	plain, err := km.DecryptFor(context.Background(), keyvault.RefCredentialVersionPassword, merged.PasswordEnc)
	if err != nil || plain != "same-secret" {
		t.Fatalf("合併後密文應以版本表身分解得回原明文，實得 %q err=%v", plain, err)
	}
	if _, err := km.DecryptFor(context.Background(), keyvault.RefAccountPassword, merged.PasswordEnc); err == nil {
		t.Fatal("合併後密文仍以帳號表身分解得開：改綁沒有真的發生，" +
			"DEK 輪替與退役金鑰引用掃描會逐筆失敗")
	}

	// 冪等閘：marker 已寫入，第二次執行不再產生第二筆憑證
	if !markerWritten(t, db) {
		t.Fatal("合併成功卻未寫入執行標記：下次啟動會再跑一次")
	}
	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("第二次執行應為 no-op: %v", err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE deleted_at IS NULL`); n != 1 {
		t.Fatalf("第二次執行後憑證數 = %d, want 1（標記應擋下重複轉換）", n)
	}
}

// TestCredentialLibraryMigrationKeepsMismatchedGroupSeparate 明文不一致的群組
// 不合併：各留專用憑證、標記待處理、寫一筆審計列。
func TestCredentialLibraryMigrationKeepsMismatchedGroupSeparate(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
	accA := seedAccount(t, db, km, assetA, "ops", "secret-a", "group-x")
	accB := seedAccount(t, db, km, assetB, "ops", "secret-b", "group-x")

	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	if err := RunCredentialSecretConversion(db, km); err != nil {
		t.Fatalf("轉換失敗: %v", err)
	}

	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ?`,
		model.CredentialScopeShared); n != 0 {
		t.Fatalf("不一致的群組被合併成 %d 筆共用憑證：任一成員不一致即不得合併", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ?`,
		model.CredentialScopeDedicated); n != 2 {
		t.Fatalf("專用憑證數 = %d, want 2", n)
	}
	for _, id := range []uint{accA, accB} {
		var acc model.AssetAccount
		if err := db.First(&acc, id).Error; err != nil {
			t.Fatalf("讀取帳號 #%d: %v", id, err)
		}
		var cred model.Credential
		if err := db.First(&cred, acc.CredentialID).Error; err != nil {
			t.Fatalf("讀取帳號 #%d 的憑證: %v", id, err)
		}
		want := MigrationGroupMismatchPrefix + "group-x]"
		if !strings.HasPrefix(cred.Note, want) {
			t.Fatalf("憑證 #%d 的備註 = %q, want 前置 %q", cred.ID, cred.Note, want)
		}
	}
	var logs []model.AuditLog
	if err := db.Where("resource = ? AND action = ?",
		model.ResourceCredential, model.ActionMigration).Find(&logs).Error; err != nil {
		t.Fatalf("讀取審計列: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("待處理審計列 = %d 筆, want 1", len(logs))
	}
	if !strings.Contains(logs[0].Details, "group-x") ||
		!strings.Contains(logs[0].Details, "group_secrets_mismatch") {
		t.Fatalf("審計列未載明群組與原因: %q", logs[0].Details)
	}
	for _, forbidden := range []string{"secret-a", "secret-b"} {
		if strings.Contains(logs[0].Details, forbidden) {
			t.Fatalf("審計列含秘密材料 %q：轉換的證據面不得落任何明文", forbidden)
		}
	}
	if !markerWritten(t, db) {
		t.Fatal("評估完畢卻未寫入執行標記：每次啟動都會重覆標記與重覆寫審計")
	}
}

// failingCodec 解密恆失敗的 codec（模擬金鑰不可用／密文不可解）。
type failingCodec struct{}

func (failingCodec) EncryptFor(context.Context, crypto.CipherRef, string) (string, error) {
	return "", errCodecUnavailable
}
func (failingCodec) DecryptFor(context.Context, crypto.CipherRef, string) (string, error) {
	return "", errCodecUnavailable
}

var errCodecUnavailable = &codecUnavailableError{}

type codecUnavailableError struct{}

func (*codecUnavailableError) Error() string { return "資料金鑰不可用" }

// TestCredentialLibraryMigrationFailsClosedWithoutDEK 金鑰不可用時大聲失敗並整批
// 回滾，**不得**降級為「全部各建專用憑證」。
func TestCredentialLibraryMigrationFailsClosedWithoutDEK(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	assetA := seedAsset(t, db, "ssh-a", model.ProtocolSSH)
	assetB := seedAsset(t, db, "ssh-b", model.ProtocolSSH)
	seedAccount(t, db, km, assetA, "ops", "same-secret", "group-1")
	seedAccount(t, db, km, assetB, "ops", "same-secret", "group-1")
	if _, err := convertAccountsToDedicatedCredentials(db); err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}

	// 情形一：完全沒有 codec
	if err := RunCredentialSecretConversion(db, nil); err == nil {
		t.Fatal("金鑰不可用時合併竟成功：跳過等於靜默丟掉全部共用關係")
	}
	// 情形二：codec 在，但解不開（金鑰材料已不可用）
	err := RunCredentialSecretConversion(db, failingCodec{})
	if err == nil {
		t.Fatal("解密失敗時合併竟成功：不得降級為「全部各建專用」")
	}
	if !strings.Contains(err.Error(), "解密") {
		t.Fatalf("錯誤訊息應指出解密失敗，實得: %v", err)
	}

	if markerWritten(t, db) {
		t.Fatal("失敗卻寫了執行標記：下次啟動不會重試，共用關係永久丟失")
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ?`,
		model.CredentialScopeShared); n != 0 {
		t.Fatalf("失敗後仍留下 %d 筆共用憑證：交易未整批回滾", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE scope = ?`,
		model.CredentialScopeDedicated); n != 2 {
		t.Fatalf("失敗後專用憑證數 = %d, want 2（回到轉換前的形狀）", n)
	}
	// 密文版本仍帶搬入時的舊身分：改綁與合併同一交易，回滾即兩者都沒發生。
	// 那是刻意的——一個解不開的秘密必須被看見，不靠讀取路徑的相容分支蓋過去
	var version model.CredentialSecretVersion
	if err := db.First(&version).Error; err != nil {
		t.Fatalf("讀取密文版本: %v", err)
	}
	if _, err := km.DecryptFor(context.Background(), keyvault.RefAccountPassword, version.PasswordEnc); err != nil {
		t.Fatalf("回滾後密文版本應維持搬入時的身分（帳號表），實得解不開: %v", err)
	}
	// 憑證化之前的舊欄仍在：本 migration 只擴不縮，回滾後的庫仍是可用的舊形狀
	var probe struct {
		Username        string
		PasswordEnc     string
		PrivateKeyEnc   string
		AuthMethod      string
		CredentialGroup string
	}
	if err := db.Raw(`SELECT username, password_enc, private_key_enc, auth_method, credential_group
		FROM asset_accounts LIMIT 1`).Scan(&probe).Error; err != nil {
		t.Fatalf("憑證化之前的舊欄應原樣保留，實測讀取失敗: %v", err)
	}
	if probe.Username == "" || probe.PasswordEnc == "" || probe.CredentialGroup == "" {
		t.Fatalf("舊欄的值被清空了: %+v", probe)
	}
}

func markerWritten(t *testing.T, db *gorm.DB) bool {
	t.Helper()
	applied, err := migrationMarkerApplied(db, CredentialSecretConversionMarkerVersion)
	if err != nil {
		t.Fatalf("讀取執行標記: %v", err)
	}
	return applied
}

// TestCredentialLibraryMigrationRetiresAccountsOfDeletedAssets 所屬資產已軟刪的帳號列
// 視同「隨資產一起移除」：仍建專用憑證與 v1 密文版本（密文不丟），但掛載列與憑證
// 於同一交易一併軟刪。
//
// **舊版刪資產只軟刪 assets 一張表**，帳號列原樣留著；若搬移照單全收，升上來的庫
// 憑證庫一開就是一排指向已不存在主機的專用憑證。密文仍要搬，因為收縮 migration
// 會卸掉帳號表的密文欄——不建版本就是真的把它丟了。
func TestCredentialLibraryMigrationRetiresAccountsOfDeletedAssets(t *testing.T) {
	db := newCredentialLibraryDB(t)
	km := newCredentialLibraryKM(t, db)

	goneAsset := seedAsset(t, db, "ssh-gone", model.ProtocolSSH)
	liveAsset := seedAsset(t, db, "ssh-live", model.ProtocolSSH)
	goneAcc := seedAccount(t, db, km, goneAsset, "root", "p@ss-gone", "")
	liveAcc := seedAccount(t, db, km, liveAsset, "root", "p@ss-live", "")
	// 軟刪在帳號列建立之後：重現舊版「刪資產不連動掛載」留下的形狀
	if err := db.Delete(&model.Asset{}, goneAsset).Error; err != nil {
		t.Fatalf("軟刪資產: %v", err)
	}

	var goneEnc string
	if err := db.Raw(`SELECT password_enc FROM asset_accounts WHERE id = ?`, goneAcc).
		Scan(&goneEnc).Error; err != nil {
		t.Fatalf("讀取轉換前密文: %v", err)
	}
	if goneEnc == "" {
		t.Fatal("夾具無效：已移除資產的帳號列沒有密文，本案例就測不到「密文不丟」")
	}

	stats, err := convertAccountsToDedicatedCredentials(db)
	if err != nil {
		t.Fatalf("存量搬移失敗: %v", err)
	}
	if stats.Live != 1 || stats.Retired != 1 {
		t.Fatalf("分項計數 = 存活 %d 筆／隨已移除資產一併移除 %d 筆, want 1／1", stats.Live, stats.Retired)
	}

	// 兩筆帳號各得一筆憑證與一個版本：已移除的那一筆也不例外（密文不丟）
	if n := countRows(t, db, `SELECT count(*) FROM credentials`); n != 2 {
		t.Fatalf("憑證總數 = %d, want 2（已移除資產的帳號仍建憑證，只是一併軟刪）", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credential_secret_versions`); n != 2 {
		t.Fatalf("密文版本數 = %d, want 2", n)
	}

	var gone struct {
		CredentialID       uint
		EffectiveVersionID *uint
		Removed            bool
	}
	if err := db.Raw(`SELECT credential_id, effective_version_id,
		deleted_at IS NOT NULL AS removed FROM asset_accounts WHERE id = ?`, goneAcc).
		Scan(&gone).Error; err != nil {
		t.Fatalf("讀取已移除資產的掛載列: %v", err)
	}
	if !gone.Removed {
		t.Fatal("已移除資產的掛載列仍存活：舊版刪資產漏掉的連動要在搬移時補上，" +
			"否則憑證庫會顯示一排指向已不存在主機的專用憑證")
	}
	if gone.CredentialID == 0 || gone.EffectiveVersionID == nil {
		t.Fatalf("已移除資產的掛載列未回填憑證指標（credential_id=%d, effective_version_id=%v）："+
			"軟刪不等於丟掉線索", gone.CredentialID, gone.EffectiveVersionID)
	}

	var goneCred struct {
		CurrentVersionID *uint
		Removed          bool
		Scope            string
	}
	if err := db.Raw(`SELECT current_version_id, scope,
		deleted_at IS NOT NULL AS removed FROM credentials WHERE id = ?`, gone.CredentialID).
		Scan(&goneCred).Error; err != nil {
		t.Fatalf("讀取已移除資產的憑證: %v", err)
	}
	if !goneCred.Removed {
		t.Fatal("已移除資產的專用憑證仍存活：掛載與憑證兩邊要一致，" +
			"專用憑證的生滅綁在它唯一的掛載上")
	}
	if goneCred.Scope != model.CredentialScopeDedicated {
		t.Fatalf("憑證範圍 = %q, want %q", goneCred.Scope, model.CredentialScopeDedicated)
	}
	if goneCred.CurrentVersionID == nil || *goneCred.CurrentVersionID != *gone.EffectiveVersionID {
		t.Fatalf("憑證的現行版本 = %v, 掛載就位版本 = %d：兩者必須同指 v1",
			goneCred.CurrentVersionID, *gone.EffectiveVersionID)
	}

	var goneVersion struct {
		PasswordEnc  string
		VersionNo    int64
		CredentialID uint
	}
	if err := db.Raw(`SELECT password_enc, version_no, credential_id
		FROM credential_secret_versions WHERE id = ?`, *gone.EffectiveVersionID).
		Scan(&goneVersion).Error; err != nil {
		t.Fatalf("讀取已移除資產的密文版本: %v", err)
	}
	if goneVersion.PasswordEnc != goneEnc {
		t.Fatalf("密文未原樣搬移：搬移後 %q，搬移前 %q。收縮 migration 會卸掉帳號表的密文欄，"+
			"這一版就是它唯一的去處", goneVersion.PasswordEnc, goneEnc)
	}
	if goneVersion.VersionNo != 1 || goneVersion.CredentialID != gone.CredentialID {
		t.Fatalf("v1 版本的序號／歸屬不符: %+v", goneVersion)
	}

	// 對照組：存活資產的掛載列與憑證都不得被波及
	var live struct {
		CredentialID uint
		Removed      bool
	}
	if err := db.Raw(`SELECT credential_id, deleted_at IS NOT NULL AS removed
		FROM asset_accounts WHERE id = ?`, liveAcc).Scan(&live).Error; err != nil {
		t.Fatalf("讀取存活資產的掛載列: %v", err)
	}
	if live.Removed || live.CredentialID == 0 {
		t.Fatalf("存活資產的掛載列被誤傷（removed=%v, credential_id=%d）",
			live.Removed, live.CredentialID)
	}
	if n := countRows(t, db, `SELECT count(*) FROM credentials WHERE id = ? AND deleted_at IS NULL`,
		live.CredentialID); n != 1 {
		t.Fatal("存活資產的專用憑證被誤軟刪：該清的歸零，該留的要維持")
	}
}
