package keyvault_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

// TestRotateDataDEKReencryptsAll DEK 輪替：全量重加密至新版本、舊版轉 retired、
// 新舊密文皆可讀
func TestRotateDataDEKReencryptsAll(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)

	result, err := km.RotateDataDEK()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if result.FromVersion != 1 || result.ToVersion != 2 {
		t.Fatalf("版本應 1→2：%+v", result)
	}
	if result.Reencrypted != 5 || result.Failed != 0 || result.Pending != 0 {
		t.Fatalf("應重加密 5 值：%+v", result)
	}

	// 全部值帶 v2 前綴且可解
	var vals []string
	db.Raw("SELECT password_enc FROM assets WHERE name = 'a1'").Scan(&vals)
	if !strings.HasPrefix(vals[0], "enc:a1:v2:") {
		t.Fatalf("輪替後應為 v2 前綴: %q", vals[0][:8])
	}
	if got, err := decryptColumn(km, "assets", "password_enc", vals[0]); err != nil || got != "asset-password" {
		t.Fatalf("輪替後解密: %q err=%v", got, err)
	}

	// 舊版 retired、新寫入用 v2
	var oldStatus string
	db.Raw("SELECT status FROM data_keys WHERE purpose = 'data' AND version = 1").Scan(&oldStatus)
	if oldStatus != model.DataKeyStatusRetired {
		t.Fatalf("v1 應 retired，得 %q", oldStatus)
	}
	ct := encryptColumn(t, km, "assets", "password_enc", "new-value")
	if !strings.HasPrefix(ct, "enc:a1:v2:") {
		t.Fatalf("新寫入應用 v2: %q", ct[:8])
	}
}

// TestRewrapKEKFullFlow 重包全流程：雙包裹並存→未換 env 重啟不鎖死→
// 新 KEK 重啟切換成功並清舊列
func TestRewrapKEKFullFlow(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	ct := encryptColumn(t, km, "assets", "password_enc", "survive-rewrap")

	resultMaterial, result := mustRewrapKEK(t, km)
	if len(resultMaterial) != 32 || result.NewKEKID == "" || result.NewKEKID == km.KEKKeyID() {
		t.Fatalf("新 KEK 形制不符: len=%d id=%s", len(resultMaterial), result.NewKEKID)
	}
	if !km.RewrapPending() {
		t.Fatal("重包後應標 pending")
	}
	// 雙包裹並存：每 (purpose,version) 新舊各一列
	var total, mine int64
	db.Model(&model.DataKey{}).Count(&total)
	db.Model(&model.DataKey{}).Where("kek_id = ?", km.KEKKeyID()).Count(&mine)
	if total != mine*2 {
		t.Fatalf("應新舊雙包裹並存：total=%d mine=%d", total, mine)
	}

	// 未換 env 重啟（舊 KEK）：照常啟動、pending 續標、資料可讀
	oldKEK, _ := crypto.NewEnvKEKProvider(kmTestKey(1))
	kmOld, err := keyvault.InitKeyManager(db, oldKEK)
	if err != nil {
		t.Fatalf("舊 KEK 重啟不應失敗: %v", err)
	}
	if !kmOld.RewrapPending() {
		t.Fatal("舊 KEK 重啟應續標重包未完成")
	}
	if got, err := decryptColumn(kmOld, "assets", "password_enc", ct); err != nil || got != "survive-rewrap" {
		t.Fatalf("舊 KEK 解密: %q err=%v", got, err)
	}

	// 換 env 重啟（新 KEK）：切換成功、清舊列、資料可讀
	newProvider, _ := crypto.NewEnvKEKProvider([]byte(resultMaterial))
	kmNew, err := keyvault.InitKeyManager(db, newProvider)
	if err != nil {
		t.Fatalf("新 KEK 重啟失敗: %v", err)
	}
	if kmNew.RewrapPending() {
		t.Fatal("新 KEK 切換後不應再標 pending")
	}
	// 切換後舊列軟退役保留（非硬刪）：現行 KEK 未退役列=mine、
	// 舊 KEK 列軟退役保留（kek_retired_at 非空、wrapped 已清）
	var currentLive, retired int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_retired_at IS NULL", result.NewKEKID).Count(&currentLive)
	db.Model(&model.DataKey{}).Where("kek_retired_at IS NOT NULL").Count(&retired)
	if currentLive != mine {
		t.Fatalf("切換後現行未退役列應為 %d，得 %d", mine, currentLive)
	}
	if retired != mine {
		t.Fatalf("舊列應軟退役保留 %d 筆，得 %d", mine, retired)
	}
	if got, err := decryptColumn(kmNew, "assets", "password_enc", ct); err != nil || got != "survive-rewrap" {
		t.Fatalf("新 KEK 解密: %q err=%v", got, err)
	}
	// 換 KEK 不動資料本體
	var vals []string
	db.Raw("SELECT password_enc FROM assets WHERE name = 'a1'").Scan(&vals)
	if got, err := decryptColumn(kmNew, "assets", "password_enc", vals[0]); err != nil || got != "asset-password" {
		t.Fatalf("資料本體應不變且可讀: %q err=%v", got, err)
	}
}

// TestAbandonRewrap 放棄未切換重包：只刪外來列、現行 KEK 列全存、清 pending、
// 資料仍可解；非 pending 拒絕；放棄後可再重包（連續二次場景基礎）
func TestAbandonRewrap(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	ct := encryptColumn(t, km, "assets", "password_enc", "survive-abandon")

	// 非 pending 時放棄：拒絕
	if _, err := km.AbandonRewrap(); !errors.Is(err, keyvault.ErrNoRewrapPending) {
		t.Fatalf("非 pending 放棄應回 keyvault.ErrNoRewrapPending，得 %v", err)
	}

	// 重包 → pending、雙包裹並存
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	var total, mine int64
	db.Model(&model.DataKey{}).Count(&total)
	db.Model(&model.DataKey{}).Where("kek_id = ?", km.KEKKeyID()).Count(&mine)
	if total != mine*2 || !km.RewrapPending() {
		t.Fatalf("重包後應雙包裹並存＋pending：total=%d mine=%d pending=%v", total, mine, km.RewrapPending())
	}

	// 放棄：軟退役外來列數 == mine（每對一列外來）——
	// 軟刪除：不硬刪、材料保留至顯式清理、reason=abandoned、無 replacement
	abandonedCount, err := km.AbandonRewrap()
	if err != nil {
		t.Fatalf("abandon: %v", err)
	}
	if int64(abandonedCount) != mine {
		t.Fatalf("放棄應軟退役 %d 筆外來列，得 %d", mine, abandonedCount)
	}
	if km.RewrapPending() {
		t.Fatal("放棄後不應再標 pending")
	}
	// 現行 KEK live 列全存；外來列不刪、全數轉 abandoned 退役且材料保留
	var afterMineLive int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_retired_at IS NULL", km.KEKKeyID()).Count(&afterMineLive)
	if afterMineLive != mine {
		t.Fatalf("放棄後現行 KEK live 列應全存：得 %d want %d", afterMineLive, mine)
	}
	var foreignRows []model.DataKey
	db.Where("kek_id <> ?", km.KEKKeyID()).Find(&foreignRows)
	if int64(len(foreignRows)) != mine {
		t.Fatalf("放棄後外來列應保留（軟退役）：得 %d want %d", len(foreignRows), mine)
	}
	for _, r := range foreignRows {
		if r.KEKRetiredAt == nil || r.KEKPending ||
			r.KEKRetiredReason != model.KEKRetireReasonAbandoned || r.KEKRetiredBy != "" {
			t.Fatalf("外來列應為 abandoned 退役形狀（retired_at 非空、非 pending、reason=abandoned、無 replacement）：%+v", r)
		}
		if r.WrappedKey == "" {
			t.Fatalf("放棄不得清空材料（銷毀僅發生於顯式清理）：%+v", r)
		}
	}
	// 資料仍以現行 KEK 可解
	if got, err := decryptColumn(km, "assets", "password_enc", ct); err != nil || got != "survive-abandon" {
		t.Fatalf("放棄後現行 KEK 解密應正常: %q err=%v", got, err)
	}

	// 放棄後可再重包
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("放棄後再重包應成功: %v", err)
	}
	if !km.RewrapPending() {
		t.Fatal("再重包後應標 pending")
	}
}

// TestRotateDataDEKPartialResume 回歸釘子：partial 後再按輪替必須以現行版本
// 續跑，不得每按一次鑄一個新版本（連環膨脹）
func TestRotateDataDEKPartialResume(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	t.Setenv("KEY_ROTATION_MAX_PER_RUN", "2") // 5 值、單輪上限 2 → 必 partial

	first, err := km.RotateDataDEK()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if first.FromVersion != 1 || first.ToVersion != 2 || first.Resumed {
		t.Fatalf("首輪應鑄 v2：%+v", first)
	}
	if first.Reencrypted != 2 || first.Pending != 3 {
		t.Fatalf("首輪應達上限 partial：%+v", first)
	}

	// 續跑直到殘值歸零：每一輪都必須是 v2 續跑，不得鑄新版
	//（MaxOps 為批次粒度軟上限，單批內可能溢出，不斷言逐輪筆數）
	last := first
	for i := 0; last.Pending > 0; i++ {
		if i >= 5 {
			t.Fatalf("續跑 %d 輪仍未清完殘值：%+v", i, last)
		}
		resumed, err := km.RotateDataDEK()
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		if !resumed.Resumed || resumed.FromVersion != 2 || resumed.ToVersion != 2 {
			t.Fatalf("殘值未清應續跑 v2 不得鑄新版：%+v", resumed)
		}
		last = resumed
	}

	// 續跑期間只鑄了一個新版本
	var dataVersions int64
	db.Model(&model.DataKey{}).Where("purpose = ?", model.DataKeyPurposeData).Count(&dataVersions)
	if dataVersions != 2 {
		t.Fatalf("data 鑰應只有 v1/v2 兩代，得 %d 列", dataVersions)
	}

	// 殘值歸零後的下一次呼叫才是真輪替
	fourth, err := km.RotateDataDEK()
	if err != nil {
		t.Fatalf("rotate v3: %v", err)
	}
	if fourth.Resumed || fourth.FromVersion != 2 || fourth.ToVersion != 3 {
		t.Fatalf("殘值歸零後應鑄 v3：%+v", fourth)
	}
}

// TestRotateBlockedWhileRewrapPending 回歸釘子：KEK 重包待切換期間拒絕輪替——
// 此時鑄的新鑰以舊 KEK 包裹、不在重包列中，切新 KEK 重啟會 KEK 不符鎖死
func TestRotateBlockedWhileRewrapPending(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	if _, err := km.RotateDataDEK(); !errors.Is(err, keyvault.ErrRewrapPending) {
		t.Fatalf("重包待切換應拒絕 data 輪替，得 %v", err)
	}
	if _, err := km.RotateAuditKey(); !errors.Is(err, keyvault.ErrRewrapPending) {
		t.Fatalf("重包待切換應拒絕蓋章鑰輪替，得 %v", err)
	}
}
