package keyvault

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// KEK 重包衛生強化測試組：跨實例互斥、收尾語義守衛、
// 軟刪除與回退指引。sqlite 環境走 package 級 try-mutex 等價路徑；
// postgres advisory lock 路徑另由 TestPGAdvisoryLockMutex（TEST_PG_DSN gating）覆蓋。

// TestAbandonThenFinalizeAborts abandon 先行、收尾後至（致命順序）：
// 收尾的 promote 列數守衛必須偵測 clones 已被放棄而整筆中止，
// data_keys 不得失去任何 live 列，任何列的材料不得被清空。
func TestAbandonThenFinalizeAborts(t *testing.T) {
	db, km := setupKM(t)
	resMaterial, _ := mustRewrapKEK(t, km)
	newProvider, _ := crypto.NewEnvKEKProvider([]byte(resMaterial))

	// 舊 KEK 實例放棄（clones 軟退役）
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("abandon: %v", err)
	}

	// 新 KEK 實例啟動收尾（交錯情境的第二步）——load 會呼叫 finalizeSwitch。
	// 放棄後新 KEK 已無 live 代表列，load 必須 fail-close（不可能刪光舊列後啟動）
	_, err := InitKeyManager(db, newProvider)
	if err == nil {
		t.Fatal("放棄後以新 KEK 啟動應 fail-close（無代表列）")
	}

	// 致命後果檢查：舊 KEK live 列必須原封不動（材料在、未退役）
	var oldLive int64
	db.Model(&model.DataKey{}).
		Where("kek_id = ? AND kek_retired_at IS NULL AND wrapped_key <> ''", km.KEKKeyID()).
		Count(&oldLive)
	if oldLive == 0 {
		t.Fatal("守衛失效：abandon＋收尾交錯後現行 KEK live 列被清光")
	}
	// 舊 KEK 實例重啟必須照常成功（資料可解）
	km2 := newTestKeyManager(t, db, 1)
	if km2 == nil {
		t.Fatal("舊 KEK 重啟失敗")
	}
}

// TestFinalizeThenAbandonRejected 收尾先行、abandon 後至：切換已完成，
// 舊 KEK 實例的放棄必須被拒（ErrNoRewrapPending），不得動到新 KEK 的現行列
func TestFinalizeThenAbandonRejected(t *testing.T) {
	db, km := setupKM(t)
	km2, _, newKEKID := rewrapAndReinit(t, db, km) // 收尾完成：舊列軟退役、新列轉正
	_ = km2

	// 舊 KEK 實例（km）此刻嘗試放棄
	if _, err := km.AbandonRewrap(); !errors.Is(err, ErrNoRewrapPending) {
		t.Fatalf("切換完成後放棄應拒 ErrNoRewrapPending，得 %v", err)
	}
	// 新 KEK 現行列不得被動到
	var newLive int64
	db.Model(&model.DataKey{}).
		Where("kek_id = ? AND kek_retired_at IS NULL AND kek_pending = ?", newKEKID, false).
		Count(&newLive)
	if newLive == 0 {
		t.Fatal("切換後新 KEK 現行列被放棄操作破壞")
	}
}

// TestAbandonThenRetryRewrap 放棄後重試重包（新隨機 KEK）不得撞唯一索引
// （partial index：退役列保留指紋史但不佔活動唯一鍵）。
// 注意守衛 (c) 拒絕「指紋曾出現於表」——同 KEK 重試會命中退役列指紋而被拒，
// 這是設計上的保守拒絕（防指紋碰撞）……實際語義見斷言。
func TestAbandonThenRetryRewrap(t *testing.T) {
	_, km := setupKM(t)
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	// 放棄後重新重包（新隨機 KEK）必須成功——退役列不佔唯一鍵、
	// backlog 守衛不誤把 abandoned 列當退役 backlog
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("放棄後再重包應成功: %v", err)
	}
}

// TestRotationRejectedByForeignPendingInDB DEK 輪替的 campaign 判定必須以 DB
// 現查為準：另一實例建立的 foreign pending 本行程記憶體不知道，
// 但輪替仍須被拒（舊實作憑 in-memory rewrapPending 會放行）
func TestRotationRejectedByForeignPendingInDB(t *testing.T) {
	db, km := setupKM(t)
	// 模擬另一實例的重包：直接落 foreign pending 列（本實例 in-memory 旗標仍 false）
	foreign := model.DataKey{Purpose: model.DataKeyPurposeData, Version: 1,
		WrappedKey: "foreign-pending", KEKID: "feedbeef00000000", Status: model.DataKeyStatusActive,
		KEKPending: true}
	if err := db.Create(&foreign).Error; err != nil {
		t.Fatalf("seed foreign pending: %v", err)
	}
	if km.RewrapPending() {
		t.Fatal("前置：本實例 in-memory 旗標應為 false（模擬跨實例不可見）")
	}
	if _, err := km.RotateDataDEK(); !errors.Is(err, ErrRewrapPending) {
		t.Fatalf("foreign pending 存在時 DEK 輪替應拒 ErrRewrapPending，得 %v", err)
	}
	if _, err := km.RotateAuditKey(); !errors.Is(err, ErrRewrapPending) {
		t.Fatalf("foreign pending 存在時蓋章鑰輪替應拒 ErrRewrapPending，得 %v", err)
	}
}

// TestLockBusyReturns409Sentinel 互斥 try 語義：鎖被佔用時立即回 ErrKeyOpBusy
// 不阻塞（sqlite 路徑驗 package 級 try-mutex；同語義的 postgres 路徑見 PG 整合測試）。
// DB 用 shared-cache 具名 memory DSN：goroutine 內的持鎖交易佔用一條連線時，
// 鎖外查詢（RewrapKEK 的遷移 fast-fail）自第二條連線仍看得到同一 DB
// （sqlite :memory: 每連線獨立空 DB 的連線池陷阱——見 sqlite-memory-connection-pool）
func TestLockBusyReturns409Sentinel(t *testing.T) {
	shared, err := gorm.Open(sqlite.Open("file:lockbusytest?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite shared: %v", err)
	}
	if err := shared.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.User{}, &model.ExportSigningKey{}, &model.CheckpointSigningKey{}, &model.OIDCProvider{},
		&model.LDAPDirectory{}, &model.NotificationChannel{}, &model.AuditLog{}, &model.DataKey{},
		&model.ChangeSecretCandidate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := shared.Exec("CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	db := shared
	km := newTestKeyManager(t, db, 1)
	seedEnvelopeData(t, db, km)
	km2 := newTestKeyManager(t, db, 1) // 同 process 第二個 service 實例

	hold := make(chan struct{})
	held := make(chan struct{})
	// released 在 withDataKeysLock **返回之後**才關閉，故它同時證明
	// `defer kekProcessMu.Unlock()`（key_manager_lock.go:82）已執行。
	//
	// **只 close(hold) 不等 goroutine 是本包在 GOMAXPROCS=1 下恆紅的真因**
	// kekProcessMu 是 package 級鎖，
	// 單核時持鎖 goroutine 多半排程在下一格開跑之後，後續每一格取鎖都得
	// ErrKeyOpBusy，失敗數與測試順序有關而不可歸因。等它確實釋放才離場。
	released := make(chan struct{})
	go func() {
		defer close(released)
		_ = km.withDataKeysLock(func(tx *gorm.DB) error {
			close(held)
			<-hold
			return nil
		})
	}()
	<-held
	defer func() {
		close(hold)
		<-released
	}()

	// 第二實例的所有寫入路徑必須立即得 ErrKeyOpBusy（per-instance rotMu 驗不出這件事）
	if _, err := rewrapKEKWith(t, km2, newTestKEKMaterial(t)); !errors.Is(err, ErrKeyOpBusy) {
		t.Fatalf("鎖佔用時 RewrapKEK 應 ErrKeyOpBusy，得 %v", err)
	}
	if _, err := km2.AbandonRewrap(); !errors.Is(err, ErrKeyOpBusy) {
		t.Fatalf("鎖佔用時 AbandonRewrap 應 ErrKeyOpBusy，得 %v", err)
	}
	if _, err := km2.RotateDataDEK(); !errors.Is(err, ErrKeyOpBusy) {
		t.Fatalf("鎖佔用時 RotateDataDEK 應 ErrKeyOpBusy，得 %v", err)
	}
}

// TestRetiredKEKBootTargetedError 以已退役且材料未清理的 KEK 開機：
// fail-close 不變，但錯誤必須是定向回退指引；材料清理後回歸籠統 mismatch
func TestRetiredKEKBootTargetedError(t *testing.T) {
	db, km := setupKM(t)
	oldProvider := km.kek
	_, oldKEK, _ := rewrapAndReinit(t, db, km) // 切換完成：舊列軟退役、材料保留

	// (1) 材料尚存 → 定向訊息
	_, err := InitKeyManager(db, oldProvider)
	if !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("退役 KEK 開機應 fail-close，得 %v", err)
	}
	if !strings.Contains(err.Error(), "已退役但材料尚未清理") {
		t.Fatalf("材料尚存時應回定向回退指引，得: %v", err)
	}

	// (2) 模擬顯式清理（材料清空）→ 回歸籠統 mismatch，不洩漏退役史
	if err := db.Model(&model.DataKey{}).Where("kek_id = ?", oldKEK).
		Update("wrapped_key", "").Error; err != nil {
		t.Fatalf("simulate purge: %v", err)
	}
	_, err = InitKeyManager(db, oldProvider)
	if !errors.Is(err, ErrKEKMismatch) {
		t.Fatalf("清理後退役 KEK 開機仍應 fail-close，得 %v", err)
	}
	if strings.Contains(err.Error(), "已退役但材料尚未清理") {
		t.Fatalf("材料已清理後不應再出定向訊息: %v", err)
	}
}

// TestCleanupRetiredMaterial 顯式清理：全收斂閘、KEK 退役列清理、
// 退役 DEK 版本引用掃描（有引用拒清／零引用清理）、清理後重啟與再重包保鏈
func TestCleanupRetiredMaterial(t *testing.T) {
	db, km := setupKM(t)

	// (0) pending 期間清理必須被全收斂閘拒絕
	if _, err := rewrapKEKWith(t, km, newTestKEKMaterial(t)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := km.CleanupRetiredMaterial(); !errors.Is(err, ErrCleanupNotConverged) {
		t.Fatalf("pending 期間清理應拒 ErrCleanupNotConverged，得 %v", err)
	}
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("abandon: %v", err)
	}

	// 造一筆退役 DEK 版本引用：先以 v1 產出一筆**真正的 enc:a1:v1 密文**，
	// DEK 輪替 v1→v2（全量重加密）後再手植回去模擬殘值。
	//
	// **殘值必須是可歸屬版本的合法密文**：
	// 原寫法植入 `enc:v1:AAAA`（發佈前過渡格式），在終態下會命中「不可歸屬殘值
	// 保守拒清」閘而整筆中止，測不到本測試要驗的逐版本引用掃描。
	v1ref := encryptColumn(t, km, "assets", "password_enc", "v1-residue")
	if !strings.HasPrefix(v1ref, "enc:a1:v1:") {
		t.Fatalf("前置：殘值須為 v1 帶 AAD 密文，得 %q", v1ref)
	}
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	v1ct := encryptColumn(t, km, "assets", "password_enc", "x") // v2 格式（清除殘值時用）
	if err := db.Exec("UPDATE assets SET password_enc = ? WHERE name = 'a1'",
		v1ref).Error; err != nil {
		t.Fatalf("plant v1 ref: %v", err)
	}

	// (1) 清理：abandoned 列（KEK 退役類）應清；data v1 有引用應拒清；
	//     audit_integrity v0 零引用應清
	result, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	var v1Skipped bool
	for _, sk := range result.Skipped {
		if sk.Purpose == model.DataKeyPurposeData && sk.Version == 1 {
			v1Skipped = true
			if sk.Refs < 1 || sk.Reason != "version_referenced" {
				t.Fatalf("v1 拒清應帶引用數與原因: %+v", sk)
			}
		}
	}
	if !v1Skipped {
		t.Fatalf("data v1 仍有存量引用，應拒清: %+v", result)
	}
	// abandoned 列材料應已清空、列與指紋保留
	var abandonedWithMaterial int64
	db.Model(&model.DataKey{}).
		Where("kek_retired_reason = ? AND wrapped_key <> ''", model.KEKRetireReasonAbandoned).
		Count(&abandonedWithMaterial)
	if abandonedWithMaterial != 0 {
		t.Fatalf("abandoned 列材料應被清理，仍有 %d 筆", abandonedWithMaterial)
	}
	var abandonedRows int64
	db.Model(&model.DataKey{}).Where("kek_retired_reason = ?", model.KEKRetireReasonAbandoned).Count(&abandonedRows)
	if abandonedRows == 0 {
		t.Fatal("清理後 abandoned 列本身（指紋軌跡）必須保留")
	}

	// (2) 清掉 v1 殘值引用後重清：v1 應可清
	if err := db.Exec("UPDATE assets SET password_enc = ? WHERE name = 'a1'", v1ct).Error; err != nil {
		t.Fatalf("clear v1 ref: %v", err)
	}
	result2, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("cleanup2: %v", err)
	}
	var v1Purged bool
	for _, p := range result2.Purged {
		if p.Purpose == model.DataKeyPurposeData && p.Version == 1 {
			v1Purged = true
		}
	}
	if !v1Purged {
		t.Fatalf("引用歸零後 v1 應可清: %+v", result2)
	}

	// (3) 清理後重啟：已清理佔位不斷鏈、既有資料（v2）可解
	ct2 := encryptColumn(t, km, "assets", "password_enc", "after-purge")
	km2 := newTestKeyManager(t, db, 1)
	if got, err := decryptColumn(km2, "assets", "password_enc", ct2); err != nil || got != "after-purge" {
		t.Fatalf("清理後重啟 v2 解密失敗: %q err=%v", got, err)
	}

	// (4) 清理後再重包＋切換：佔位隨行複製，新 KEK 開機保鏈
	km3, _, _ := rewrapAndReinit(t, db, km2)
	ct3 := encryptColumn(t, km3, "assets", "password_enc", "after-rewrap")
	if got, err := decryptColumn(km3, "assets", "password_enc", ct3); err != nil || got != "after-rewrap" {
		t.Fatalf("清理後重包切換失敗: %q err=%v", got, err)
	}
}

// TestFinalizePromoteRowsGuard promote 影響列數守衛的直接敏感性釘住。
// 鎖內重讀的 toPromote 判定（pending 且 kek_id==env）不含「未退役」條件，
// 而 promote UPDATE 的 WHERE 含——一列 clone 帶 pending 卻已標退役時兩者
// 必然不符，守衛須整筆 rollback（其餘 clones 不得被 promote、不得進入退役
// 步驟），失敗記於 lastFinalizeErr。該 slot 舊列一併預標退役以繞開第二道
// per-slot 守衛，確保本測試單獨釘住第一道（守衛移除時其餘 clones 會被
// promote，promoted 斷言即轉紅）。
func TestFinalizePromoteRowsGuard(t *testing.T) {
	db, km := setupKM(t)
	resMaterial, _ := mustRewrapKEK(t, km)
	newProvider, _ := crypto.NewEnvKEKProvider([]byte(resMaterial))
	newID := newProvider.KeyID()

	var victim model.DataKey
	if err := db.Where("kek_id = ? AND kek_pending = ?", newID, true).
		Order("purpose, version").First(&victim).Error; err != nil {
		t.Fatalf("找 clone: %v", err)
	}
	now := time.Now()
	if err := db.Model(&model.DataKey{}).Where("id = ?", victim.ID).
		Update("kek_retired_at", now).Error; err != nil {
		t.Fatalf("標 clone 退役: %v", err)
	}
	if err := db.Model(&model.DataKey{}).
		Where("purpose = ? AND version = ? AND kek_id = ?", victim.Purpose, victim.Version, km.KEKKeyID()).
		Update("kek_retired_at", now).Error; err != nil {
		t.Fatalf("標舊列退役: %v", err)
	}

	km.finalizeSwitch(newID)

	var promoted int64
	db.Model(&model.DataKey{}).
		Where("kek_id = ? AND kek_pending = ?", newID, false).
		Count(&promoted)
	if promoted != 0 {
		t.Fatalf("promote 影響列數守衛失效：%d 列 clone 在不一致態下仍被 promote", promoted)
	}
	if err := km.LastFinalizeErr(); err == nil || !strings.Contains(err.Error(), "影響列數") {
		t.Fatalf("lastFinalizeErr 應記錄影響列數不符，得 %v", err)
	}
}

// TestRotationStaleInstanceRejected（回歸）：KEK 切換完成後，
// 仍以舊 env 運行的實例執行 DEK 輪替 MUST 被 ErrStaleKeyCache 拒絕——放行會鑄出
// 僅被已退役 KEK 包裹的新版本，新舊實例全數不可開機、v2 密文僅剩行程記憶體可解
func TestRotationStaleInstanceRejected(t *testing.T) {
	db, km1 := setupKM(t)
	oldKEK := km1.KEKKeyID()
	rewrapAndReinit(t, db, km1) // 另一實例完成切換；km1 從此為 stale

	if _, err := km1.RotateDataDEK(); !errors.Is(err, ErrStaleKeyCache) {
		t.Fatalf("stale 實例 data 輪替應 ErrStaleKeyCache，得 %v", err)
	}
	if _, err := km1.RotateAuditKey(); !errors.Is(err, ErrStaleKeyCache) {
		t.Fatalf("stale 實例 audit 輪替應 ErrStaleKeyCache，得 %v", err)
	}
	var minted int64
	db.Model(&model.DataKey{}).
		Where("kek_id = ? AND kek_retired_at IS NULL", oldKEK).Count(&minted)
	if minted != 0 {
		t.Fatalf("stale 實例鑄出 %d 列以退役 KEK 包裹的未退役列", minted)
	}
}

// TestRotationStaleVersionRejected 同 KEK 雙實例：另一實例已完成 data 輪替，
// 本實例 in-memory active 落後 → ErrStaleKeyCache
func TestRotationStaleVersionRejected(t *testing.T) {
	db, km1 := setupKM(t)
	km2 := newTestKeyManager(t, db, 1) // 同 KEK 第二實例
	if _, err := km2.RotateDataDEK(); err != nil {
		t.Fatalf("km2 輪替: %v", err)
	}
	if _, err := km1.RotateDataDEK(); !errors.Is(err, ErrStaleKeyCache) {
		t.Fatalf("落後實例輪替應 ErrStaleKeyCache，得 %v", err)
	}
}

// TestBootstrapRaceFailsClosed（回歸）：bootstrap 鎖內重讀
// 發現用途已被另一實例補齊時 MUST fail-close——不同 KEK 下唯一索引攔不住
// 「同版本不同材料」的腦裂，只能靠鎖內重讀拒絕
func TestBootstrapRaceFailsClosed(t *testing.T) {
	db, _ := setupKM(t) // 表已被「另一實例」bootstrap 完成
	p, err := crypto.NewEnvKEKProvider(kmTestKey(9))
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	racer := &KeyManagerService{db: db, kek: p}
	if err := racer.bootstrap(); err == nil || !strings.Contains(err.Error(), "競態") {
		t.Fatalf("空表判定失效後 bootstrap 應 fail-close（競態錯誤），得 %v", err)
	}
	var n int64
	db.Model(&model.DataKey{}).Where("kek_id = ?", p.KeyID()).Count(&n)
	if n != 0 {
		t.Fatalf("fail-close 後不得留下競態實例的列，得 %d", n)
	}
}

// TestCleanupAbortsWithoutEnvLiveCopy（回歸）：KEK 退役列的
// slot 若無現行 KEK 的 live 材料列，清理 MUST 整筆中止——退役副本是該版本
// 唯一材料時銷毀＝永久不可解。病態以 DB 手術構造（自證防的就是不可預期路徑）
func TestCleanupAbortsWithoutEnvLiveCopy(t *testing.T) {
	db, km := setupKM(t)
	km2, oldKEK, _ := rewrapAndReinit(t, db, km)
	if err := db.Model(&model.DataKey{}).
		Where("kek_id = ? AND purpose = ? AND version = ?", km2.KEKKeyID(), model.DataKeyPurposeData, 1).
		Update("wrapped_key", "").Error; err != nil {
		t.Fatalf("造病態: %v", err)
	}
	_, err := km2.CleanupRetiredMaterial()
	if err == nil || !strings.Contains(err.Error(), "清理中止") {
		t.Fatalf("env live 材料缺失時清理應中止，得 %v", err)
	}
	var relic model.DataKey
	if err := db.Where("kek_id = ? AND purpose = ? AND version = ?", oldKEK, model.DataKeyPurposeData, 1).
		First(&relic).Error; err != nil {
		t.Fatalf("找退役列: %v", err)
	}
	if relic.WrappedKey == "" {
		t.Fatal("中止後退役列材料仍被清空（rollback 失效）")
	}
}

// TestInventoryMaterialDerivation：material_purged／
// material_rows 為 SQL 端衍生布林，SELECT 運算式被改動時本測試轉紅。
// 覆蓋：切換軟退役後退役史材料尚存 → 輪替使 v1 零引用 → 清理 → 清冊標已清理、
// 退役史材料歸零
func TestInventoryMaterialDerivation(t *testing.T) {
	db, km := setupKM(t)
	km2, _, _ := rewrapAndReinit(t, db, km)

	recs, err := km2.ListRetiredKEKs()
	if err != nil || len(recs) == 0 {
		t.Fatalf("退役史: %v（%d 筆）", err, len(recs))
	}
	if recs[0].MaterialRows == 0 {
		t.Fatal("切換軟退役後退役史材料應尚存（material_rows>0）")
	}

	if _, err := km2.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := km2.CleanupRetiredMaterial(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	keys, err := km2.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if k.Purpose == "data" && k.Version == 1 {
			seen["v1"] = true
			if !k.MaterialPurged {
				t.Fatal("清理後 data v1 應標 material_purged")
			}
		}
		if k.Purpose == "data" && k.Version == 2 {
			seen["v2"] = true
			if k.MaterialPurged {
				t.Fatal("現行 data v2 不得標 material_purged")
			}
		}
	}
	if !seen["v1"] || !seen["v2"] {
		t.Fatalf("清冊缺 v1/v2 列: %+v", keys)
	}
	recs2, err := km2.ListRetiredKEKs()
	if err != nil || len(recs2) == 0 {
		t.Fatalf("退役史（清理後）: %v", err)
	}
	if recs2[0].MaterialRows != 0 {
		t.Fatalf("清理後退役史材料應歸零，得 %d", recs2[0].MaterialRows)
	}
}

// TestFinalizeRetireGuardKeepsLiveRep：收尾語義的第二道守衛——退役步驟
// 將使某 slot 失去現行 KEK live 代表列時 MUST 整筆 rollback、舊列留在 backlog。
// 這是「任何操作順序下不可能刪光 live 列」論證的另一半（第一道 promote 列數
// 守衛由 TestFinalizePromoteRowsGuard 釘住）。
// 病態構造：pending clone 全數就緒（promote 會成功），但某 slot 的新 KEK 列
// 在 promote 後被移除——直呼 finalizeSwitch 以繞過 load 的前置代表列檢查
func TestFinalizeRetireGuardKeepsLiveRep(t *testing.T) {
	db, km := setupKM(t)
	oldKEK := km.KEKKeyID()
	resMaterial, _ := mustRewrapKEK(t, km)
	newProvider, _ := crypto.NewEnvKEKProvider([]byte(resMaterial))
	newID := newProvider.KeyID()

	// 移除新 KEK 對 data v1 的 clone：promote 後該 slot 只剩舊 KEK live 列，
	// 退役它會使 slot 無代表列——守衛必須中止
	if err := db.Where("kek_id = ? AND purpose = ? AND version = ?",
		newID, model.DataKeyPurposeData, 1).Delete(&model.DataKey{}).Error; err != nil {
		t.Fatalf("造病態: %v", err)
	}

	km2 := &KeyManagerService{db: db, kek: newProvider,
		keys: map[string]map[int][]byte{}, ciphers: map[int]*crypto.AESCrypto{}, active: map[string]int{}}
	km2.finalizeSwitch(newID)

	var retired int64
	db.Model(&model.DataKey{}).Where("kek_id = ? AND kek_retired_at IS NOT NULL", oldKEK).
		Count(&retired)
	if retired != 0 {
		t.Fatalf("退役守衛失效：%d 筆舊列在該 slot 將失去代表列的情況下仍被退役", retired)
	}
	var stillLive int64
	db.Model(&model.DataKey{}).
		Where("kek_id = ? AND purpose = ? AND version = ? AND kek_retired_at IS NULL AND wrapped_key <> ''",
			oldKEK, model.DataKeyPurposeData, 1).Count(&stillLive)
	if stillLive == 0 {
		t.Fatal("退役守衛失效：data v1 已無任何 live 材料列（資料將永久不可解）")
	}
	if err := km2.LastFinalizeErr(); err == nil || !strings.Contains(err.Error(), "代表列") {
		t.Fatalf("lastFinalizeErr 應記錄代表列守衛中止，得 %v", err)
	}
}

// TestUnknownDialectFailsClose：白名單外的 dialect 無跨實例互斥
// 能力，MUST 直接拒絕而非靜默退化為行程內鎖
func TestUnknownDialectFailsClose(t *testing.T) {
	db, km := setupKM(t)
	orig := db.Config.Dialector
	db.Config.Dialector = fakeDialector{Dialector: orig, name: "mysql"}
	defer func() { db.Config.Dialector = orig }()

	err := km.withDataKeysLock(func(tx *gorm.DB) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "不支援的資料庫 dialect") {
		t.Fatalf("未知 dialect 應 fail-close，得 %v", err)
	}
}

// fakeDialector 僅覆寫 Name()，其餘沿用真 dialector
type fakeDialector struct {
	gorm.Dialector
	name string
}

func (f fakeDialector) Name() string { return f.name }

// TestAuditKeyNeverPurgedWhileReferenced（稽核需求，spec「稽核蓋章鑰不可清理」）：
// 仍有審計紀錄以某 audit_integrity 版本蓋章時，清理 MUST 拒絕該版本並回
// reason=audit_referenced——銷毀＝歷史審計紀錄永久無法驗章，稽核軌跡失去證明力。
// 本測試是該稽核需求的機制保證，不得因「引用掃描已測過」而視為重複
func TestAuditKeyNeverPurgedWhileReferenced(t *testing.T) {
	db, km := setupKM(t)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	// 輪替蓋章鑰使 v1 退役，並留下以 v1 蓋章的歷史審計列
	if _, err := km.RotateAuditKey(); err != nil {
		t.Fatalf("rotate audit key: %v", err)
	}
	if err := db.Create(&model.AuditLog{
		Action: model.ActionRead, Resource: model.ResourceAuditLog,
		Status: model.StatusSuccess, UserID: 1, Username: "auditor",
		KeyVersion: 1,
	}).Error; err != nil {
		t.Fatalf("seed audit log: %v", err)
	}

	res, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	for _, p := range res.Purged {
		if p.Purpose == model.DataKeyPurposeAuditIntegrity && p.Version == 1 {
			t.Fatal("稽核需求違反：仍被審計紀錄引用的蓋章鑰被銷毀，歷史紀錄將永久無法驗章")
		}
	}
	var found bool
	for _, s := range res.Skipped {
		if s.Purpose == model.DataKeyPurposeAuditIntegrity && s.Version == 1 {
			found = true
			if s.Reason != "audit_referenced" {
				t.Fatalf("拒清原因應為 audit_referenced，得 %q", s.Reason)
			}
			if s.Refs == 0 {
				t.Fatal("拒清應回報引用筆數")
			}
		}
	}
	if !found {
		t.Fatalf("被引用的蓋章鑰應出現在拒清清單，得 %+v", res.Skipped)
	}
	// 材料確實仍在（不只是回報拒清）
	var row model.DataKey
	if err := db.Where("purpose = ? AND version = ? AND kek_id = ?",
		model.DataKeyPurposeAuditIntegrity, 1, km.KEKKeyID()).First(&row).Error; err != nil {
		t.Fatalf("find audit v1: %v", err)
	}
	if row.WrappedKey == "" {
		t.Fatal("稽核需求違反：拒清後材料仍被清空")
	}
}

// TestPurgeClassRegistryCompleteness 保護類別登記表完備性（開發期守衛）：
// 每個金鑰用途 MUST 有登記的保護類別。新增用途卻忘了宣告保護語義時本測試先紅
// ——執行期的保底行為是「保守保留該列並逐項回報」（見
// TestUnregisteredPurposeSkippedNotBlocking），開發期由本測試把關使該保底不被常態依賴
func TestPurgeClassRegistryCompleteness(t *testing.T) {
	allPurposes := []string{model.DataKeyPurposeData, model.DataKeyPurposeAuditIntegrity}
	for _, p := range allPurposes {
		c, ok := purgeClassOf(p)
		if !ok {
			t.Fatalf("用途 %s 未登記保護類別", p)
		}
		if c.Name == "" || c.ReasonCode == "" {
			t.Fatalf("用途 %s 的保護類別欄位不完整: %+v", p, c)
		}
		if !c.NeverPurgeable && c.CountRefs == nil {
			t.Fatalf("用途 %s 非 NeverPurgeable 卻無 CountRefs（無從判定引用）", p)
		}
	}
	if len(purgeClasses) != len(allPurposes) {
		t.Fatalf("登記表有 %d 筆但已知用途 %d 個——新增用途須同步本測試與登記表",
			len(purgeClasses), len(allPurposes))
	}
	// 未登記用途：回保底類別且標記為未登記，保底必須是「永不可銷毀」
	c, ok := purgeClassOf("future_purpose_zz")
	if ok {
		t.Fatal("未登記用途不得被當成已登記")
	}
	if !c.NeverPurgeable {
		t.Fatal("未登記用途的保底類別必須永不可銷毀（不得預設為可清）")
	}
}

// TestUnregisteredPurposeSkippedNotBlocking 未登記用途的退役列存在時，
// 清理 MUST 保守跳過該列並逐項回報，**但不得中止整個清理操作**——
// 把「一列未知」升級成「清理功能整組不可用」會讓釋出後的使用者撞牆且無自救
// 手段（只能等新版程式），而少清一列本身零風險。其餘可清列須照常清理
func TestUnregisteredPurposeSkippedNotBlocking(t *testing.T) {
	db, km := setupKM(t)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate audit_logs: %v", err)
	}
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := db.Create(&model.DataKey{
		Purpose: "future_purpose_zz", Version: 1, WrappedKey: "some-material",
		KEKID: km.KEKKeyID(), Status: model.DataKeyStatusRetired,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("未登記用途不得中止整個清理操作: %v", err)
	}
	var skipped *KeyCleanupSkipped
	for i := range res.Skipped {
		if res.Skipped[i].Purpose == "future_purpose_zz" {
			skipped = &res.Skipped[i]
		}
	}
	if skipped == nil {
		t.Fatalf("未登記用途應逐項回報為拒清，得 %+v", res.Skipped)
	}
	if skipped.Reason != "unregistered_purpose" || skipped.ProtectionClass != "unregistered" {
		t.Fatalf("拒清原因與類別應可辨識為未登記，得 %+v", *skipped)
	}
	var row model.DataKey
	if err := db.Where("purpose = ?", "future_purpose_zz").First(&row).Error; err != nil {
		t.Fatalf("find row: %v", err)
	}
	if row.WrappedKey == "" {
		t.Fatal("未登記用途的材料不得被銷毀")
	}
	if len(res.Purged) == 0 {
		t.Fatal("其餘可清列應照常清理（不因一列未知而全案癱瘓）")
	}
}

// TestCleanupRefusesOnNonAttributableResidue 引用掃描遇不可歸屬殘值保守拒清
// （3.3／spec delta）。
//
// **為何這道閘不可缺**：引用掃描以 `envelopeVersionOf` 判定值屬哪個版本，
// 解析不過的值回 `ok=false`，而 skip 謂詞 `!ok || ver != version` 對它恆為真——
// 即不計入**任何**版本的引用。於是一個無法歸屬的過渡格式殘值會讓每個退役版本
// 都被算成零引用而放行銷毀；該殘值若其實由某退役版本加密，銷毀即永久不可解。
//
// 本測試**不得遷就現況**：它先確認同一情境下「殘值換成可歸屬的合法密文時
// 清理會照常進行」，證明拒清確實來自殘值偵測而非其他恆定阻擋。
func TestCleanupRefusesOnNonAttributableResidue(t *testing.T) {
	db, km := setupKM(t)

	// 造出退役 DEK 版本（v1）：輪替 v1→v2 後 v1 成 retired
	if _, err := km.RotateDataDEK(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// 實驗組：植入**不可歸屬**的過渡格式殘值（模擬繞過 API 的 DB 直寫）
	if err := db.Exec("UPDATE assets SET password_enc = ? WHERE name = 'a1'",
		"enc:v1:AAAA").Error; err != nil {
		t.Fatalf("plant residue: %v", err)
	}
	_, err := km.CleanupRetiredMaterial()
	if !errors.Is(err, ErrCleanupResidueDetected) {
		t.Fatalf("不可歸屬殘值 MUST 整筆拒清，得 %v", err)
	}
	// 逐項回報殘值位置（不落值本身）
	if !strings.Contains(err.Error(), "assets.password_enc") {
		t.Fatalf("拒清 MUST 逐項回報殘值位置: %v", err)
	}
	if strings.Contains(err.Error(), "enc:v1:AAAA") {
		t.Fatalf("回報 MUST NOT 落殘值本身（可能是敏感密文）: %v", err)
	}
	// 拒清 MUST 為整筆中止：v1 材料不得被銷毀
	var material string
	if err := db.Raw("SELECT wrapped_key FROM data_keys WHERE purpose = ? AND version = 1 AND kek_id = ?",
		model.DataKeyPurposeData, km.KEKKeyID()).Scan(&material).Error; err != nil {
		t.Fatalf("查詢 v1 材料: %v", err)
	}
	if material == "" {
		t.Fatal("拒清後 v1 材料竟已被銷毀——閘未達成整筆中止")
	}

	// 對照組：殘值換成可歸屬的合法密文 → 清理照常進行。
	// 沒有這一半，上面的拒清可能來自任何恆定阻擋而非殘值偵測（測試遷就現況的典型）
	if err := db.Exec("UPDATE assets SET password_enc = ? WHERE name = 'a1'",
		encryptColumn(t, km, "assets", "password_enc", "attributable")).Error; err != nil {
		t.Fatalf("plant attributable: %v", err)
	}
	result, err := km.CleanupRetiredMaterial()
	if err != nil {
		t.Fatalf("對照組：可歸屬密文下清理不應被拒: %v", err)
	}
	var purged bool
	for _, p := range result.Purged {
		if p.Purpose == model.DataKeyPurposeData && p.Version == 1 {
			purged = true
		}
	}
	if !purged {
		t.Fatalf("對照組：零引用的 v1 應可清（證明拒清來自殘值偵測）: %+v", result)
	}
}
