package audit

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newIntegrityDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.IntegrityBaseline{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newIntegrityServiceWithKey 測試用建構：以固定單鑰充當 **v1** 蓋章鑰。
//
// 取代已刪除的 `InitAuditIntegrity`（legacy 單鑰模式、版本恆 0，
// release-transitional-cleanup D4）。**版本刻意為 1 而非 0**：終態下系統無 v0 鑰，
// 測試若沿用 0 會讓「key_version=0 一律不符」的不變式在測試裡自相矛盾。
func newIntegrityServiceWithKey(t *testing.T, db *gorm.DB, key string) *AuditIntegrityService {
	t.Helper()
	baselineMaxID, err := loadBaseline(db)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	material := []byte(key)
	svc := &AuditIntegrityService{
		keyFn: func(version int) []byte {
			if version == 1 {
				return material
			}
			return nil
		},
		activeFn:      func() (int, []byte) { return 1, material },
		baselineMaxID: baselineMaxID,
	}
	registerAuditIntegrity(svc)
	return svc
}

func newIntegrityService(t *testing.T, db *gorm.DB) *AuditIntegrityService {
	t.Helper()
	return newIntegrityServiceWithKey(t, db, "test-integrity-key")
}

// TestIntegrityHMACDeterministic 同列同碼、金鑰不同碼不同、內容變動碼不同
func TestIntegrityHMACDeterministic(t *testing.T) {
	db := newIntegrityDB(t)
	svc := newIntegrityService(t, db)
	l := &model.AuditLog{
		CreatedAt: time.Now(), Action: model.ActionUpdate, Resource: model.ResourceUser,
		Status: model.StatusSuccess, UserID: 3, Username: "admin", ClientIP: "10.0.0.1",
		// 終態下版本鏈自 v1 起；KeyVersion 留 0 會取不到鑰而回空碼
		KeyVersion: 1,
	}
	h1 := svc.ComputeHMAC(l)
	if h1 == "" || len(h1) != 64 {
		t.Fatalf("HMAC 應為 64 hex, got %q", h1)
	}
	if h2 := svc.ComputeHMAC(l); h2 != h1 {
		t.Error("同列重算應得同碼")
	}
	l.Username = "attacker"
	if svc.ComputeHMAC(l) == h1 {
		t.Error("內容變動後 HMAC 應不同")
	}

	other := newIntegrityServiceWithKey(t, db, "another-key")
	l.Username = "admin"
	if other.ComputeHMAC(l) == h1 {
		t.Error("不同金鑰應得不同碼")
	}
}

// TestIntegrityKeyVersionZeroAlwaysMismatches 偽造 v0 版本列計為不符
// （release-transitional-cleanup D4／audit-integrity spec）：
// 系統無 v0 鑰，`HMACKeyByVersion`／keyFn 對不存在版本回 nil＝驗證不符。
func TestIntegrityKeyVersionZeroAlwaysMismatches(t *testing.T) {
	db := newIntegrityDB(t)
	svc := newIntegrityService(t, db)

	l := &model.AuditLog{
		CreatedAt: time.Now(), Action: model.ActionCreate, Resource: model.ResourceAsset,
		Status: model.StatusSuccess, UserID: 1, Username: "u",
	}
	svc.Stamp([]*model.AuditLog{l})
	if l.KeyVersion != 1 {
		t.Fatalf("蓋章 MUST 記現行版本 v1，得 v%d", l.KeyVersion)
	}
	if err := db.Create(l).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	// DB 直改為 key_version=0（模擬繞過 hook 直插／偽造）
	if err := db.Exec("UPDATE audit_logs SET key_version = 0 WHERE id = ?", l.ID).Error; err != nil {
		t.Fatalf("forge: %v", err)
	}
	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatched != 1 || report.Passed != 0 {
		t.Fatalf("key_version=0 MUST 計為不符（系統無 v0 鑰）: %+v", report)
	}
	if svc.keyFn(0) != nil {
		t.Fatal("v0 鑰 MUST 不存在")
	}
}

// TestIntegrityBaselinePersistence 基準首啟寫入、再啟沿用（不得每次刷新——
// 刷新等於把之後的無 HMAC 列永久洗白成 Legacy）
func TestIntegrityBaselinePersistence(t *testing.T) {
	db := newIntegrityDB(t)
	// 基準前已有兩筆歷史列：首啟基準應錨定當下最大 id
	for _, name := range []string{"h1", "h2"} {
		if err := db.Create(&model.AuditLog{
			CreatedAt: time.Now(), Action: model.ActionCreate, Resource: model.ResourceAsset,
			Status: model.StatusSuccess, UserID: 1, Username: name,
		}).Error; err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	first := newIntegrityService(t, db)
	if first.baselineMaxID != 2 {
		t.Errorf("首啟基準應錨定現有最大 id: got %d, want 2", first.baselineMaxID)
	}
	// 基準後又寫一筆——再啟必須沿用持久化基準，不得重算吞掉新列
	if err := db.Create(&model.AuditLog{
		CreatedAt: time.Now(), Action: model.ActionCreate, Resource: model.ResourceAsset,
		Status: model.StatusSuccess, UserID: 1, Username: "post",
	}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	second := newIntegrityService(t, db)
	if second.baselineMaxID != first.baselineMaxID {
		t.Errorf("再啟應沿用既有基準: first=%d second=%d", first.baselineMaxID, second.baselineMaxID)
	}
	var count int64
	db.Model(&model.IntegrityBaseline{}).Count(&count)
	if count != 1 {
		t.Errorf("基準應為單列, got %d", count)
	}
}

// TestIntegrityVerify 三計數誠實分類：通過／DB 直改不符（含 ID）／基準前無 HMAC 歷史列
func TestIntegrityVerify(t *testing.T) {
	db := newIntegrityDB(t)

	mkLog := func(username string) *model.AuditLog {
		return &model.AuditLog{
			CreatedAt: time.Now(), Action: model.ActionCreate, Resource: model.ResourceAsset,
			Status: model.StatusSuccess, UserID: 1, Username: username,
		}
	}
	// legacy 列必須真的在基準建立之前入庫（id 錨點語義——時間欄不再算數）
	legacy := mkLog("dave")
	if err := db.Create(legacy).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	svc := newIntegrityService(t, db)

	// 兩筆正常（Stamp 後入庫）＋一筆將被竄改
	good := []*model.AuditLog{mkLog("alice"), mkLog("bob")}
	svc.Stamp(good)
	tampered := mkLog("carol")
	svc.Stamp([]*model.AuditLog{tampered})
	for _, l := range append(good, tampered) {
		if err := db.Create(l).Error; err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	// DB 直改（繞過 ORM 守衛，模擬攻擊者）
	if err := db.Exec("UPDATE audit_logs SET username = 'attacker' WHERE id = ?", tampered.ID).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Checked != 4 || report.Passed != 2 || report.Mismatched != 1 || report.Legacy != 1 {
		t.Errorf("report = %+v, want checked 4/passed 2/mismatched 1/legacy 1", report)
	}
	if len(report.MismatchedIDs) != 1 || report.MismatchedIDs[0] != tampered.ID {
		t.Errorf("MismatchedIDs = %v, want [%d]", report.MismatchedIDs, tampered.ID)
	}
}

// TestIntegrityBlankEvasionDetected 對抗驗證回歸：竄改內容並同時清空 HMAC
// 不得歸入 Legacy 洗白——基準之後的空 HMAC 列必須列為不符
func TestIntegrityBlankEvasionDetected(t *testing.T) {
	db := newIntegrityDB(t)
	svc := newIntegrityService(t, db)

	victim := &model.AuditLog{
		CreatedAt: time.Now(), Action: model.ActionDelete, Resource: model.ResourceAsset,
		Status: model.StatusSuccess, UserID: 2, Username: "admin",
	}
	svc.Stamp([]*model.AuditLog{victim})
	if err := db.Create(victim).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	// 攻擊：改內容＋清空 HMAC（原實作會歸 Legacy 而躲過偵測）
	if err := db.Exec("UPDATE audit_logs SET username = 'attacker', integrity_hmac = '' WHERE id = ?", victim.ID).Error; err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Mismatched != 1 || report.Legacy != 0 {
		t.Errorf("清空規避應計入不符: %+v", report)
	}
	if len(report.MismatchedIDs) != 1 || report.MismatchedIDs[0] != victim.ID {
		t.Errorf("MismatchedIDs = %v, want [%d]", report.MismatchedIDs, victim.ID)
	}
}

// TestIntegrityBackdatedInsertDetected H2 回歸（key-management-envelope
// 對抗驗證）：基準後插入的列即使回填 created_at 至基準前並留空 HMAC，
// 也不得歸 Legacy——legacy 判定以不可回填的自增 id 為錨，非時間欄
func TestIntegrityBackdatedInsertDetected(t *testing.T) {
	db := newIntegrityDB(t)
	// 基準前一筆真歷史列（無 HMAC）
	old := &model.AuditLog{
		CreatedAt: time.Now().Add(-2 * time.Hour), Action: model.ActionCreate,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, UserID: 1, Username: "old",
	}
	if err := db.Create(old).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	svc := newIntegrityService(t, db)

	// 攻擊：基準後插新列，created_at 回填到基準前、HMAC 留空——
	// 原 created_at 判定會歸 Legacy 洗白（對抗驗證實證 mismatched=0/legacy=1）
	forged := &model.AuditLog{
		CreatedAt: time.Now().Add(-90 * time.Minute), Action: model.ActionDelete,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, UserID: 9, Username: "attacker",
	}
	if err := db.Create(forged).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	report, err := svc.Verify(db, time.Now().Add(-3*time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Legacy != 1 || report.Mismatched != 1 {
		t.Errorf("回填插列應計入不符（真歷史列仍為 legacy）: %+v", report)
	}
	if len(report.MismatchedIDs) != 1 || report.MismatchedIDs[0] != forged.ID {
		t.Errorf("MismatchedIDs = %v, want [%d]", report.MismatchedIDs, forged.ID)
	}
}

// TestIntegrityStampViaCreateHook model BeforeCreate 註冊 hook 覆蓋直寫路徑
// （asset GORM hook、file_tap、k8s cp 等不經 audit worker 的寫入）
func TestIntegrityStampViaCreateHook(t *testing.T) {
	db := newIntegrityDB(t)
	svc := newIntegrityService(t, db)
	model.SetAuditCreateHooks(svc.StampOne, nil)
	defer model.SetAuditCreateHooks(nil, nil)

	// 模擬直寫路徑：不經 Stamp，直接 db.Create
	direct := &model.AuditLog{
		Action: model.ActionCreate, Resource: model.ResourceAsset,
		Status: model.StatusSuccess, UserID: 1, Username: "hooked",
	}
	if err := db.Create(direct).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var stored model.AuditLog
	if err := db.First(&stored, direct.ID).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.IntegrityHMAC == "" {
		t.Fatal("直寫路徑應經 BeforeCreate hook 蓋章")
	}
	report, err := svc.Verify(db, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Checked != 1 || report.Passed != 1 {
		t.Errorf("hook 蓋章後應驗證通過: %+v", report)
	}
}
