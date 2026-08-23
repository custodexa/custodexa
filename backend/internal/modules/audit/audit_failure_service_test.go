package audit

import (
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupFailureDB(t *testing.T) (*AuditFailureService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditFailureEvent{}, &model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 直接建構不註冊單例：避免污染其他測試的 GetAuditFailure()
	return &AuditFailureService{db: db, policy: policy.NewSecurityPolicyService(db)}, db
}

// TestFailureReportDedupAndResolve 進行中去重、恢復回填起訖、再失效建新列
func TestFailureReportDedupAndResolve(t *testing.T) {
	svc, db := setupFailureDB(t)

	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed,
		map[string]string{model.CauseParamDetail: "refused"})
	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed,
		map[string]string{model.CauseParamDetail: "refused again"}) // 去重
	var count int64
	db.Model(&model.AuditFailureEvent{}).Count(&count)
	if count != 1 {
		t.Errorf("進行中重複上報應去重, 列數 = %d, want 1", count)
	}

	svc.Resolve(model.MechanismSyslogForward)
	var event model.AuditFailureEvent
	db.First(&event)
	if event.EndedAt == nil || !event.EndedAt.After(event.StartedAt) && !event.EndedAt.Equal(event.StartedAt) {
		t.Errorf("恢復後應回填 EndedAt 形成起訖區間: %+v", event)
	}
	if event.Cause == "" {
		t.Error("Cause 必須記錄（PCI 10.7.3）")
	}

	// 恢復後再失效 = 新事件
	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)
	db.Model(&model.AuditFailureEvent{}).Count(&count)
	if count != 2 {
		t.Errorf("恢復後再失效應建新列, 列數 = %d, want 2", count)
	}

	// 不同機制互不去重
	svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteFallbackFile, nil)
	db.Model(&model.AuditFailureEvent{}).Count(&count)
	if count != 3 {
		t.Errorf("不同機制應各自記錄, 列數 = %d, want 3", count)
	}
}

// TestFailureResolveWithoutOpen 無進行中失效時 Resolve 為 no-op
func TestFailureResolveWithoutOpen(t *testing.T) {
	svc, db := setupFailureDB(t)
	svc.Resolve(model.MechanismAuditWrite)
	var count int64
	db.Model(&model.AuditFailureEvent{}).Count(&count)
	if count != 0 {
		t.Errorf("無進行中失效 Resolve 不應建列, 列數 = %d", count)
	}
}

// TestFailureNotifyDespiteDBError 回歸：DB 全掛（事件表不可寫）時
// 通知仍須發出——原實作 Create 失敗直接 return，失效區間零紀錄零告警。
// in-memory 狀態機須繼續去重、恢復通知對稱發出
func TestFailureNotifyDespiteDBError(t *testing.T) {
	svc, db := setupFailureDB(t)
	db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"})

	var notified []notifycat.Event
	var lastParams map[string]string
	svc.notify = func(event notifycat.Event, params map[string]string) {
		notified = append(notified, event)
		lastParams = params
	}

	// 模擬 DB 掛掉：事件表消失，查詢與寫入都失敗
	if err := db.Migrator().DropTable(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("drop: %v", err)
	}

	svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteFallbackFile,
		map[string]string{model.CauseParamDetail: "connection refused"})
	svc.Report(model.MechanismAuditWrite, model.CauseAuditWriteBatchDropped, nil) // in-memory 去重
	if len(notified) != 1 || notified[0] != notifycat.EventAuditFailure {
		t.Errorf("DB 掛掉時仍應通知一次, got %v", notified)
	}
	// 出站只帶碼：forensic detail 不進通知 params（去識別紅線）
	if lastParams["cause_code"] != model.CauseAuditWriteFallbackFile {
		t.Errorf("通知應帶 cause_code, got %v", lastParams)
	}
	if _, ok := lastParams[model.CauseParamDetail]; ok {
		t.Errorf("detail 不得進出站 params, got %v", lastParams)
	}

	svc.Resolve(model.MechanismAuditWrite)
	if len(notified) != 2 || notified[1] != notifycat.EventAuditFailureResolved {
		t.Errorf("恢復通知應對稱發出（即使無列可回填）, got %v", notified)
	}
	// 無列可回填＝起點不明，走 unknown variant
	if lastParams["interval"] != notifycat.IntervalUnknown {
		t.Errorf("無 open 列時 interval 應為 unknown, got %v", lastParams)
	}
}

// blockUpdates 讓 audit_failure_events 的 UPDATE 全部失敗、SELECT/INSERT 照常
// （模擬「查得到列但寫不進去」的抖動）。回傳解除阻擋的函式
func blockUpdates(t *testing.T, db *gorm.DB) func() {
	t.Helper()
	if err := db.Exec(`CREATE TRIGGER block_failure_update BEFORE UPDATE ON audit_failure_events
		BEGIN SELECT RAISE(ABORT, 'update blocked'); END;`).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	return func() {
		if err := db.Exec("DROP TRIGGER block_failure_update").Error; err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
	}
}

// TestFailureResolveBackfillsAfterUpdateFailure（回歸）：
// 結案 UPDATE 失敗時，舊實作先清 in-memory failing 旗標又不重試，之後每次
// Resolve 都被「非失效中」早退吞掉 → open event 永久懸掛，PCI 失效區間的
// 結束端證據永久缺失。修正後失敗僅留待補標記，下次 Resolve 補結案
func TestFailureResolveBackfillsAfterUpdateFailure(t *testing.T) {
	svc, db := setupFailureDB(t)
	db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"})
	var notified []notifycat.Event
	svc.notify = func(event notifycat.Event, _ map[string]string) {
		notified = append(notified, event)
	}

	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)

	unblock := blockUpdates(t, db)
	svc.Resolve(model.MechanismSyslogForward)

	// 恢復事實優先出站：寫庫失敗不得吞掉恢復通知
	if len(notified) != 2 || notified[1] != notifycat.EventAuditFailureResolved {
		t.Fatalf("結案寫庫失敗時恢復通知仍須發出，得 %v", notified)
	}
	var ev model.AuditFailureEvent
	if err := db.First(&ev).Error; err != nil {
		t.Fatalf("read event: %v", err)
	}
	if ev.EndedAt != nil {
		t.Fatal("前置條件不成立：UPDATE 應已被阻擋，事件不該結案")
	}

	// 抖動結束後再次 Resolve：必須補上結案，而非因「非失效中」永久 no-op
	unblock()
	svc.Resolve(model.MechanismSyslogForward)

	if err := db.First(&ev).Error; err != nil {
		t.Fatalf("read event: %v", err)
	}
	if ev.EndedAt == nil {
		t.Fatal("後續 Resolve 必須補結案，open event 不得永久懸掛（PCI 失效區間證據）")
	}
	// 補結案不重複投遞恢復通知（狀態機已在第一次轉換過）
	if len(notified) != 2 {
		t.Fatalf("補結案不應重複投遞，得 %v", notified)
	}
	// 補上的是原始恢復時刻：重試不得把失效區間拉長
	if ev.EndedAt.Sub(ev.StartedAt) > time.Minute {
		t.Fatalf("補結案應記原始恢復時刻，得區間 %v", ev.EndedAt.Sub(ev.StartedAt))
	}
}

// TestFailureReportReopensAfterPendingClose 待補結案不得被誤認為「進行中事件」：
// 補結案後同機制再度失效須開新列（兩段失效不得被併成一段）
func TestFailureReportReopensAfterPendingClose(t *testing.T) {
	svc, db := setupFailureDB(t)
	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)

	unblock := blockUpdates(t, db)
	svc.Resolve(model.MechanismSyslogForward)
	unblock()

	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)

	var total, open int64
	db.Model(&model.AuditFailureEvent{}).Count(&total)
	db.Model(&model.AuditFailureEvent{}).Where("ended_at IS NULL").Count(&open)
	if total != 2 || open != 1 {
		t.Fatalf("補結案後再失效應開新列（總 %d、進行中 %d，want 2/1）", total, open)
	}
}

// TestFailureReportReusesExistingStartedAt（回歸）：
// 沿用 DB 既有未結束事件時，出站 started_at 必須是該事件的真實起點；
// 報 time.Now() 會把已持續數小時的失效講成剛剛才發生，且與 Resolve 的區間對不上
func TestFailureReportReusesExistingStartedAt(t *testing.T) {
	svc, db := setupFailureDB(t)
	db.Create(&model.SecurityPolicy{Key: policy.PolicyFailureAlertEnabled, Value: "true"})
	var lastParams map[string]string
	svc.notify = func(_ notifycat.Event, params map[string]string) { lastParams = params }

	// 重啟遺留的未結束事件（in-memory 狀態已歸零）
	started := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)
	if err := db.Create(&model.AuditFailureEvent{
		Mechanism: model.MechanismSyslogForward, StartedAt: started,
		Cause: "重啟前的斷線", CauseCode: model.CauseSyslogConnectFailed,
	}).Error; err != nil {
		t.Fatalf("seed open event: %v", err)
	}

	svc.Report(model.MechanismSyslogForward, model.CauseSyslogConnectFailed, nil)

	if got := lastParams["started_at"]; got != started.Format(time.RFC3339) {
		t.Fatalf("沿用既有事件時 started_at 應為 %q，實得 %q", started.Format(time.RFC3339), got)
	}
	var total int64
	db.Model(&model.AuditFailureEvent{}).Count(&total)
	if total != 1 {
		t.Fatalf("沿用既有事件不應重複開列，列數 = %d", total)
	}
}

// TestFailureReconcileOnStartup 重啟遺留的進行中事件須在啟動時回填結束時間
// （失效狀態不跨進程保存，不回填即永久懸掛）
func TestFailureReconcileOnStartup(t *testing.T) {
	svc, db := setupFailureDB(t)
	db.Create(&model.AuditFailureEvent{
		Mechanism: model.MechanismSyslogForward,
		StartedAt: time.Now().Add(-time.Hour),
		Cause:     "重啟前的斷線",
	})

	svc.ReconcileOnStartup()

	var event model.AuditFailureEvent
	db.First(&event)
	if event.EndedAt == nil {
		t.Fatal("啟動回填後 EndedAt 不應為空")
	}
	if event.Details == "" {
		t.Error("回填事件應於 Details 誠實註明時間非精確")
	}
}
