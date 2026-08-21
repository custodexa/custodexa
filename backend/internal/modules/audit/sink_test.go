package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// audit 三個落地面的行為契約（modular-architecture W4 4.2／4.3／4.6／4.9）。

func sinkTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// ── 4.3 TxSink ──────────────────────────────────────────────────────────

// TestTxSinkWritesInsideCallerTransaction 寫入必須落在呼叫方的交易內。
//
// 驗法是「交易回滾後審計列必須一起消失」——若落地器偷偷換了 session 或自開交易，
// 這一格會紅。**這是 fail-close 成立的前提**：審計列若不在同一筆交易裡，
// 業務回滾時它會留下來，變成「操作沒發生但有留痕」。
func TestTxSinkWritesInsideCallerTransaction(t *testing.T) {
	db := sinkTestDB(t)
	sink := NewTxSink()

	wantRollback := errors.New("業務失敗")
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := sink.WriteInTx(tx, port.AuditEvent{
			Action: string(model.ActionCreate), Resource: string(model.ResourceAsset),
			Status: string(model.StatusSuccess),
		}); err != nil {
			t.Fatalf("交易內寫入應成功: %v", err)
		}
		return wantRollback
	})
	if !errors.Is(err, wantRollback) {
		t.Fatalf("交易應回傳業務錯誤: %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Count(&n)
	if n != 0 {
		t.Fatalf("交易回滾後審計列應一併消失，實留 %d 筆——落地器不在呼叫方交易內", n)
	}
}

// TestTxSinkIgnoresAuditLogEnabledFlag 落地器 SHALL NOT 受 AuditLogEnabled 管制。
//
// 強制審計是「全操作審計」紅線的唯一落地路徑；一個設定旗標若能讓它整批消失，
// 而業務操作照樣成立，那就是把紅線交給設定檔。
func TestTxSinkIgnoresAuditLogEnabledFlag(t *testing.T) {
	db := sinkTestDB(t)
	// 刻意把兩個開關都關掉——TxSink 不看它們（它根本沒有 cfg）
	_ = NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: false})

	if err := db.Transaction(func(tx *gorm.DB) error {
		return NewTxSink().WriteInTx(tx, port.AuditEvent{Action: string(model.ActionDelete)})
	}); err != nil {
		t.Fatalf("寫入應成功: %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Count(&n)
	if n != 1 {
		t.Fatalf("AuditLogEnabled=false 時交易內審計仍應落地，實得 %d 筆", n)
	}
}

// TestTxSinkPropagatesErrorUnwrapped 錯誤原樣上拋，不吞也不包裝。
//
// **不包裝**是刻意的：各呼叫點的包裝詞（「審計留痕失敗: %w」…）已被既有測試斷言，
// 落地器若再包一層，收口前後的錯誤字串就不再逐字相同。
func TestTxSinkPropagatesErrorUnwrapped(t *testing.T) {
	db := sinkTestDB(t)
	injected := errors.New("注入：寫入失敗")
	if err := db.Callback().Create().Before("gorm:create").Register("txsink_test:fail", func(tx *gorm.DB) {
		_ = tx.AddError(injected)
	}); err != nil {
		t.Fatalf("註冊 callback: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove("txsink_test:fail") })

	err := NewTxSink().WriteInTx(db, port.AuditEvent{Action: string(model.ActionCreate)})
	if err == nil {
		t.Fatal("寫入失敗時 SHALL 回 error，不得吞掉")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("錯誤應原樣上拋（errors.Is 認得出注入的那一個），實得 %v", err)
	}
}

// TestTxSinkFieldMapping 欄位對應與收口前逐欄相同。
func TestTxSinkFieldMapping(t *testing.T) {
	db := sinkTestDB(t)
	rid := uint(42)
	at := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	ev := port.AuditEvent{
		OccurredAt: at,
		Actor:      gatewayapi.Actor{UserID: 7, Username: "admin"},
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceUserGroup),
		ResourceID: &rid,
		Status:     string(model.StatusSuccess),
		Request:    gatewayapi.RequestMeta{ClientIP: "10.1.2.3", Method: "POST", Path: "/x", StatusCode: 200, DurationMS: 12, RequestID: "rq", Body: "{}"},
		Details:    `{"k":"v"}`,
		ErrorMsg:   "",
	}
	if err := NewTxSink().WriteInTx(db, ev); err != nil {
		t.Fatalf("寫入: %v", err)
	}
	var row model.AuditLog
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	switch {
	case row.UserID != 7 || row.Username != "admin":
		t.Fatalf("Actor 對應錯誤: %+v", row)
	case row.Action != model.ActionUpdate || row.Resource != model.ResourceUserGroup:
		t.Fatalf("Action/Resource 對應錯誤: %+v", row)
	case row.ResourceID == nil || *row.ResourceID != 42:
		t.Fatalf("ResourceID 對應錯誤: %+v", row)
	case row.ClientIP != "10.1.2.3" || row.Method != "POST" || row.Path != "/x" || row.StatusCode != 200 || row.Duration != 12:
		t.Fatalf("Request 對應錯誤: %+v", row)
	case row.Details != `{"k":"v"}`:
		t.Fatalf("Details 對應錯誤: %+v", row)
	case !row.CreatedAt.UTC().Equal(at):
		t.Fatalf("OccurredAt 未落到 CreatedAt: %v", row.CreatedAt)
	}
}

// TestTxSinkZeroOccurredAtLeavesCreatedAtToGorm 零值時刻交給 GORM 補。
//
// 現況五個交易內產生點都不自填時刻；落地器若硬補 time.Now()，「誰決定時刻」
// 就從 ORM 悄悄搬到落地器——兩者取值幾乎相同，但那是行為變更的入口。
func TestTxSinkZeroOccurredAtLeavesCreatedAtToGorm(t *testing.T) {
	db := sinkTestDB(t)
	before := time.Now().Add(-time.Second)
	if err := NewTxSink().WriteInTx(db, port.AuditEvent{Action: string(model.ActionCreate)}); err != nil {
		t.Fatalf("寫入: %v", err)
	}
	var row model.AuditLog
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if row.CreatedAt.Before(before) || row.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt 應由 GORM 補為現在時刻，實得 %v", row.CreatedAt)
	}
}

// ── 4.4／4.7 port.WriteInTx 的 nil 防護 ────────────────────────────────

// TestPortWriteInTxNilSinkIsFailClose nil sink 一律回 error，SHALL NOT 靜默成功。
func TestPortWriteInTxNilSinkIsFailClose(t *testing.T) {
	db := sinkTestDB(t)
	err := port.WriteInTx(nil, db, port.AuditEvent{Action: string(model.ActionCreate)})
	if !errors.Is(err, port.ErrTxSinkMissing) {
		t.Fatalf("nil sink 應回 ErrTxSinkMissing，實得 %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Count(&n)
	if n != 0 {
		t.Fatalf("nil sink 不該寫出任何列，實得 %d", n)
	}
}

// ── 4.2 AsyncSink（AuditLogService.Submit）────────────────────────────

// TestAsyncSinkSubmitIsLogWrapper Submit 是 Log 的包裝，語義不變。
func TestAsyncSinkSubmitIsLogWrapper(t *testing.T) {
	db := sinkTestDB(t)
	withRepositoryDB(t, db)
	svc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})

	if err := svc.Submit(context.Background(), gatewayapi.AuditEvent{
		Actor: gatewayapi.Actor{UserID: 3, Username: "u"}, Action: string(model.ActionLogin),
		Resource: string(model.ResourceAuth), Status: string(model.StatusSuccess),
	}); err != nil {
		t.Fatalf("Submit 不該回 error（入列語義）: %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Count(&n)
	if n != 1 {
		t.Fatalf("同步模式下 Submit 應落地 1 筆，實得 %d", n)
	}
}

// TestAsyncSinkSubmitRespectsAuditLogEnabled 開關關閉時靜默丟棄（現況語義，不得改變）。
func TestAsyncSinkSubmitRespectsAuditLogEnabled(t *testing.T) {
	db := sinkTestDB(t)
	withRepositoryDB(t, db)
	svc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: false})

	if err := svc.Submit(context.Background(), gatewayapi.AuditEvent{Action: string(model.ActionLogin)}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Count(&n)
	if n != 0 {
		t.Fatalf("AuditLogEnabled=false 時 SHALL 靜默丟棄（現況語義），實得 %d 筆", n)
	}
}

// TestAsyncSinkSubmitCarriesOccurredAt 事件時刻不得被替換成入列時刻。
func TestAsyncSinkSubmitCarriesOccurredAt(t *testing.T) {
	db := sinkTestDB(t)
	withRepositoryDB(t, db)
	svc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	if err := svc.Submit(context.Background(), gatewayapi.AuditEvent{
		OccurredAt: at, Action: string(model.ActionLogin),
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	var row model.AuditLog
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if !row.CreatedAt.UTC().Equal(at) {
		t.Fatalf("OccurredAt 未被承載（實得 %v）——事件時刻被替換成入列時刻是無聲的失真", row.CreatedAt)
	}
}

// ── 4.6 DirectSink（C-plain 專用，繞過開關）───────────────────────────

// TestDirectSinkBypassesAuditLogEnabled C-plain 兩點現況不受開關管制，收口後亦然。
func TestDirectSinkBypassesAuditLogEnabled(t *testing.T) {
	db := sinkTestDB(t)
	// 即使把主 sink 的開關關掉，DirectSink 仍寫——這正是它存在的理由
	_ = NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: false})

	if err := NewDirectSink(db).Submit(context.Background(), gatewayapi.AuditEvent{
		Action: string(model.ActionFileUpload), Resource: string(model.ResourceFile),
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	var n int64
	db.Model(&model.AuditLog{}).Count(&n)
	if n != 1 {
		t.Fatalf("DirectSink SHALL 繞過 AuditLogEnabled，實得 %d 筆", n)
	}
}

// TestDirectSinkWithoutDBReturnsError 未注入 DB 時回錯，不靜默成功。
func TestDirectSinkWithoutDBReturnsError(t *testing.T) {
	if err := NewDirectSink(nil).Submit(context.Background(), gatewayapi.AuditEvent{}); err == nil {
		t.Fatal("未注入 DB 時 SHALL 回 error，不得靜默成功")
	}
}

// ── 4.9 AlertSink 基建 ───────────────────────────────────────────────

// TestAlertRecorderBatchIsSingleInsert 批次 SHALL NOT 被拆成 N 次 INSERT。
//
// matcher 路徑現況是一次 `Create(&alerts)`；拆成逐筆是效能與交易語義的雙重行為變更。
// 以 Create callback 計次證明它只發生一次。
func TestAlertRecorderBatchIsSingleInsert(t *testing.T) {
	db := alertSinkTestDB(t)
	creates := 0
	if err := db.Callback().Create().Before("gorm:create").Register("alertsink_test:count", func(tx *gorm.DB) {
		creates++
	}); err != nil {
		t.Fatalf("callback: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove("alertsink_test:count") })

	rec := NewAlertRecorder(db)
	rule1, rule2 := uint(1), uint(2)
	alerts := []gatewayapi.CommandAlert{
		{Kind: model.AlertKindRule, RuleID: &rule1, RuleName: "r1", SessionID: 9, Command: "rm -rf /", Level: "high", Disposition: model.AlertDispositionPending, OccurredAt: time.Now()},
		{Kind: model.AlertKindRule, RuleID: &rule2, RuleName: "r2", SessionID: 9, Command: "shutdown", Level: "medium", Disposition: model.AlertDispositionPending, OccurredAt: time.Now()},
	}
	if err := rec.RecordAlerts(context.Background(), alerts); err != nil {
		t.Fatalf("RecordAlerts: %v", err)
	}
	if creates != 1 {
		t.Fatalf("批次應為單次 INSERT，實得 %d 次——RecordAlerts 不得實作成迴圈呼叫 RecordAlert", creates)
	}
	var n int64
	db.Model(&model.CommandAlert{}).Count(&n)
	if n != 2 {
		t.Fatalf("應落地 2 筆告警，實得 %d", n)
	}
}

// TestAlertRecorderImplementsGatewayContract 編譯期斷言的執行期補強（欄位對應）。
func TestAlertRecorderImplementsGatewayContract(t *testing.T) {
	db := alertSinkTestDB(t)
	aid := uint(5)
	ruleID := uint(3)
	var sink gatewayapi.AlertSink = NewAlertRecorder(db)
	if err := sink.RecordAlert(context.Background(), gatewayapi.CommandAlert{
		Kind: model.AlertKindRule, RuleID: &ruleID, RuleName: "blocker", SessionID: 11, AssetID: &aid,
		Actor: gatewayapi.Actor{UserID: 2}, Command: "dd if=/dev/zero",
		Level: "high", Disposition: model.AlertDispositionPending, Blocked: true,
		OccurredAt: time.Now(),
	}); err != nil {
		t.Fatalf("RecordAlert: %v", err)
	}
	var row model.CommandAlert
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if row.RuleName != "blocker" || !row.Blocked || row.AssetID == nil || *row.AssetID != 5 ||
		row.UserID != 2 || row.Disposition != model.AlertDispositionPending {
		t.Fatalf("欄位對應錯誤: %+v", row)
	}
}

// withRepositoryDB 把套件級 database.DB 暫時換成測試庫（AuditLogService 的
// 落地走的是那個全域句柄——W4 未改變此事實，資料層去全域化不在本波範圍）。
func withRepositoryDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
}

// alertSinkTestDB command_alerts 的 sqlite 等價 schema（生產走原生 SQL 的 timestamptz，
// AutoMigrate 出來的欄位 glebarez 驅動 scan 不回 time.Time——沿用
// command_alert_service_test.go 的既有作法）。
func alertSinkTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatalf("create command_alerts: %v", err)
	}
	return db
}
