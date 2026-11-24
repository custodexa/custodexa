package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// notifyPipeline 測試用的完整通知管線：sqlite 測試庫＋排入介面＋投遞程序。
//
// 舊測試以「快取通道後直接投遞」的形狀撰寫（setChannels → notify／NotifyEvent）；這裡把同樣的呼叫
// 換成「通道寫入資料庫 → 排入 → 投遞程序跑一輪」，斷言的對象（收端收到的請求）不變。
type notifyPipeline struct {
	t  testing.TB
	db *gorm.DB
	n  *AlertNotifier
	w  *SystemAlertOutboxWorker
}

// newTestNotifier 建立測試管線；投遞程序的退避極短，時鐘為真實時鐘。
func newTestNotifier() *notifyPipeline {
	return newNotifyPipelineT(nil)
}

func newNotifyPipeline(t testing.TB) *notifyPipeline {
	return newNotifyPipelineT(t)
}

func newNotifyPipelineT(t testing.TB) *notifyPipeline {
	db := setupNotificationDB(t)
	n := NewAlertNotifier(db, nil)
	n.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	w := NewSystemAlertOutboxWorker(db, nil)
	w.tee = func(model.CommandAlert) {}
	w.backoffBase = time.Millisecond
	w.backoffMax = 4 * time.Millisecond
	w.UseEnqueueStats(n.EnqueueStats())
	w.reporter = nopFailureReporter{}
	return &notifyPipeline{t: t, db: db, n: n, w: w}
}

// nopFailureReporter 不回報稽核失效（避免測試取用套件單例）。
type nopFailureReporter struct{}

func (nopFailureReporter) ReportWithCounts(string, string, map[string]string, map[string]int) {}
func (nopFailureReporter) Resolve(string)                                                     {}
func (nopFailureReporter) NotifyOngoing(notifycat.Event, map[string]string)                   {}

// setupNotificationDB 建一個含通知投遞所需資料表的 sqlite 測試庫（單一連線）。
func setupNotificationDB(t testing.TB) *gorm.DB {
	var tt *testing.T
	if x, ok := t.(*testing.T); ok {
		tt = x
	}
	db := openSQLiteForPipeline(tt)
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`,
		`CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`,
		`CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, client_ip TEXT NOT NULL DEFAULT '', deleted_at DATETIME)`,
		`CREATE TABLE IF NOT EXISTS session_commands (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,
			degraded BOOLEAN NOT NULL DEFAULT 0, executed_at DATETIME, degrade_reason TEXT NOT NULL DEFAULT '')`,
	}
	for _, s := range stmts {
		if err := db.Exec(s).Error; err != nil {
			panic(err)
		}
	}
	if err := db.AutoMigrate(&model.NotificationMessage{}); err != nil {
		panic(err)
	}
	return db
}

func openSQLiteForPipeline(t *testing.T) *gorm.DB {
	if t != nil {
		return setupSystemAlertDB(t)
	}
	db := mustOpenMemorySQLite()
	ensureSystemAlertTablesNoT(db)
	return db
}

// setChannels 把通道寫入資料庫（明文；codec 為 nil）。回傳啟用通道數。
func (p *notifyPipeline) setChannels(chs []model.NotificationChannel) int {
	enabled := 0
	for _, ch := range chs {
		ch := ch
		if ch.Language == "" {
			ch.Language = "zh-TW"
		}
		if ch.MinSeverity == "" {
			ch.MinSeverity = model.AlertSeverityLow
		}
		if ch.Name == "" {
			ch.Name = "ch"
		}
		wantEnabled := ch.Enabled
		if err := p.db.Create(&ch).Error; err != nil {
			panic(err)
		}
		if !wantEnabled {
			p.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Update("enabled", false)
		} else {
			enabled++
		}
	}
	return enabled
}

// notify 寫入告警列、排入指令告警並跑一輪。
func (p *notifyPipeline) notify(alert model.CommandAlert) {
	if alert.TriggeredAt.IsZero() {
		alert.TriggeredAt = time.Now().UTC()
	}
	if alert.Disposition == "" {
		alert.Disposition = "pending"
	}
	if err := p.db.Create(&alert).Error; err != nil {
		panic(err)
	}
	if err := p.n.EnqueueStandalone(commandAlertNotice(alert)); err != nil {
		panic(err)
	}
	p.w.RunOnce()
}

// NotifyEvent 排入系統事件並跑一輪。
func (p *notifyPipeline) NotifyEvent(event notifycat.Event, params map[string]string) {
	if err := p.n.EnqueueStandalone(SystemEventNotice(event, params)); err != nil {
		panic(err)
	}
	p.w.RunOnce()
}

// run 跑一輪投遞程序。
func (p *notifyPipeline) run() int { return p.w.RunOnce() }

func mustOpenMemorySQLite() *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		panic(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	return db
}

func ensureSystemAlertTablesNoT(db *gorm.DB) {
	if err := db.Exec(`CREATE TABLE IF NOT EXISTS command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		panic(err)
	}
	if err := db.AutoMigrate(&model.SystemAlertDetail{}, &model.NotificationDelivery{},
		&model.SystemAlertSeverityOverride{}, &model.NotificationChannel{}, &model.AuditLog{}); err != nil {
		panic(err)
	}
}
