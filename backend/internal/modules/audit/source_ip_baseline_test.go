package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 基準服務的行為測試：單勝者、登入與建線分開追蹤、失敗回滾（故障注入證明注入點
// 走到）、真並發只有一個勝者。sqlite 與 PostgreSQL（gated）兩條路徑都跑——
// upsert 的 ON CONFLICT／RETURNING 與時間相等判定是方言敏感的，單一方言的綠
// 證明不了另一邊。

// sourceIPBaselineDB 基準測試庫：user_source_ips＋audit_logs 走 AutoMigrate，
// command_alerts 沿 alertSinkTestDB 的 sqlite 等價 DDL（timestamptz 欄 glebarez
// scan 不回）。連線池釘為 1：被測程式在多 goroutine 內開交易，`:memory:` 配
// 連線池的第二條連線是另一個空 DB。
func sourceIPBaselineDB(t *testing.T) *gorm.DB {
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
	if err := db.AutoMigrate(&model.UserSourceIP{}, &model.AuditLog{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
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

func newBaselineForTest(t *testing.T, db *gorm.DB) *SourceIPBaseline {
	t.Helper()
	return NewSourceIPBaseline(db, NewAlertRecorder(db), NewTxSink())
}

func countAlerts(t *testing.T, db *gorm.DB, kind string) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.CommandAlert{}).Where("kind = ?", kind).Count(&n).Error; err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

func baselineRow(t *testing.T, db *gorm.DB, userID uint, ip string) model.UserSourceIP {
	t.Helper()
	var row model.UserSourceIP
	if err := db.Where("user_id = ? AND client_ip = ?", userID, ip).First(&row).Error; err != nil {
		t.Fatalf("讀基準列失敗: %v", err)
	}
	return row
}

func TestSourceIPBaselineFirstSessionWinsAndRepeatIsSilent(t *testing.T) {
	db := sourceIPBaselineDB(t)
	b := newBaselineForTest(t, db)
	asset := uint(7)
	t0 := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	winner, err := b.ObserveSession(context.Background(), 1, "203.0.113.5", 11, &asset, t0)
	if err != nil {
		t.Fatalf("首次觀察失敗: %v", err)
	}
	if !winner {
		t.Fatal("首次建線應為勝者")
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 1 {
		t.Fatalf("首次建線應恰一筆告警，實得 %d", n)
	}
	var alert model.CommandAlert
	if err := db.Where("kind = ?", model.AlertKindNewSourceIP).First(&alert).Error; err != nil {
		t.Fatalf("讀告警列: %v", err)
	}
	if alert.SessionID != 11 || alert.UserID != 1 || alert.RuleID != nil ||
		alert.ReasonCode != model.AlertReasonNewSourceIPSession || alert.Command != "" ||
		alert.Severity != "medium" || alert.Disposition != model.AlertDispositionPending {
		t.Errorf("告警形狀不符: %+v", alert)
	}
	row := baselineRow(t, db, 1, "203.0.113.5")
	if row.FirstSessionID == nil || *row.FirstSessionID != 11 {
		t.Errorf("first_session_id 應為 11，實得 %v", row.FirstSessionID)
	}

	// 再現：不同會話、同（帳號, 位址）→ 不是勝者、零新告警、last_seen 前進
	winner, err = b.ObserveSession(context.Background(), 1, "203.0.113.5", 12, &asset, t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("再現觀察失敗: %v", err)
	}
	if winner {
		t.Fatal("再現不應為勝者")
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 1 {
		t.Fatalf("再現不應追加告警，實得 %d", n)
	}
	row = baselineRow(t, db, 1, "203.0.113.5")
	if *row.FirstSessionID != 11 {
		t.Errorf("first_session_id 不得被再現改寫，實得 %v", *row.FirstSessionID)
	}
	if !row.LastSeenAt.After(row.FirstSeenAt) {
		t.Errorf("last_seen_at 應前進: first=%v last=%v", row.FirstSeenAt, row.LastSeenAt)
	}

	// 空位址與零主鍵：不觀察、不告警、不報錯
	for _, tc := range []struct {
		user, session uint
		ip            string
	}{{0, 13, "203.0.113.5"}, {1, 0, "203.0.113.5"}, {1, 13, ""}, {1, 13, "not-an-address"}} {
		w, err := b.ObserveSession(context.Background(), tc.user, tc.ip, tc.session, nil, t0)
		if err != nil || w {
			t.Errorf("無效輸入 %+v 應靜默略過，實得 winner=%v err=%v", tc, w, err)
		}
	}
}

func TestSourceIPBaselineLoginMarksButDoesNotClaimSession(t *testing.T) {
	db := sourceIPBaselineDB(t)
	b := newBaselineForTest(t, db)
	t0 := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	obs := LoginObservation{UserID: 2, Username: "alice", IP: "198.51.100.7",
		Method: "POST", Path: "/api/v1/auth/login", Now: t0}

	inserted, err := b.ObserveLogin(context.Background(), obs)
	if err != nil {
		t.Fatalf("登入觀察失敗: %v", err)
	}
	if !inserted {
		t.Fatal("首次登入應為新建")
	}
	var marks int64
	if err := db.Model(&model.AuditLog{}).Where("action = ? AND user_id = 2", string(model.ActionNewSourceIP)).Count(&marks).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if marks != 1 {
		t.Fatalf("首次登入應恰一筆審計標記，實得 %d", marks)
	}
	var mark model.AuditLog
	if err := db.Where("action = ?", string(model.ActionNewSourceIP)).First(&mark).Error; err != nil {
		t.Fatalf("讀標記: %v", err)
	}
	if mark.Resource != model.ResourceAuth || mark.Status != model.StatusSuccess ||
		mark.ClientIP != "198.51.100.7" || mark.Details != `{"via":"login"}` {
		t.Errorf("標記形狀不符: action=%s resource=%s status=%s ip=%s details=%s",
			mark.Action, mark.Resource, mark.Status, mark.ClientIP, mark.Details)
	}
	row := baselineRow(t, db, 2, "198.51.100.7")
	if row.FirstSessionAt != nil || row.FirstSessionID != nil {
		t.Errorf("登入不得設定首次建線兩欄: %+v", row)
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 0 {
		t.Fatalf("登入不得寫告警表，實得 %d", n)
	}

	// 再登入：只更新 last_seen，不追加標記
	obs.Now = t0.Add(time.Hour)
	inserted, err = b.ObserveLogin(context.Background(), obs)
	if err != nil || inserted {
		t.Fatalf("已見位址再登入應為 (false, nil)，實得 (%v, %v)", inserted, err)
	}
	if err := db.Model(&model.AuditLog{}).Where("action = ?", string(model.ActionNewSourceIP)).Count(&marks).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if marks != 1 {
		t.Fatalf("再登入不得追加標記，實得 %d", marks)
	}

	// 先登入再建線：建線仍勝一次、恰一筆告警——登入不得抹掉「新」
	winner, err := b.ObserveSession(context.Background(), 2, "198.51.100.7", 21, nil, t0.Add(2*time.Hour))
	if err != nil || !winner {
		t.Fatalf("先登入再建線應仍為勝者，實得 (%v, %v)", winner, err)
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 1 {
		t.Fatalf("先登入再建線應恰一筆告警，實得 %d", n)
	}
	// 建線之後再登入：首次建線兩欄不得被動
	obs.Now = t0.Add(3 * time.Hour)
	if _, err := b.ObserveLogin(context.Background(), obs); err != nil {
		t.Fatalf("建線後登入: %v", err)
	}
	row = baselineRow(t, db, 2, "198.51.100.7")
	if row.FirstSessionID == nil || *row.FirstSessionID != 21 {
		t.Errorf("登入不得改寫 first_session_id，實得 %v", row.FirstSessionID)
	}
	if row.FirstSessionAt == nil || !row.FirstSessionAt.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("登入不得改寫 first_session_at，實得 %v", row.FirstSessionAt)
	}
}

func TestSourceIPBaselineAlertWriteFailureRollsBackAndNextObservationCompensates(t *testing.T) {
	db := sourceIPBaselineDB(t)
	b := newBaselineForTest(t, db)
	t0 := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	// 前置：先登入使基準列存在（first_session 兩欄 NULL）——回滾斷言才能區分
	// 「整列消失」與「首次建線轉態被回捲」
	if _, err := b.ObserveLogin(context.Background(), LoginObservation{
		UserID: 3, Username: "u3", IP: "192.0.2.9", Now: t0}); err != nil {
		t.Fatalf("前置登入: %v", err)
	}

	sentinel := errors.New("injected alert write failure")
	var fired atomic.Int64
	b.beforeAlertWrite = func() error {
		fired.Add(1)
		return sentinel
	}
	_, err := b.ObserveSession(context.Background(), 3, "192.0.2.9", 31, nil, t0.Add(time.Hour))
	if !errors.Is(err, sentinel) {
		t.Fatalf("注入的錯誤應原樣上拋，實得: %v", err)
	}
	if fired.Load() < 1 {
		t.Fatal("注入點一次都沒走到：本測試沒測到回滾路徑")
	}
	row := baselineRow(t, db, 3, "192.0.2.9")
	if row.FirstSessionID != nil || row.FirstSessionAt != nil {
		t.Errorf("告警寫入失敗後基準不得轉態（整筆回滾），實得 %+v", row)
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 0 {
		t.Fatalf("回滾後告警表應零列，實得 %d", n)
	}

	// 解除注入再觀察一次：資格仍在、恰一筆補發
	b.beforeAlertWrite = nil
	winner, err := b.ObserveSession(context.Background(), 3, "192.0.2.9", 32, nil, t0.Add(2*time.Hour))
	if err != nil || !winner {
		t.Fatalf("回滾後下一次觀察應補發，實得 (%v, %v)", winner, err)
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 1 {
		t.Fatalf("補發應恰一筆，實得 %d", n)
	}
	row = baselineRow(t, db, 3, "192.0.2.9")
	if row.FirstSessionID == nil || *row.FirstSessionID != 32 {
		t.Errorf("補發勝者應為 32，實得 %v", row.FirstSessionID)
	}
}

func TestSourceIPBaselineAuditWriteFailureRollsBackLoginMark(t *testing.T) {
	db := sourceIPBaselineDB(t)
	b := newBaselineForTest(t, db)
	t0 := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

	sentinel := errors.New("injected audit write failure")
	var fired atomic.Int64
	b.beforeAuditWrite = func() error {
		fired.Add(1)
		return sentinel
	}
	_, err := b.ObserveLogin(context.Background(), LoginObservation{
		UserID: 4, Username: "u4", IP: "192.0.2.10", Now: t0})
	if !errors.Is(err, sentinel) {
		t.Fatalf("注入的錯誤應原樣上拋，實得: %v", err)
	}
	if fired.Load() < 1 {
		t.Fatal("注入點一次都沒走到")
	}
	var n int64
	if err := db.Model(&model.UserSourceIP{}).Where("user_id = 4").Count(&n).Error; err != nil {
		t.Fatalf("count baseline: %v", err)
	}
	if n != 0 {
		t.Fatalf("審計標記寫入失敗後基準列不得存在（整筆回滾），實得 %d 列", n)
	}

	// 解除注入：下一次登入補寫
	b.beforeAuditWrite = nil
	inserted, err := b.ObserveLogin(context.Background(), LoginObservation{
		UserID: 4, Username: "u4", IP: "192.0.2.10", Now: t0.Add(time.Hour)})
	if err != nil || !inserted {
		t.Fatalf("回滾後下一次登入應補寫，實得 (%v, %v)", inserted, err)
	}
	if err := db.Model(&model.AuditLog{}).Where("action = ? AND user_id = 4", string(model.ActionNewSourceIP)).Count(&n).Error; err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("補寫應恰一筆標記，實得 %d", n)
	}
}

func TestSourceIPBaselineNotWiredAndDBErrorReturnError(t *testing.T) {
	db := sourceIPBaselineDB(t)
	// 告警落地面不是組裝根建構的具體型別 → 回明確錯誤而非靜默不告警
	b := NewSourceIPBaseline(db, stubAlertSink{}, NewTxSink())
	if _, err := b.ObserveSession(context.Background(), 1, "203.0.113.5", 1, nil, time.Now()); !errors.Is(err, ErrSourceIPBaselineNotWired) {
		t.Fatalf("非交易內告警落地面應回 ErrSourceIPBaselineNotWired，實得: %v", err)
	}

	// DB 錯（表被移走）→ 回 error 不 panic
	ok := newBaselineForTest(t, db)
	if err := db.Exec(`DROP TABLE user_source_ips`).Error; err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := ok.ObserveSession(context.Background(), 1, "203.0.113.5", 1, nil, time.Now()); err == nil {
		t.Fatal("表缺失應回 error")
	}
	if _, err := ok.ObserveLogin(context.Background(), LoginObservation{UserID: 1, IP: "203.0.113.5", Now: time.Now()}); err == nil {
		t.Fatal("表缺失應回 error")
	}
}

// stubAlertSink 只滿足 gatewayapi.AlertSink、不具交易內方法。
type stubAlertSink struct{}

func (stubAlertSink) RecordAlert(context.Context, gatewayapi.CommandAlert) error   { return nil }
func (stubAlertSink) RecordAlerts(context.Context, []gatewayapi.CommandAlert) error { return nil }

// runConcurrentFirstSessions N 條 goroutine 同（帳號, 位址）、各自不同 session id
// 同時觀察，回傳勝者數與勝者 session id 集合。
func runConcurrentFirstSessions(t *testing.T, b *SourceIPBaseline, userID uint, ip string, n int) (int, []uint) {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int64
	var mu sync.Mutex
	var winnerSessions []uint
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(sessionID uint) {
			defer wg.Done()
			<-start
			w, err := b.ObserveSession(context.Background(), userID, ip, sessionID, nil, time.Now())
			if err != nil {
				errs <- fmt.Errorf("session %d: %w", sessionID, err)
				return
			}
			if w {
				winners.Add(1)
				mu.Lock()
				winnerSessions = append(winnerSessions, sessionID)
				mu.Unlock()
			}
		}(uint(100 + i))
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("並發觀察失敗: %v", err)
	}
	return int(winners.Load()), winnerSessions
}

func TestSourceIPBaselineConcurrentFirstSessionsSingleWinner(t *testing.T) {
	db := sourceIPBaselineDB(t)
	b := newBaselineForTest(t, db)

	winners, sessions := runConcurrentFirstSessions(t, b, 5, "203.0.113.99", 16)
	if winners != 1 {
		t.Fatalf("勝者應恰一個，實得 %d（%v）", winners, sessions)
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 1 {
		t.Fatalf("並發首連線應恰一筆告警，實得 %d", n)
	}
	var alert model.CommandAlert
	if err := db.Where("kind = ?", model.AlertKindNewSourceIP).First(&alert).Error; err != nil {
		t.Fatalf("讀告警: %v", err)
	}
	row := baselineRow(t, db, 5, "203.0.113.99")
	if row.FirstSessionID == nil || alert.SessionID != *row.FirstSessionID {
		t.Errorf("告警的 session_id（%d）應等於基準列 first_session_id（%v）", alert.SessionID, row.FirstSessionID)
	}
	if alert.SessionID != sessions[0] {
		t.Errorf("告警的 session_id（%d）應等於回報勝者（%v）", alert.SessionID, sessions)
	}
}

// TestSourceIPBaselinePGConcurrentFirstSessionsSingleWinner 真 PostgreSQL 上的
// 單勝者語義：ON CONFLICT 的條件更新與 RETURNING 是方言敏感的核心，sqlite 的綠
// 證明不了這裡。
func TestSourceIPBaselinePGConcurrentFirstSessionsSingleWinner(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	const schema = "sip_baseline_conc_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("postgres 連線失敗: %v", err)
	}
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		t.Fatalf("清理舊 schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("建立 schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec(drop)
		if s, err := admin.DB(); err == nil {
			_ = s.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("scoped 連線: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	if err := db.AutoMigrate(&model.UserSourceIP{}, &model.CommandAlert{}, &model.AuditLog{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	b := newBaselineForTest(t, db)

	winners, sessions := runConcurrentFirstSessions(t, b, 6, "2001:db8::9", 16)
	if winners != 1 {
		t.Fatalf("勝者應恰一個，實得 %d（%v）", winners, sessions)
	}
	if n := countAlerts(t, db, model.AlertKindNewSourceIP); n != 1 {
		t.Fatalf("並發首連線應恰一筆告警，實得 %d", n)
	}
	var alert model.CommandAlert
	if err := db.Where("kind = ?", model.AlertKindNewSourceIP).First(&alert).Error; err != nil {
		t.Fatalf("讀告警: %v", err)
	}
	row := baselineRow(t, db, 6, "2001:db8::9")
	if row.FirstSessionID == nil || alert.SessionID != *row.FirstSessionID {
		t.Errorf("告警的 session_id（%d）應等於基準列 first_session_id（%v）", alert.SessionID, row.FirstSessionID)
	}

	// 同庫再驗登入路徑的方言相等判定（timestamptz 微秒截斷）
	inserted, err := b.ObserveLogin(context.Background(), LoginObservation{
		UserID: 7, Username: "u7", IP: "203.0.113.77", Now: time.Now()})
	if err != nil || !inserted {
		t.Fatalf("pg 首次登入應為新建，實得 (%v, %v)", inserted, err)
	}
	inserted, err = b.ObserveLogin(context.Background(), LoginObservation{
		UserID: 7, Username: "u7", IP: "203.0.113.77", Now: time.Now()})
	if err != nil || inserted {
		t.Fatalf("pg 再登入應為已見，實得 (%v, %v)", inserted, err)
	}
}
