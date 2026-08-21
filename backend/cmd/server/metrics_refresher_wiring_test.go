package main

import (
	"bytes"
	"context"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/observability"
)

// 指標背景刷新的接線回歸（observability-lite，2026-08-16 `cmd/server` 競態 FAIL）。
//
// 缺陷形態：資料源在**執行當下**才裸讀全域 `database.DB`，而刷新跑在背景 goroutine，
// 其執行時刻與組裝根的生命週期無關。全域被關閉／還原後那一刻的刷新讀到 nil，
// gorm 解參考 panic，而背景 goroutine 的 panic 直接終止整個行程——一個旁路的指標
// 查詢因此有能力讓正在服務連線的堡壘機下線。
//
// 本檔守兩件事：接線層的可用性檢查（回 error 而非解參考），與刷新層的 panic 攔截。

// newAlertMetricsDB 建一個含 command_alerts 的 sqlite DB 並裝上全域，測試結束還原。
//
// sqlite `:memory:` 每條新連線是獨立的空 DB，連線池必須收到 1，
// 否則寫入與讀回會落在不同 DB 上而恆為零列（假綠）。
func newAlertMetricsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: glogger.Discard})
	require.NoError(t, err, "開 sqlite")
	sqlDB, err := db.DB()
	require.NoError(t, err, "取底層 sql.DB")
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.CommandAlert{}), "migrate command_alerts")

	now := time.Now()
	reviewed := now.Add(-time.Hour)
	rule1, rule2 := uint(1), uint(2)
	rows := []model.CommandAlert{
		{RuleID: &rule1, RuleName: "r", SessionID: 1, UserID: 1, Command: "rm -rf /", Severity: "high", TriggeredAt: now, Disposition: "pending"},
		{RuleID: &rule1, RuleName: "r", SessionID: 2, UserID: 1, Command: "rm -rf /", Severity: "high", TriggeredAt: now, Disposition: "pending"},
		{RuleID: &rule2, RuleName: "r2", SessionID: 3, UserID: 1, Command: "id", Severity: "low", TriggeredAt: now, Disposition: "pending"},
		// 已審閱的不該入未審閱計數（正對照的另一半）
		{RuleID: &rule2, RuleName: "r2", SessionID: 4, UserID: 1, Command: "id", Severity: "low", TriggeredAt: now, Disposition: "benign", ReviewedAt: &reviewed},
	}
	require.NoError(t, db.Create(&rows).Error, "塞入 command_alerts 樣本")

	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	return db
}

// TestMetricsRefreshSourcesGuardUnavailableDB 資料源在 DB 不可用時 SHALL 回 error，不得解參考。
func TestMetricsRefreshSourcesGuardUnavailableDB(t *testing.T) {
	// —— 前置條件：被守的那個失敗形態真的存在 ——
	// 若 nil 句柄本來就不會 panic，底下所有「守衛擋住了」的斷言都是空的
	require.Panics(t, func() {
		_, _ = audit.NewCommandAlertService(nil).CountUnreviewedBySeverity()
	}, "nil DB 句柄未 panic：本檔守衛的失敗形態不存在，全部斷言將由假前提成立")

	sessionService := session.NewSessionService(nil)
	recordingService := session.NewRecordingService(t.TempDir())

	// 組裝時句柄即為空（例如在 DB 就緒前接線）
	nilSrc := newMetricsRefreshSources(nil, sessionService, recordingService)
	_, err := nilSrc.PendingAlerts()
	require.Error(t, err, "句柄為 nil 時 PendingAlerts 未回錯——它要嘛 panic 了，要嘛回了假數字")
	_, err = nilSrc.ActiveSessions()
	require.Error(t, err, "句柄為 nil 時 ActiveSessions 未回錯")

	// —— 正對照：句柄有效時資料源必須成功 ——
	// 沒有這一段，上面的 Error 斷言可以由「這條路永遠回錯」滿足
	db := newAlertMetricsDB(t)
	src := newMetricsRefreshSources(db, sessionService, recordingService)
	got, err := src.PendingAlerts()
	require.NoError(t, err, "句柄有效時 PendingAlerts 竟失敗：守衛過嚴，指標將永遠不更新")
	require.Equal(t, map[string]float64{"high": 2, "low": 1}, got,
		"未審閱計數不符（已審閱的那筆不該入帳）")

	// —— 缺陷情境：刷新啟動後全域被移除（關機序後段、測試還原全域）——
	database.DB = nil
	_, err = src.PendingAlerts()
	require.Error(t, err, "全域被移除後 PendingAlerts 未回錯：指標可能由兩個不同的 DB 拼出來")
	_, err = src.ActiveSessions()
	require.Error(t, err, "全域被移除後 ActiveSessions 未回錯——這正是 panic 的入口")
}

// TestMetricsRefresherSurvivesUnguardedNilDBSource 刷新進行中資料源 panic → 行程存活且留下紀錄。
//
// 這裡刻意用**未設防**的資料源（與缺陷發生時的接線逐字同構：執行當下才把
// `database.DB` 交給 gorm），驗的是最後一道防線：接線層的守衛若哪天被繞過或漏掉，
// 指標刷新仍然不得殺掉行程。
//
// 攔截失效時本測試不會是紅的——整個 test binary 會當場 panic 而死，
// 與缺陷發生時 `cmd/server` 的表現同構。
func TestMetricsRefresherSurvivesUnguardedNilDBSource(t *testing.T) {
	var logs syncLogBuffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	var calls, healthy int32
	m := observability.New()
	stop := observability.StartRefresher(m, observability.RefreshSources{
		PendingAlerts: func() (map[string]float64, error) {
			atomic.AddInt32(&calls, 1)
			counts, err := audit.NewCommandAlertService(nil).CountUnreviewedBySeverity()
			if err != nil {
				return nil, err
			}
			out := make(map[string]float64, len(counts))
			for k, v := range counts {
				out[k] = float64(v)
			}
			return out, nil
		},
		// 另一個健康的資料源：它有沒有繼續被刷，決定了「該輪跳過」與「任務死了」的分別
		RecordingStorage: func() (float64, error) {
			atomic.AddInt32(&healthy, 1)
			return 42, nil
		},
	}, 5*time.Millisecond)
	t.Cleanup(func() { _ = stop(context.Background()) })

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) >= 2 && atomic.LoadInt32(&healthy) >= 2 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	// 前置條件：panic 真的被觸發過不只一次（一次也沒觸發 → 本測試什麼都沒證明；
	// 只觸發一次 → 分不出「攔下了」與「任務被第一次 panic 帶走」）
	require.GreaterOrEqualf(t, atomic.LoadInt32(&calls), int32(2),
		"nil 句柄資料源只被呼叫 %d 次：注入未觸發或任務已被首次 panic 終止", atomic.LoadInt32(&calls))
	require.GreaterOrEqual(t, atomic.LoadInt32(&healthy), int32(2),
		"健康資料源未持續被刷新：panic 已使整條任務停擺")

	require.NoError(t, stop(context.Background()), "停止函式未等到刷新結束")

	out := logs.String()
	require.Contains(t, out, "未審閱告警數", "log 未指出是哪一個資料源出事")
	require.Contains(t, out, "invalid memory address",
		"log 未帶出 panic 值：攔截若不留現場，就是把根因藏起來而非處理掉")
}

// syncLogBuffer log 輸出的併發安全接收端（刷新在背景 goroutine 內寫、測試主 goroutine 讀）。
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
