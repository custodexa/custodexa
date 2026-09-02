package sshproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
)

// 會話的四種非自願結束：閒置、慢速消費者（兩條分支）、目標端關閉、管理端終斷。
//
// # 為什麼結束原因值得單獨測
//
// 四者在畫面上都只是「連線斷了」，差別全在會話列的 `end_reason` 與審計事件。
// 稽核員回頭看一場會話時，「客戶端自己關掉」與「我方因為它讀不動而收線」
// 是兩個不同的結論，而只有寫進去的那一個值分得出來。

// waitFor 輪詢等待條件成立（計時類測試不睡固定長度：睡太短假紅、睡太長全包變慢）
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等不到：%s（上限 %s）", what, limit)
}

// closedReasonOf 取出佇列中的 `closed` 訊息原因
func closedReasonOf(msgs []map[string]any) string {
	for _, m := range msgs {
		if m["type"] == consoleMsgClosed {
			if r, ok := m["reason"].(string); ok {
				return r
			}
		}
	}
	return ""
}

// hasConsoleAuditKind 審計列中是否有指定 kind 與欄位
func hasConsoleAuditKind(t *testing.T, e *consoleEnv, kind string, check func(map[string]any) bool) bool {
	t.Helper()
	for _, row := range e.auditRows(t) {
		var body map[string]any
		if json.Unmarshal([]byte(row.RequestBody), &body) != nil {
			continue
		}
		if body["kind"] != kind {
			continue
		}
		if check == nil || check(body) {
			return true
		}
	}
	return false
}

// TestConsoleIdleTimeoutEndsSession 閒置逾時的結束原因。
//
// 閒置自**最後一則客戶端訊息**起算，不含伺服端的送出——
// 一條跑了五十分鐘的語句不該讓會話被判為閒置
func TestConsoleIdleTimeoutEndsSession(t *testing.T) {
	old := consoleTimeoutTick
	consoleTimeoutTick = 5 * time.Millisecond
	t.Cleanup(func() { consoleTimeoutTick = old })

	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)
	f.s.touch()

	done := make(chan struct{})
	go f.s.watchTimeouts(time.Millisecond, 0, time.Now(), done)
	t.Cleanup(func() { close(done) })

	// 同步點取 `closed` 幀而非 end_reason：收尾是「先寫 end_reason、再把幀塞進
	// 佇列」兩步，以第一步當同步點會在幀入列前就把佇列讀空。反過來成立——
	// 幀看得到，end_reason 必然已經寫好
	var frames []map[string]any
	waitFor(t, 2*time.Second, "閒置逾時的 closed 幀", func() bool {
		frames = append(frames, f.drain()...)
		return closedReasonOf(frames) != ""
	})
	if got := closedReasonOf(frames); got != consoleClosedIdleTimeout {
		t.Errorf("closed.reason = %q，期望 %q", got, consoleClosedIdleTimeout)
	}
	if got := f.s.EndReason(); got != endReasonIdleTimeout {
		t.Errorf("end_reason = %q，期望 %q", got, endReasonIdleTimeout)
	}
}

// TestConsoleMaxDurationEndsSession 最大時長到期的結束原因（與閒置分屬兩個值）
func TestConsoleMaxDurationEndsSession(t *testing.T) {
	old := consoleTimeoutTick
	consoleTimeoutTick = 5 * time.Millisecond
	t.Cleanup(func() { consoleTimeoutTick = old })

	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)
	f.s.touch()

	done := make(chan struct{})
	go f.s.watchTimeouts(0, time.Millisecond, time.Now(), done)
	t.Cleanup(func() { close(done) })

	waitFor(t, 2*time.Second, "最大時長收線", func() bool {
		return f.s.EndReason() != ""
	})
	if got := f.s.EndReason(); got != endReasonMaxDuration {
		t.Errorf("end_reason = %q，期望 %q", got, endReasonMaxDuration)
	}
}

// TestConsoleSlowConsumerQueueFullClosesSession 外送佇列滿即收線。
//
// 背壓的方向必須是關掉這一條連線：無界緩衝會把一個讀不動的客戶端
// 變成整個行程的記憶體風險
func TestConsoleSlowConsumerQueueFullClosesSession(t *testing.T) {
	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)

	// 佇列深度為 OutboundQueueDepth，且測試不取用——第 depth+1 則即溢位
	for i := 0; i < dbconsole.OutboundQueueDepth+1; i++ {
		f.s.sendNotice(consoleNoticeDatabaseSwitched, map[string]any{"database": "app"})
	}

	if got := f.s.EndReason(); got != model.EndReasonSlowConsumer {
		t.Fatalf("end_reason = %q，期望 %q", got, model.EndReasonSlowConsumer)
	}
	if !hasConsoleAuditKind(t, f.env, consoleKindConnectionClose, func(b map[string]any) bool {
		return b["reason"] == consoleClosedSlowConsumer
	}) {
		t.Errorf("慢速消費者收線未留痕")
	}
}

// TestConsoleSlowConsumerWriteDeadlineClosesSession 單則寫入逾期即收線。
//
// 這是與佇列滿不同的一條分支：客戶端連著但不讀，佇列裡的訊息還沒滿，
// 卡住的是 socket 本身。**判定依據是寫入期限到期而不是連線壞掉**——
// 後者只是客戶端走了，不該記成慢速消費者
func TestConsoleSlowConsumerWriteDeadlineClosesSession(t *testing.T) {
	if testing.Short() {
		t.Skip("寫入期限為釘住的常數，本測試需等它到期")
	}
	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)

	// 讓伺服端拿到一條真的 WebSocket，客戶端連上後**完全不讀**
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		f.s.ws = ws
		close(ready)
		f.s.writePump()
	}))
	defer srv.Close()

	client, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("WebSocket 連線失敗: %v", err)
	}
	defer client.Close()
	<-ready

	// 每則約 1 MiB：socket 緩衝很快填滿而佇列（16 則）填不滿，
	// 逼出的就是寫入期限那條分支
	blob := strings.Repeat("x", 1<<20)
	for i := 0; i < dbconsole.OutboundQueueDepth; i++ {
		f.s.sendNotice(consoleNoticeDatabaseSwitched, map[string]any{"database": blob})
	}

	waitFor(t, dbconsole.WriteDeadline+20*time.Second, "寫入逾期收線", func() bool {
		return f.s.EndReason() != ""
	})
	if got := f.s.EndReason(); got != model.EndReasonSlowConsumer {
		t.Fatalf("end_reason = %q，期望 %q（寫入逾期必須與客戶端自己離開分開記）",
			got, model.EndReasonSlowConsumer)
	}
	if !hasConsoleAuditKind(t, f.env, consoleKindConnectionClose, func(b map[string]any) bool {
		return b["reason"] == consoleClosedSlowConsumer
	}) {
		t.Errorf("寫入逾期收線未留痕")
	}
}

// TestConsoleTargetClosedDoesNotRedial 目標連線關閉後零重撥。
//
// 重撥要重新解封憑證，那是一次沒有票、沒有閘序的連線建立——
// 而使用者看到的只是「連線恢復了」
func TestConsoleTargetClosedDoesNotRedial(t *testing.T) {
	d := &stubDialect{currentDB: "app", execErr: io.EOF}
	f := newConsoleFixture(t, d)

	f.runQuery("SELECT 1")

	if got := f.s.EndReason(); got != model.EndReasonTargetClosed {
		t.Fatalf("end_reason = %q，期望 %q", got, model.EndReasonTargetClosed)
	}
	if d.dialCount != 0 {
		t.Errorf("目標連線關閉後重撥了 %d 次", d.dialCount)
	}
	if f.s.currentDialect() != dbconsole.Dialect(d) {
		t.Errorf("連線被換過——這條路徑不得重建連線")
	}
	execs := 0
	for _, c := range d.callLog() {
		if strings.HasPrefix(c, "exec:") {
			execs++
		}
	}
	if execs != 1 {
		t.Errorf("送出次數 = %d，期望 1（失敗後不得重送）", execs)
	}
	if got := closedReasonOf(f.drain()); got != consoleClosedTargetClosed {
		t.Errorf("closed.reason = %q，期望 %q", got, consoleClosedTargetClosed)
	}
	if !strings.Contains(f.sink.String(), "-- connection closed: "+consoleClosedTargetClosed) {
		t.Errorf("轉錄未記連線關閉：%q", f.sink.String())
	}
	if !hasConsoleAuditKind(t, f.env, consoleKindConnectionClose, func(b map[string]any) bool {
		return b["reason"] == consoleClosedTargetClosed
	}) {
		t.Errorf("目標連線關閉未留痕")
	}
	// 該單位的結論是「不知道」，不是「失敗」
	_, backfill := f.recorder.snapshot()
	found := false
	for _, fct := range backfill {
		if fct.Status == model.ResultStatusEffectUnknown && fct.Reason == model.ReasonConnectionLost {
			found = true
		}
	}
	if !found {
		t.Errorf("回填狀態 = %+v，期望 effect_unknown/connection_lost", backfill)
	}
}

// TestConsoleCancelClosesSessionBeforeNextStatement 取消打死目標連線後，
// 使用者**不必再送一句**就會收到 closed。
//
// MySQL 的取消實作是關閉連線，該單位因此記 effect_unknown/cancel_unconfirmed
// ——這個語義本身是對的，且不因本測試而改變。但「連線死了」被這個原因碼蓋掉時，
// 會話會一路撐到下一句才發現，而那一句是在死連線上開場的：它一個位元組都沒送到
// 目標端，卻在語句紀錄裡留下一列「送了但不知結果」。稽核員讀到的會是一句
// 從未發生的執行
func TestConsoleCancelClosesSessionBeforeNextStatement(t *testing.T) {
	d := &stubDialect{
		currentDB: "app",
		execOutcomes: []*dbconsole.ExecOutcome{{
			Status:         dbconsole.StatusEffectUnknown,
			Reason:         dbconsole.ReasonCancelUnconfirmed,
			TxState:        dbconsole.TxStateUnknown,
			ConnectionLost: true,
		}},
	}
	f := newConsoleFixture(t, d)
	// 取消在語句進行中送達（生產路徑上它來自讀取迴圈，與執行不同 goroutine）
	d.execHook = func() { f.s.handleCancel(f.s.lastEventID()) }

	f.runQuery("SELECT SLEEP(20)")

	if got := closedReasonOf(f.drain()); got != consoleClosedTargetClosed {
		t.Errorf("closed.reason = %q，期望 %q（取消後未再送語句即應收到）",
			got, consoleClosedTargetClosed)
	}
	if got := f.s.EndReason(); got != model.EndReasonTargetClosed {
		t.Errorf("end_reason = %q，期望 %q", got, model.EndReasonTargetClosed)
	}
	if !hasConsoleAuditKind(t, f.env, consoleKindConnectionClose, func(b map[string]any) bool {
		return b["reason"] == consoleClosedTargetClosed
	}) {
		t.Errorf("目標連線關閉未留痕")
	}
	if !strings.Contains(f.sink.String(), "-- connection closed: "+consoleClosedTargetClosed) {
		t.Errorf("轉錄未記連線關閉：%q", f.sink.String())
	}

	// 取消那一筆的結論不變：未獲確認＝我們不知道它生效了沒
	rows, backfill := f.recorder.snapshot()
	if len(rows) != 1 {
		t.Fatalf("語句紀錄 = %d 列，期望 1（未送出的語句不得留下紀錄）", len(rows))
	}
	if fct := backfill[rows[0].ID]; fct.Status != model.ResultStatusEffectUnknown ||
		fct.Reason != model.ReasonCancelUnconfirmed {
		t.Errorf("回填 = %s/%s，期望 effect_unknown/cancel_unconfirmed",
			fct.Status, fct.Reason)
	}

	execs, cancelled := 0, false
	for _, c := range d.callLog() {
		if strings.HasPrefix(c, "exec:") {
			execs++
		}
		if c == "cancel" {
			cancelled = true
		}
	}
	if !cancelled {
		t.Errorf("取消未送達方言層：%v", d.callLog())
	}
	if execs != 1 {
		t.Errorf("送出次數 = %d，期望 1（連線已死不得再送）", execs)
	}
}

// TestConsoleAssetDisabledTerminatesSession 資產停用即收線。
//
// 走的是與命令列會話同一條路：`TerminateByAsset` → 連線註冊表 → 會話自己的收線回呼。
// end_reason 留給終斷那一側寫——只有它知道是誰、為什麼終止的
func TestConsoleAssetDisabledTerminatesSession(t *testing.T) {
	d := &stubDialect{currentDB: "app"}
	f := newConsoleFixture(t, d)
	f.env.h.SessionService = session.NewSessionService(f.env.h.Registry)
	f.env.h.Registry.Register(f.s.sessionID(), f.s.terminate)

	n, err := f.env.h.SessionService.TerminateByAsset(1, model.EndReasonAssetDisabled)
	if err != nil {
		t.Fatalf("資產停用收線失敗: %v", err)
	}
	if n != 1 {
		t.Fatalf("收線會話數 = %d，期望 1", n)
	}

	if got := closedReasonOf(f.drain()); got != consoleClosedTerminated {
		t.Errorf("closed.reason = %q，期望 %q", got, consoleClosedTerminated)
	}
	var row model.Session
	if err := f.env.db.First(&row, f.s.sessionID()).Error; err != nil {
		t.Fatalf("查會話列: %v", err)
	}
	if row.EndReason != model.EndReasonAssetDisabled {
		t.Errorf("會話列 end_reason = %q，期望 %q", row.EndReason, model.EndReasonAssetDisabled)
	}
}

// TestConsoleTranscriptTruncatesLongErrorMessage 轉錄保存的錯誤訊息截斷。
//
// 訊息可能夾帶資料片段（唯一約束違反會回鍵值），而轉錄是長期保存的；
// 截斷以字元為單位——按位元組切會把多位元組字元切成兩半，
// 寫進 .cast 就是一段無效 UTF-8
func TestConsoleTranscriptTruncatesLongErrorMessage(t *testing.T) {
	sink := &captureSink{}
	tr := newConsoleTranscript(sink)
	long := strings.Repeat("中", consoleTranscriptMaxMessage+300)
	tr.Error("01ARZ3NDEKTSV4RRFFQ69G5FAV", "1062", long)

	line := sink.String()
	if !strings.Contains(line, "01ARZ3NDEKTSV4RRFFQ69G5FAV") {
		t.Fatalf("轉錄行未帶事件識別：%q", line)
	}
	body := strings.TrimSuffix(strings.SplitN(line, ": ", 2)[1], "\r\n")
	if !strings.HasSuffix(body, "…") {
		t.Errorf("超長訊息未標記截斷：%q", body[:40])
	}
	if got := len([]rune(strings.TrimSuffix(body, "…"))); got != consoleTranscriptMaxMessage {
		t.Errorf("截斷後 %d 個字元，期望 %d", got, consoleTranscriptMaxMessage)
	}
	if strings.ContainsRune(body, '�') {
		t.Errorf("截斷切壞了多位元組字元：%q", body[:40])
	}
}

// gin 需在測試中處於 TestMode（本檔的 httptest 路徑會自建引擎）
func init() { gin.SetMode(gin.TestMode) }
