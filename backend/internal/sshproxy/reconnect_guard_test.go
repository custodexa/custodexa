package sshproxy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gorilla/websocket"
)

// 資料庫命令列的改連目標守衛：以假的命令列子程序（行編輯語義：可印字元累積、
// Backspace／Ctrl+W 刪字、Ctrl+C／Ctrl+U 清行、Enter 送出）取代真子程序，
// 觀測點是「子程序實際送出（執行）過哪些行」與「它當前輸入行還剩什麼」。

// fakeCLI 假的命令列子程序：實作 TerminalConn，記錄寫入並模擬行編輯。
type fakeCLI struct {
	*fakeTerminalConn
	clearErr error // 非 nil＝Ctrl+C 寫入失敗

	mu       sync.Mutex
	raw      [][]byte
	cur      []byte
	executed []string
	esc      int // 0 正常；1 剛收 ESC；2 在 CSI 序列中
}

func newFakeCLI(clearErr error) *fakeCLI {
	return &fakeCLI{fakeTerminalConn: newFakeTerminalConn(), clearErr: clearErr}
}

func (c *fakeCLI) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.raw = append(c.raw, append([]byte(nil), p...))
	if len(p) == 1 && p[0] == 0x03 && c.clearErr != nil {
		return 0, c.clearErr
	}
	for _, b := range p {
		switch c.esc {
		case 1:
			if b == '[' {
				c.esc = 2
			} else {
				c.esc = 0
			}
			continue
		case 2:
			if b >= 0x40 && b <= 0x7e {
				c.esc = 0
			}
			continue
		}
		switch {
		case b == 0x1b:
			c.esc = 1
		case b == '\r' || b == '\n':
			c.executed = append(c.executed, string(c.cur))
			c.cur = nil
		case b == 0x03 || b == 0x15:
			c.cur = nil
		case b == 0x17: // Ctrl+W：刪掉游標前的一個字（含其前的空白）
			s := strings.TrimRight(string(c.cur), " ")
			if i := strings.LastIndex(s, " "); i >= 0 {
				c.cur = []byte(s[:i+1])
			} else {
				c.cur = nil
			}
		case b == 0x7f || b == 0x08:
			if len(c.cur) > 0 {
				c.cur = c.cur[:len(c.cur)-1]
			}
		case b >= 0x20:
			c.cur = append(c.cur, b)
		}
	}
	return len(p), nil
}

func (c *fakeCLI) executedLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.executed...)
}

func (c *fakeCLI) currentLine() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.cur)
}

func (c *fakeCLI) sawCtrlC() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, w := range c.raw {
		if len(w) == 1 && w[0] == 0x03 {
			return true
		}
	}
	return false
}

// reconnectAlertSink 記錄落地的告警。
type reconnectAlertSink struct {
	mu     sync.Mutex
	alerts []gatewayapi.CommandAlert
}

func (s *reconnectAlertSink) RecordAlert(_ context.Context, a gatewayapi.CommandAlert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
	return nil
}

func (s *reconnectAlertSink) RecordAlerts(ctx context.Context, as []gatewayapi.CommandAlert) error {
	for _, a := range as {
		_ = s.RecordAlert(ctx, a)
	}
	return nil
}

func (s *reconnectAlertSink) list() []gatewayapi.CommandAlert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]gatewayapi.CommandAlert(nil), s.alerts...)
}

// keystrokeSpy 代鍵盤紀錄旁路：記錄轉送的輸入、被攔的輸入與平台送出的中斷。
type keystrokeSpy struct {
	mu       sync.Mutex
	forward  []byte
	blocked  []byte
	platform []byte
}

func (k *keystrokeSpy) WriteInput(p []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.forward = append(k.forward, p...)
}
func (k *keystrokeSpy) WriteBlockedInput(p []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.blocked = append(k.blocked, p...)
}
func (k *keystrokeSpy) WritePlatformInput(p []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.platform = append(k.platform, p...)
}
func (k *keystrokeSpy) snapshot() (forward, blocked, platform string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return string(k.forward), string(k.blocked), string(k.platform)
}

// frameLog 在背景持續讀取後端送給前端的幀。
type frameLog struct {
	mu     sync.Mutex
	frames []Message
}

func (f *frameLog) add(raw []byte) {
	var m Message
	if json.Unmarshal(raw, &m) == nil {
		f.mu.Lock()
		f.frames = append(f.frames, m)
		f.mu.Unlock()
	}
}

func (f *frameLog) noticeCodes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.frames {
		if m.Type == MsgNotice {
			out = append(out, string(m.Code))
		}
	}
	return out
}

// reconnectRig 一條掛了改連守衛的 bridge 與它的觀測點。
type reconnectRig struct {
	b      *bridge
	cli    *fakeCLI
	rec    *captureSink
	alerts *reconnectAlertSink
	ks     *keystrokeSpy
	log    *frameLog
	send   func(string)
	entry  string
}

type rigOpts struct {
	clearErr error
	blocker  *commandBlocker
}

// newReconnectRig entry 為 "human"（真人 WebSocket）或 "agent"（行程內傳輸，AI agent 入口）。
func newReconnectRig(t *testing.T, protocol, entry string, o rigOpts) *reconnectRig {
	t.Helper()
	cli := newFakeCLI(o.clearErr)
	rig := &reconnectRig{cli: cli, rec: &captureSink{}, alerts: &reconnectAlertSink{}, ks: &keystrokeSpy{}, log: &frameLog{}, entry: entry}

	var server Transport
	switch entry {
	case "human":
		serverWS, clientWS := newWSPair(t)
		server = serverWS
		rig.send = func(data string) { sendInput(t, clientWS, data) }
		go func() {
			for {
				_, raw, err := clientWS.ReadMessage()
				if err != nil {
					return
				}
				rig.log.add(raw)
			}
		}()
	case "agent":
		srv, cl := NewInProcessTransportPair()
		server = srv
		rig.send = func(data string) {
			raw, err := EncodeMessage(MsgData, data)
			if err != nil {
				t.Fatalf("編碼輸入失敗: %v", err)
			}
			if err := cl.WriteMessage(websocket.TextMessage, raw); err != nil {
				t.Fatalf("送出輸入失敗: %v", err)
			}
		}
		go func() {
			for {
				_, raw, err := cl.ReadMessage()
				if err != nil {
					return
				}
				rig.log.add(raw)
			}
		}()
	default:
		t.Fatalf("未知入口 %q", entry)
	}

	b := newBridge(server, cli, nil, nil, "", 0, 0)
	b.outputSinks = append(b.outputSinks, rig.rec)
	b.inputSinks = append(b.inputSinks, rig.ks)
	b.blockedSinks = append(b.blockedSinks, rig.ks)
	b.platformSinks = append(b.platformSinks, rig.ks)
	if o.blocker != nil {
		b.attachBlocker(o.blocker)
	}
	// 與 handler 同一個建構函式與協議判斷
	b.attachReconnectGuard(newReconnectGuard(protocol, rig.alerts, 7, 8, 9))
	rig.b = b
	go b.pumpInput()
	t.Cleanup(b.stop)
	return rig
}

// settleMarker 同步標記行。它不帶 Ctrl+C：若子程序當前輸入還有殘留，標記會被接在殘留之後，
// 執行過的行就不再等於標記本身，殘留因此顯形。
const settleMarker = "echo-settle"

// settle 等到輸入泵處理完先前送出的所有幀：再送一行同步標記並等它被執行。
func (r *reconnectRig) settle(t *testing.T) {
	t.Helper()
	r.send(settleMarker + "\r")
	rcWaitFor(t, "同步標記行被執行", func() bool {
		for _, l := range r.cli.executedLines() {
			if strings.HasSuffix(l, settleMarker) {
				return true
			}
		}
		return false
	})
}

func rcWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待逾時：%s", what)
}

// executedExcludingSettle 執行過的行（略過同步標記）。
func (r *reconnectRig) executedExcludingSettle() []string {
	var out []string
	for _, l := range r.cli.executedLines() {
		if l != settleMarker {
			out = append(out, l)
		}
	}
	return out
}

// assertNoConnectExecuted 子程序從未執行含改連指令的行。
func assertNoConnectExecuted(t *testing.T, r *reconnectRig) {
	t.Helper()
	for _, l := range r.executedExcludingSettle() {
		low := strings.ToLower(l)
		if strings.Contains(low, "connect") || strings.Contains(l, `\r`) {
			t.Fatalf("子程序 stdin 收到該行並執行：%q（全部執行過的行：%q）", l, r.executedExcludingSettle())
		}
	}
}

// ── 七種改連形態都不得進入子程序 ──────────────────────────────────

func TestReconnectLineNotForwarded(t *testing.T) {
	cases := []struct{ name, protocol, input string }{
		{"redis 直接改連", "redis", "connect 203.0.113.5 6379\r"},
		{"redis 雙引號", "redis", "\"connect\" 203.0.113.5 6379\r"},
		{"redis 十六進位跳脫", "redis", "\"\\x63onnect\" 203.0.113.5 6379\r"},
		{"mysql 短指令", "mysql", "\\r db 203.0.113.5\r"},
		{"mysql 大小寫變體", "mysql", "CONNECT db 203.0.113.5;\r"},
		{"mysql 同行後段短指令", "mysql", "SELECT 1; \\r db 203.0.113.5\r"},
		{"mssql 前置空白大小寫混用", "mssql", "  :Connect 203.0.113.5\r"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newReconnectRig(t, c.protocol, "human", rigOpts{})
			r.send(c.input)
			r.settle(t)
			sent := strings.TrimRight(c.input, "\r")
			for _, l := range r.executedExcludingSettle() {
				if l == sent {
					t.Fatalf("子程序 stdin 收到該行並執行：%q", l)
				}
			}
			assertNoConnectExecuted(t, r)
		})
	}
}

// ── 涵蓋矩陣：入口 × 輸入形態 ───────────────────────────────────────────

// TestReconnectGuardMatrix 入口（真人 WebSocket、agent）× 輸入形態（單幀單行、單幀兩行、
// 跨幀、括號貼上、刪字鍵、站點零指令規則），每格都斷言：改連行未被執行、子程序當前輸入無殘留、
// 終端與錄影含警告、命中者有阻斷紀錄。
func TestReconnectGuardMatrix(t *testing.T) {
	type form struct {
		name     string
		protocol string
		frames   []string
		// wantExecuted 預期子程序執行過的行（不含同步標記）
		wantExecuted []string
		// wantNotice 預期的終端警告碼
		wantNotice string
	}
	forms := []form{
		{"單幀單行", "redis", []string{"connect 203.0.113.5 6379\r"}, nil, string(apierror.CodeDBReconnectBlocked)},
		{"單幀兩行", "redis", []string{"INFO clients\rconnect 203.0.113.5 6379\r"}, []string{"INFO clients"}, string(apierror.CodeDBReconnectBlocked)},
		{"跨幀", "redis", []string{"con", "nect 203.0.113.5", " 6379\r"}, nil, string(apierror.CodeDBReconnectBlocked)},
		{"括號貼上", "redis", []string{"\x1b[200~connect 203.0.113.5 6379\x1b[201~\r"}, nil, string(apierror.CodeDBReconnectBlocked)},
		{"刪字鍵", "redis", []string{"GET key", "\x17", "\r"}, nil, string(apierror.CodeDBLineUncertain)},
		{"站點零指令規則", "mysql", []string{"SELECT 1; \\r db 203.0.113.5\r"}, nil, string(apierror.CodeDBReconnectBlocked)},
	}
	for _, entry := range []string{"human", "agent"} {
		for _, f := range forms {
			t.Run(entry+"/"+f.name, func(t *testing.T) {
				r := newReconnectRig(t, f.protocol, entry, rigOpts{}) // 沒有掛任何指令阻斷器＝零規則
				for _, fr := range f.frames {
					r.send(fr)
				}
				r.settle(t)

				// (1) 改連行未進子程序
				assertNoConnectExecuted(t, r)
				got := r.executedExcludingSettle()
				if strings.Join(got, "|") != strings.Join(f.wantExecuted, "|") {
					t.Fatalf("執行過的行 = %q, want %q", got, f.wantExecuted)
				}
				// (2) 清行後子程序當前輸入無殘留（同步標記行前的 Ctrl+C 不能替它掩蓋：
				// 另以 sawCtrlC 確認守衛自己送過中斷）
				if !r.cli.sawCtrlC() {
					t.Fatal("被攔下後應送中斷位元組清掉子程序當前輸入")
				}
				if cur := r.cli.currentLine(); cur != "" {
					t.Fatalf("子程序當前輸入殘留 %q", cur)
				}
				// (3) 終端警告
				rcWaitFor(t, "終端收到警告幀", func() bool { return len(r.log.noticeCodes()) > 0 })
				if codes := r.log.noticeCodes(); codes[0] != f.wantNotice {
					t.Fatalf("終端警告碼 = %v, want %s", codes, f.wantNotice)
				}
				// (4) 錄影（輸出旁路）含警告
				rec := r.rec.String()
				if f.wantNotice == string(apierror.CodeDBReconnectBlocked) {
					if !strings.Contains(rec, "RULE_COMMAND_BLOCKED") || !strings.Contains(rec, apierror.DBReconnectRuleName) {
						t.Fatalf("錄影缺阻斷標記：%q", rec)
					}
					// 真人入口的畫面已有遠端回顯，證據行只給 agent 入口（且須經遮蔽）
					hasEvidence := strings.Contains(rec, "  > ")
					if entry == "human" && hasEvidence {
						t.Fatalf("真人入口的錄影不應另寫證據行：%q", rec)
					}
					if entry == "agent" && (!hasEvidence || strings.Contains(rec, "203.0.113.5")) {
						t.Fatalf("agent 入口應有證據行且經過遮蔽：%q", rec)
					}
					// (5) 阻斷紀錄
					rcWaitFor(t, "阻斷告警落地", func() bool { return len(r.alerts.list()) > 0 })
					a := r.alerts.list()[0]
					if a.Kind != model.AlertKindRule || !a.Blocked || a.RuleName != apierror.DBReconnectRuleName ||
						a.SessionID != 7 || a.Actor.UserID != 8 || a.AssetID == nil || *a.AssetID != 9 {
						t.Fatalf("阻斷告警內容不符：%+v", a)
					}
				} else {
					if !strings.Contains(rec, "RULE_DB_LINE_UNCERTAIN") {
						t.Fatalf("錄影缺「無法確定」標記：%q", rec)
					}
					if n := len(r.alerts.list()); n != 0 {
						t.Fatalf("無法確定的行不入阻斷告警，實得 %d 筆", n)
					}
				}
				// (6) 鍵盤紀錄的 blocked 旁路收到被攔下的位元組
				if _, blocked, platform := r.ks.snapshot(); blocked == "" || !strings.Contains(platform, "\x03") {
					t.Fatalf("鍵盤紀錄旁路缺 blocked／platform 輸入：blocked=%q platform=%q", blocked, platform)
				}
			})
		}
	}
}

// ── 相容性回歸 ───────────────────────────────────────────────────────

func TestReconnectGuardNormalQueriesUnaffected(t *testing.T) {
	for _, c := range []struct{ protocol, line string }{
		{"mysql", "SELECT 1;"},
		{"mysql", "SELECT disconnect_time FROM t;"},
		{"mysql", "\\R prompt>"},
		{"redis", "INFO clients"},
		{"redis", "GET connected_clients"},
		{"mssql", "SELECT name FROM sys.databases;"},
	} {
		t.Run(c.protocol+"/"+c.line, func(t *testing.T) {
			r := newReconnectRig(t, c.protocol, "human", rigOpts{})
			r.send(c.line + "\r")
			r.settle(t)
			if got := r.executedExcludingSettle(); len(got) != 1 || got[0] != c.line {
				t.Fatalf("一般查詢應照常轉送並執行，執行過的行 = %q", got)
			}
			if codes := r.log.noticeCodes(); len(codes) != 0 {
				t.Fatalf("一般查詢不應產生警告：%v", codes)
			}
			if n := len(r.alerts.list()); n != 0 {
				t.Fatalf("一般查詢不應產生阻斷紀錄，實得 %d 筆", n)
			}
		})
	}
}

// TestReconnectPostgresUntouched postgres 會話不套用本守衛：\c 行照常轉送（它走既有的再提示守衛）。
func TestReconnectPostgresUntouched(t *testing.T) {
	r := newReconnectRig(t, "postgres", "human", rigOpts{})
	if r.b.reconnect != nil {
		t.Fatal("postgres 會話不應掛改連守衛")
	}
	r.send("\\c appdb dbuser otherhost\r")
	r.settle(t)
	if got := r.executedExcludingSettle(); len(got) != 1 || got[0] != "\\c appdb dbuser otherhost" {
		t.Fatalf("postgres 的 \\c 行應照常轉送，執行過的行 = %q", got)
	}
}

// ── 無法確定整行時不轉送 ────────────────────────────────────────────────

func TestReconnectUncertainLineNotForwarded(t *testing.T) {
	for _, c := range []struct{ name, protocol string }{
		{"redis", "redis"}, {"mysql", "mysql"}, {"mssql", "mssql"},
	} {
		t.Run(c.name+" 方向鍵叫回歷史後 Enter", func(t *testing.T) {
			r := newReconnectRig(t, c.protocol, "human", rigOpts{})
			r.send("SET k v")
			r.send("\x1b[A") // 上方向鍵：叫回歷史，行內容已不可信
			r.send("\r")
			r.settle(t)
			if got := r.executedExcludingSettle(); len(got) != 0 {
				t.Fatalf("無法確定整行時不得轉送，子程序執行過 %q", got)
			}
			rcWaitFor(t, "終端收到提示", func() bool { return len(r.log.noticeCodes()) > 0 })
			if codes := r.log.noticeCodes(); codes[0] != string(apierror.CodeDBLineUncertain) {
				t.Fatalf("警告碼 = %v, want %s", codes, apierror.CodeDBLineUncertain)
			}
			if cur := r.cli.currentLine(); cur != "" {
				t.Fatalf("子程序當前輸入殘留 %q", cur)
			}
		})
	}
	t.Run("提示後重新輸入可正常執行", func(t *testing.T) {
		r := newReconnectRig(t, "redis", "human", rigOpts{})
		r.send("SET k v\x1b[D\r") // 左方向鍵
		r.send("INFO clients\r")
		r.settle(t)
		if got := r.executedExcludingSettle(); len(got) != 1 || got[0] != "INFO clients" {
			t.Fatalf("重新輸入的行應執行，執行過的行 = %q", got)
		}
	})
}

// ── 與指令阻斷器並存 ────────────────────────────────────────────────────

// exactMatcher 只在整行恰為 target 時命中。
type exactMatcher struct{ target string }

func (m *exactMatcher) MatchBlock(command, protocol string) (*model.AlertRule, bool) {
	if command == m.target {
		return &model.AlertRule{Name: "exact"}, true
	}
	return nil, false
}

// TestReconnectBlockClearsBlockerBuffer 被守衛攔下的行不會走到阻斷器的 Enter；
// 阻斷器已累積的前綴必須清掉，否則下一行會與它拼接而誤判。
func TestReconnectBlockClearsBlockerBuffer(t *testing.T) {
	blocker := newCommandBlocker(&exactMatcher{target: "zzz"}, nil, 1, 2, 3, "redis")
	r := newReconnectRig(t, "redis", "human", rigOpts{blocker: blocker})
	r.send("connect 203.0.113.5")
	r.send(" 6379")
	r.send("\r") // 守衛攔下
	r.send("zz")
	r.send("z\r") // 阻斷器應看到完整的 zzz 而命中
	r.settle(t)
	assertNoConnectExecuted(t, r)
	for _, l := range r.executedExcludingSettle() {
		if l == "zzz" {
			t.Fatalf("zzz 應被指令阻斷器攔下（守衛攔截後阻斷器的行緩衝未清）；執行過 %q", r.executedExcludingSettle())
		}
	}
	rcWaitFor(t, "兩則警告都送達", func() bool { return len(r.log.noticeCodes()) >= 2 })
	codes := r.log.noticeCodes()
	if codes[0] != string(apierror.CodeDBReconnectBlocked) || codes[1] != string(apierror.CodeCommandBlocked) {
		t.Fatalf("警告碼 = %v", codes)
	}
}

// ── fail-close ────────────────────────────────────────────────────────

// TestReconnectClearFailureTerminatesSession 攔下後清行失敗即終止會話（與指令阻斷同一條 fail-close）。
func TestReconnectClearFailureTerminatesSession(t *testing.T) {
	r := newReconnectRig(t, "redis", "human", rigOpts{clearErr: errors.New("pty gone")})
	r.send("connect 203.0.113.5 6379\r")
	rcWaitFor(t, "會話被終止", func() bool { return r.b.EndReason() == endReasonBlockClearFailed })
	for _, l := range r.cli.executedLines() {
		if strings.Contains(l, "connect") {
			t.Fatalf("子程序 stdin 收到該行並執行：%q", l)
		}
	}
}
