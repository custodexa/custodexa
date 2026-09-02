package sshproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/testgate"
)

// 對真實目標端跑一整場 WebSocket 會話。
//
// # 為什麼這些條目非活會話不可
//
// 轉錄落檔、監看同步、閒置與斷線的收尾順序，全都發生在「兌換 → 撥號 → 註冊 →
// 訊息迴圈 → 收尾」這條完整鏈路上。以組好的 `consoleSession` 直接呼叫函式證明得了
// 判定邏輯，證明不了那條鏈路本身接得對——錄影 tap 有沒有掛上、會話結束時關閉的
// 順序對不對、目標端真的斷線時我方走的是哪一條分支。
//
// gating：座標未設即 skip；`REQUIRE_INTEGRATION=1` 時 skip 轉 fail。
//
// 跑法（compose 內，靶機須先 up）：
//
//	docker compose exec -T backend sh -c '
//	  TEST_DBCONSOLE_MYSQL="mysql-test|3306|root|testpass123|testdb" \
//	  TEST_DBCONSOLE_POSTGRES="postgres|5432|postgres|postgres|postgres" \
//	  go test ./internal/sshproxy -run LiveConsole -v'

// consoleTarget 五段式座標拆出來的欄位（刻意不是連線字串：
// 主控台路徑的紀律是逐欄位組裝，測試的入口收字串就會有人把它直接餵進 driver）
type consoleTarget struct {
	host     string
	port     int
	user     string
	password string
	database string
}

func consoleTargetOf(t *testing.T, env string) consoleTarget {
	t.Helper()
	parts := strings.Split(testgate.Value(t, env), "|")
	if len(parts) != 5 {
		t.Fatalf("%s 的值需為 host|port|user|password|database 五段，實得 %d 段", env, len(parts))
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("%s 的埠 %q 非數字: %v", env, parts[1], err)
	}
	return consoleTarget{host: parts[0], port: port, user: parts[2],
		password: parts[3], database: parts[4]}
}

// liveConsole 一套指向真實目標端的完整鋪陳
type liveConsole struct {
	env       *consoleEnv
	srv       *httptest.Server
	recordDir string
	target    consoleTarget
}

// newLiveConsole 建鋪陳：資產指向真實靶機、帳號密碼以與生產同源的欄位加密方式落庫、
// 路由掛在 httptest 伺服器上（WebSocket 升級需要真的連線，httptest.NewRecorder 不行）
func newLiveConsole(t *testing.T, protocol, envVar string) *liveConsole {
	t.Helper()
	target := consoleTargetOf(t, envVar)
	env := setupConsoleEnv(t, protocol)

	if err := env.db.Model(&model.Asset{}).Where("id = ?", 1).Updates(map[string]any{
		"host": target.host, "port": target.port, "db_name": target.database,
	}).Error; err != nil {
		t.Fatalf("指向靶機失敗: %v", err)
	}
	enc, err := aesColumnCodec(t, make([]byte, 32)).
		EncryptFor(context.Background(), keyvault.RefAccountPassword, target.password)
	if err != nil {
		t.Fatalf("加密帳號密碼失敗: %v", err)
	}
	if err := env.db.Exec(
		`INSERT INTO asset_accounts (asset_id, username, password_enc, is_default, auth_method, created_at, updated_at)
		 VALUES (1, ?, ?, 1, 'sql', ?, ?)`,
		target.user, enc, time.Now(), time.Now()).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	// 比對器缺席在主控台是 fail-close（語句一律不執行），故活會話測試必須有一個。
	// 規則表為空即「沒有任何 block 規則」，比對照跑但不命中——**規則要載得起來**，
	// 載不起來與「沒有規則」是兩件事，前者一樣 fail-close
	matcher := audit.InitAlertMatcher(env.db, nil)
	if err := matcher.LoadRules(); err != nil {
		t.Fatalf("載入規則快取失敗: %v", err)
	}
	t.Cleanup(func() { audit.InitAlertMatcher(nil, nil) })

	// 資產停用收線走 SessionService → 連線註冊表 → 會話的收線回呼
	env.h.SessionService = session.NewSessionService(env.h.Registry)

	recordDir := t.TempDir()
	env.h.RecordingPath = recordDir

	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(env.h.AuditService))
	r.GET("/api/v1/db-console", env.h.HandleDBConsole)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	// 會話收尾的最後一步是寫會話列，而它跑在被劫持的連線上——httptest 的關閉
	// 不等這種連線。不等它跑完就把測試用的資料庫換掉，收尾會打在一個已經消失的
	// 連線上；那不是產品缺陷，是拆場拆得太早
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for env.h.Registry.Count() > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
	})

	return &liveConsole{env: env, srv: srv, recordDir: recordDir, target: target}
}

// dial 兌換一張票並連上主控台
func (l *liveConsole) dial(t *testing.T) *consoleClient {
	t.Helper()
	tok := l.env.issueTicket(t)
	url := "ws" + strings.TrimPrefix(l.srv.URL, "http") + "/api/v1/db-console?connect_token=" + tok
	ws, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		body := ""
		if resp != nil {
			body = resp.Status
		}
		t.Fatalf("主控台連線失敗: %v (%s)", err, body)
	}
	c := &consoleClient{t: t, ws: ws}
	t.Cleanup(func() { _ = ws.Close() })
	return c
}

// consoleClient 測試用客戶端：只送訊息、只讀訊息，不重試也不緩衝
type consoleClient struct {
	t  *testing.T
	ws *websocket.Conn
}

func (c *consoleClient) send(v any) {
	c.t.Helper()
	if err := c.ws.WriteJSON(v); err != nil {
		c.t.Fatalf("送出訊息失敗: %v", err)
	}
}

// await 讀到第一則滿足述詞的訊息（其餘丟棄）
func (c *consoleClient) await(what string, pred func(map[string]any) bool) map[string]any {
	c.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := c.ws.SetReadDeadline(deadline); err != nil {
			c.t.Fatalf("設定讀取期限失敗: %v", err)
		}
		var m map[string]any
		if err := c.ws.ReadJSON(&m); err != nil {
			c.t.Fatalf("等 %s 時讀取中斷: %v", what, err)
		}
		if pred(m) {
			return m
		}
	}
}

func (c *consoleClient) awaitType(msgType string) map[string]any {
	c.t.Helper()
	return c.await(msgType, func(m map[string]any) bool { return m["type"] == msgType })
}

// awaitReady 等就緒（伺服端於收到首則訊息或寬限到期後送出）
func (c *consoleClient) awaitReady() map[string]any {
	c.t.Helper()
	c.send(map[string]any{"type": consoleMsgHello})
	return c.awaitType(consoleMsgReady)
}

// runQuery 送一次語句並等回它的結果或錯誤
func (c *consoleClient) runQuery(sql string) map[string]any {
	c.t.Helper()
	c.send(map[string]any{"type": consoleMsgQuery, "sql": sql})
	return c.await("結果", func(m map[string]any) bool {
		return m["type"] == consoleMsgResult || m["type"] == consoleMsgError
	})
}

// waitSessionGone 等會話的收尾流程跑完。
//
// 判準取「會話列已離開 active」而不是「活躍會話表已刪除」：後者發生在收尾的中段，
// 而寫會話列（結束原因就在那裡）是最後一步——以中段為判準就會在讀 end_reason 時
// 讀到還沒寫上去的值，而那種失敗只會偶發
func (l *liveConsole) waitSessionGone(t *testing.T, id uint) {
	t.Helper()
	waitFor(t, 30*time.Second, "會話收尾完成", func() bool {
		if _, ok := l.env.h.consoleSessionsRef().Load(id); ok {
			return false
		}
		var status string
		l.env.db.Model(&model.Session{}).Select("status").
			Where("id = ?", id).Scan(&status)
		return status != "" && status != string(model.SessionStatusActive)
	})
}

// transcriptOf 讀出會話的 `.cast` 並還原成純文字轉錄。
//
// 順帶驗了它是一份合法的 asciicast v2：首行是含版本與尺寸的標頭物件，
// 其後每行是 `[時間, "o", 資料]` 三元組——回放器認的就是這個形狀
func (l *liveConsole) transcriptOf(t *testing.T, sessionID uint) string {
	t.Helper()
	var path string
	want := fmt.Sprintf("session-%d.cast", sessionID)
	err := filepath.WalkDir(l.recordDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == want {
			path = p
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走訪錄影目錄失敗: %v", err)
	}
	if path == "" {
		t.Fatalf("錄影檔未落地（目錄 %s 下找不到 %s）", l.recordDir, want)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀錄影檔失敗: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("錄影檔只有 %d 行，沒有任何事件", len(lines))
	}
	var header struct {
		Version int `json:"version"`
		Width   int `json:"width"`
		Height  int `json:"height"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("錄影檔標頭不是 JSON：%v（%s）", err, lines[0])
	}
	if header.Version != 2 {
		t.Errorf("asciicast 版本 = %d，回放器認的是 2", header.Version)
	}
	if header.Width != consoleTranscriptCols || header.Height != consoleTranscriptRows {
		t.Errorf("錄影尺寸 = %dx%d，期望 %dx%d",
			header.Width, header.Height, consoleTranscriptCols, consoleTranscriptRows)
	}
	var text strings.Builder
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev []any
		if err := json.Unmarshal([]byte(line), &ev); err != nil || len(ev) != 3 {
			t.Fatalf("錄影事件行不是三元組：%q", line)
		}
		if ev[1] != "o" {
			continue
		}
		data, ok := ev[2].(string)
		if !ok {
			t.Fatalf("錄影事件的資料不是字串：%q", line)
		}
		text.WriteString(data)
	}
	return text.String()
}

// TestLiveConsoleTranscriptRecording 一場真實會話的轉錄落檔。
//
// **不含結果資料列**是這裡最要緊的一條：轉錄的體積沒有上界，而結果資料含敏感內容
// 且本產品沒有遮罩。標記字串刻意只出現在結果裡、不出現在語句原文中——
// 否則「錄影裡搜得到它」就分不出是語句被記下來還是資料被記下來
func TestLiveConsoleTranscriptRecording(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		env      string
		// leakSQL 結果含標記但原文不含標記的語句
		leakSQL string
	}{
		{"mysql", "mysql", testgate.EnvDBConsoleMySQL,
			`SELECT CONCAT('CUSTODEXA', '_LEAK_', 'MARKER') AS m`},
		{"postgres", "postgres", testgate.EnvDBConsolePostgres,
			`SELECT 'CUSTODEXA' || '_LEAK_' || 'MARKER' AS m`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLiveConsole(t, tc.protocol, tc.env)
			c := l.dial(t)
			ready := c.awaitReady()
			sessionID := uint(ready["session_id"].(float64))

			res := c.runQuery(tc.leakSQL)
			if res["type"] != consoleMsgResult || res["status"] != model.ResultStatusOK {
				t.Fatalf("查詢未成功：%v", res)
			}
			okEvent := res["event_id"].(string)
			// 標記真的在結果裡，「錄影搜不到它」才是一句有內容的話——
			// 否則這個斷言只是在證明一個從未出現過的字串沒有出現
			if raw, _ := json.Marshal(res["sets"]); !strings.Contains(string(raw), "CUSTODEXA_LEAK_MARKER") {
				t.Fatalf("結果集裡沒有標記，本測試的缺席斷言會落空：%s", raw)
			}

			bad := c.runQuery("SELECT * FROM this_table_does_not_exist_xyz")
			badEvent, _ := bad["event_id"].(string)
			if badEvent == "" {
				t.Fatalf("錯誤回應沒有事件識別：%v", bad)
			}

			_ = c.ws.Close()
			l.waitSessionGone(t, sessionID)

			text := l.transcriptOf(t, sessionID)
			if strings.Contains(text, "CUSTODEXA_LEAK_MARKER") {
				t.Errorf("轉錄含結果資料列：\n%s", text)
			}
			for _, want := range []string{
				"] " + okEvent + "> " + tc.leakSQL,
				"-- " + okEvent + " ok:",
				"] " + badEvent + "> SELECT * FROM this_table_does_not_exist_xyz",
				"-- " + badEvent + " error ",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("轉錄缺行 %q：\n%s", want, text)
				}
			}
			// 每一行都要能對回一個事件，或是會話層級的三種行之一
			for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				if strings.Contains(line, okEvent) || strings.Contains(line, badEvent) {
					continue
				}
				if strings.HasPrefix(line, "-- switched database:") ||
					strings.HasPrefix(line, "-- switch failed:") ||
					strings.HasPrefix(line, "-- connection closed:") {
					continue
				}
				t.Errorf("轉錄行既無事件識別也不是會話層級行：%q", line)
			}

			// 轉錄與審計列以事件識別逐行對應（列是唯一真相，轉錄是派生的閱讀面）
			facts, ok := l.env.commandFactsOf(t, okEvent)
			if !ok {
				t.Fatalf("查不到事件 %s 的語句列", okEvent)
			}
			if facts.Status != model.ResultStatusOK {
				t.Errorf("語句列狀態 = %q", facts.Status)
			}
			if facts.TargetDatabase == "" {
				t.Errorf("語句列未記目標庫")
			}
			if facts.TxStateAfter == "" {
				t.Errorf("語句列的交易態為空——空字串在這個欄位上的語義是「命令列的列」")
			}
			errFacts, ok := l.env.commandFactsOf(t, badEvent)
			if !ok {
				t.Fatalf("查不到事件 %s 的語句列", badEvent)
			}
			if errFacts.Status != model.ResultStatusError || errFacts.ErrorCode == "" {
				t.Errorf("失敗列 = %+v，期望 error 狀態且帶目標端錯誤碼", errFacts)
			}
		})
	}
}

// TestLiveConsoleTranscriptTruncatesTargetError 目標端的超長錯誤訊息於轉錄截斷。
//
// PostgreSQL 的型別轉換錯誤會把整個輸入值放進訊息裡，那正是「錯誤文本可能夾帶
// 資料片段」的實例——轉錄長期保存，故截斷；即時回給語句作者的不截斷
func TestLiveConsoleTranscriptTruncatesTargetError(t *testing.T) {
	l := newLiveConsole(t, "postgres", testgate.EnvDBConsolePostgres)
	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))

	long := strings.Repeat("9", consoleTranscriptMaxMessage+400)
	res := c.runQuery(fmt.Sprintf("SELECT CAST('%sx' AS INTEGER)", long))
	if res["type"] != consoleMsgResult && res["type"] != consoleMsgError {
		t.Fatalf("未收到結果：%v", res)
	}
	eventID, _ := res["event_id"].(string)
	if eventID == "" {
		t.Fatalf("回應沒有事件識別：%v", res)
	}
	// 即時回應不截斷：作者在目標端本來就看得到完整訊息
	if dbErr, ok := res["db_error"].(map[string]any); ok {
		if msg, _ := dbErr["message"].(string); len([]rune(msg)) <= consoleTranscriptMaxMessage {
			t.Fatalf("目標端訊息只有 %d 字元，測不到截斷（訊息=%q）", len([]rune(msg)), msg)
		}
	} else {
		t.Fatalf("錯誤回應未帶 db_error：%v", res)
	}

	_ = c.ws.Close()
	l.waitSessionGone(t, sessionID)

	text := l.transcriptOf(t, sessionID)
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(line, "-- "+eventID+" error ") {
			continue
		}
		body := strings.SplitN(line, ": ", 2)[1]
		if !strings.HasSuffix(body, "…") {
			t.Errorf("轉錄的錯誤行未截斷：%q", body)
		}
		if got := len([]rune(strings.TrimSuffix(body, "…"))); got != consoleTranscriptMaxMessage {
			t.Errorf("轉錄訊息 %d 字元，期望 %d", got, consoleTranscriptMaxMessage)
		}
		return
	}
	t.Fatalf("轉錄沒有該事件的錯誤行：\n%s", text)
}

// TestLiveConsoleMonitorSeesTranscript 監看端看到的就是回放會看到的。
//
// 錄影 tap 與監看 tap 由同一批位元組餵入——這條若斷了，監看畫面與事後回放
// 會是兩份不同的敘述，而沒有任何東西會報錯
func TestLiveConsoleMonitorSeesTranscript(t *testing.T) {
	l := newLiveConsole(t, "mysql", testgate.EnvDBConsoleMySQL)
	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))

	// 觀察者走與生產同一個 hub 入口（角色閘在 HandleMonitor，此處驗的是 room 這一段）
	obsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if !l.env.h.Monitor.Join(sessionID, ws, ObserverContext{UserID: 2}) {
			ws.Close()
		}
	}))
	defer obsSrv.Close()
	obs, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(obsSrv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("監看連線失敗: %v", err)
	}
	defer obs.Close()

	res := c.runQuery("SELECT 1 AS monitored")
	eventID := res["event_id"].(string)

	seen := ""
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(seen, eventID) {
		if err := obs.SetReadDeadline(deadline); err != nil {
			t.Fatalf("設定監看讀取期限失敗: %v", err)
		}
		var m Message
		if err := obs.ReadJSON(&m); err != nil {
			t.Fatalf("監看端讀取中斷（已收到 %q）: %v", seen, err)
		}
		if m.Type == MsgData {
			seen += m.Data
		}
	}
	if strings.Contains(seen, "monitored\t") {
		t.Errorf("監看端收到了結果資料：%q", seen)
	}
	if !strings.Contains(seen, "SELECT 1 AS monitored") {
		t.Errorf("監看端沒收到語句行：%q", seen)
	}
}

// TestLiveConsoleRecordingUnwritableStillOpens 錄影目錄不可寫時會話仍成立。
//
// 錄影 fail-close 掛在簽發點，不在這裡：連線已經建立、憑證已經解封，
// 此時斷線只是把一場已發生的存取變成一場沒有紀錄的存取。但**不得沉默**——
// 會話列標記失敗原因，並留一筆審計
func TestLiveConsoleRecordingUnwritableStillOpens(t *testing.T) {
	l := newLiveConsole(t, "mysql", testgate.EnvDBConsoleMySQL)
	// 錄影根指向一個「檔案」：連 root 也建不出它底下的日期目錄
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
		t.Fatalf("建阻擋檔失敗: %v", err)
	}
	l.env.h.RecordingPath = blocked

	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))

	res := c.runQuery("SELECT 1")
	if res["type"] != consoleMsgResult {
		t.Fatalf("錄影失敗不該影響執行：%v", res)
	}

	var row model.Session
	if err := l.env.db.First(&row, sessionID).Error; err != nil {
		t.Fatalf("查會話列: %v", err)
	}
	if row.RecordingError == "" {
		t.Errorf("錄影啟動失敗卻未在會話列留下原因")
	}
	found := false
	for _, a := range l.env.auditRows(t) {
		if a.Action == model.ActionRecordingFailed && a.Status == model.StatusFailure {
			found = true
		}
	}
	if !found {
		t.Errorf("錄影啟動失敗未留審計")
	}
}

// TestLiveConsoleSessionRecordFailClose 會話記錄寫不進去就不連。
//
// 無 session 主鍵即無註冊表、無錄影、無語句審計、無監看——那是一條完全沒有
// 紀錄的連線，admin 亦不豁免
func TestLiveConsoleSessionRecordFailClose(t *testing.T) {
	l := newLiveConsole(t, "mysql", testgate.EnvDBConsoleMySQL)
	// 注入點：會話表消失即 INSERT 必敗，而撥號已經成功——
	// 走到的正是「連線建立之後、會話列寫入失敗」那個窗口
	if err := l.env.db.Exec("DROP TABLE sessions").Error; err != nil {
		t.Fatalf("移除會話表失敗: %v", err)
	}

	tok := l.env.issueTicket(t)
	resp, err := http.Get(l.srv.URL + "/api/v1/db-console?connect_token=" + tok)
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols || resp.StatusCode == http.StatusOK {
		t.Fatalf("會話記錄失敗卻放行了連線（狀態碼 %d）", resp.StatusCode)
	}
	if u, total := l.env.h.consoleAdmission().counts(1); u != 0 || total != 0 {
		t.Errorf("拒連後名額未釋放：%d/%d", u, total)
	}
}

// TestLiveConsoleTargetClosedEndsSession 目標端踢線即結束會話且不重撥。
//
// MySQL 的 `KILL CONNECTION` 打在自己的連線上，是最貼近「目標端把我們踢掉」
// 的真實形狀。**該單位的結論是「不知道」**：已經送出而目標端沒回報完成
func TestLiveConsoleTargetClosedEndsSession(t *testing.T) {
	l := newLiveConsole(t, "mysql", testgate.EnvDBConsoleMySQL)
	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))

	// 目標端把自己的連線踢掉。踢線本身可能先回一個成功的結果（伺服器在關閉之前
	// 回了 OK），真正的斷線要到下一次往返才浮出——那正是本測試要走的那條路：
	// 連線池不得為此另開一條連線（一次性 connector 把重撥堵死）
	c.send(map[string]any{"type": consoleMsgQuery, "sql": "KILL CONNECTION CONNECTION_ID()"})
	first := c.await("踢線回應", func(m map[string]any) bool {
		return m["type"] == consoleMsgResult || m["type"] == consoleMsgError ||
			m["type"] == consoleMsgClosed
	})
	if first["type"] != consoleMsgClosed {
		c.send(map[string]any{"type": consoleMsgQuery, "sql": "SELECT 1"})
	}
	closed := c.await("連線關閉", func(m map[string]any) bool { return m["type"] == consoleMsgClosed })
	if closed["reason"] != consoleClosedTargetClosed {
		t.Fatalf("closed.reason = %v，期望 %s", closed["reason"], consoleClosedTargetClosed)
	}
	l.waitSessionGone(t, sessionID)

	var row model.Session
	if err := l.env.db.First(&row, sessionID).Error; err != nil {
		t.Fatalf("查會話列: %v", err)
	}
	if row.EndReason != model.EndReasonTargetClosed {
		t.Errorf("會話列 end_reason = %q，期望 %q", row.EndReason, model.EndReasonTargetClosed)
	}
	// 起始連線只留一筆撥號；重撥會是第二筆會話列或第二筆連線審計
	var sessions int64
	l.env.db.Model(&model.Session{}).Count(&sessions)
	if sessions != 1 {
		t.Errorf("會話列 %d 筆——目標端關閉後不得重建連線", sessions)
	}
	found := false
	for _, a := range l.env.auditRows(t) {
		if strings.Contains(a.RequestBody, consoleKindConnectionClose) &&
			strings.Contains(a.RequestBody, consoleClosedTargetClosed) {
			found = true
		}
	}
	if !found {
		t.Errorf("目標端關閉未留痕")
	}
}

// TestLiveConsoleAssetDisabledTerminates 資產停用即收線（走真實會話的註冊表回呼）
func TestLiveConsoleAssetDisabledTerminates(t *testing.T) {
	l := newLiveConsole(t, "mysql", testgate.EnvDBConsoleMySQL)
	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))

	n, err := l.env.h.SessionService.TerminateByAsset(1, model.EndReasonAssetDisabled)
	if err != nil || n != 1 {
		t.Fatalf("資產停用收線失敗: n=%d err=%v", n, err)
	}
	closed := c.await("收線", func(m map[string]any) bool { return m["type"] == consoleMsgClosed })
	if closed["reason"] != consoleClosedTerminated {
		t.Errorf("closed.reason = %v", closed["reason"])
	}
	l.waitSessionGone(t, sessionID)

	var row model.Session
	if err := l.env.db.First(&row, sessionID).Error; err != nil {
		t.Fatalf("查會話列: %v", err)
	}
	if row.EndReason != model.EndReasonAssetDisabled {
		t.Errorf("end_reason = %q，期望 %q", row.EndReason, model.EndReasonAssetDisabled)
	}
}

// TestLiveConsolePGSwitchSucceeds PostgreSQL 的切庫在協議契約下走得通。
//
// 切庫要換一條連線，而換連線要重跑閘序。閘序取哪一份是有後果的：終端那一份
// 含一道解析 PTY 尺寸的請求形狀閘，而主控台的協議裡沒有尺寸——沿用它，
// 每一次切庫都會被一個客戶端不可能帶的參數擋下，而畫面上看起來像授權失敗。
//
// 授權完好的成功路徑必須自己有一支測試：只驗「撤銷授權後被拒」的話，
// 無條件先拒也會讓那支測試通過。
func TestLiveConsolePGSwitchSucceeds(t *testing.T) {
	l := newLiveConsole(t, "postgres", testgate.EnvDBConsolePostgres)
	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))
	before := ready["database"].(string)
	const target = "template1"
	if before == target {
		t.Fatalf("靶機的起始庫就是 %s，切庫測不出東西", target)
	}
	beforePID := singleValueOf(t, c.runQuery("SELECT pg_backend_pid() AS pid"))

	c.send(map[string]any{"type": consoleMsgSwitch, "database": target})
	msg := c.await("切庫回應", func(m map[string]any) bool {
		return m["type"] == consoleMsgError || m["type"] == consoleMsgNotice
	})
	if msg["type"] != consoleMsgNotice || msg["code"] != consoleNoticeDatabaseSwitched {
		t.Fatalf("切庫未成功：%v", msg)
	}

	if got := singleValueOf(t, c.runQuery("SELECT current_database() AS db")); got != target {
		t.Errorf("切庫後當前庫 = %q，期望 %q", got, target)
	}
	if afterPID := singleValueOf(t, c.runQuery("SELECT pg_backend_pid() AS pid")); afterPID == beforePID {
		t.Errorf("目標端後端行程未變（%s）——切庫沒有換成新連線", afterPID)
	}

	// 切庫後的每一列都要指得出新的目標庫，否則稽核讀不出語句打在哪裡
	var targets []string
	if err := l.env.db.Model(&model.SessionCommand{}).Where("session_id = ?", sessionID).
		Order("seq asc").Pluck("target_database", &targets).Error; err != nil {
		t.Fatalf("查語句紀錄: %v", err)
	}
	if len(targets) == 0 || targets[len(targets)-1] != target {
		t.Errorf("最後一列的目標庫 = %v，期望 %q", targets, target)
	}

	switched := false
	for _, a := range l.env.auditRows(t) {
		if strings.Contains(a.RequestBody, consoleKindSwitch) && a.Status == model.StatusSuccess {
			switched = true
		}
	}
	if !switched {
		t.Errorf("切庫成功未留痕")
	}
	_ = c.ws.Close()
	l.waitSessionGone(t, sessionID)
}

// singleValueOf 取單列單欄結果的值
func singleValueOf(t *testing.T, res map[string]any) string {
	t.Helper()
	sets, ok := res["sets"].([]any)
	if !ok || len(sets) == 0 {
		t.Fatalf("結果沒有結果集：%v", res)
	}
	rows, ok := sets[0].(map[string]any)["rows"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("結果集沒有列：%v", res)
	}
	v, ok := rows[0].([]any)[0].(string)
	if !ok {
		t.Fatalf("第一欄不是文字：%v", res)
	}
	return v
}

// TestLiveConsolePGSwitchRerunsGates PostgreSQL 的切庫要重跑整段閘序。
//
// 切庫就是換一條連線；不重跑等於用一張已經兌換過的票再開一條，
// 而授權在這段期間可能已經被撤銷。**被拒時會話維持原庫**——
// 使用者的既有結果不該因為一次被拒的切換而消失
func TestLiveConsolePGSwitchRerunsGates(t *testing.T) {
	l := newLiveConsole(t, "postgres", testgate.EnvDBConsolePostgres)
	c := l.dial(t)
	ready := c.awaitReady()
	sessionID := uint(ready["session_id"].(float64))
	before := ready["database"].(string)

	// 會話期間撤銷授權：下一次切庫必須在閘序被擋下
	if err := l.env.db.Exec("DELETE FROM asset_authorizations").Error; err != nil {
		t.Fatalf("撤銷授權失敗: %v", err)
	}

	c.send(map[string]any{"type": consoleMsgSwitch, "database": "template1"})
	msg := c.await("切庫回應", func(m map[string]any) bool {
		return m["type"] == consoleMsgError || m["type"] == consoleMsgNotice
	})
	if msg["type"] != consoleMsgError {
		t.Fatalf("授權撤銷後切庫仍成功：%v", msg)
	}

	res := c.runQuery("SELECT current_database() AS db")
	sets := res["sets"].([]any)
	if len(sets) == 0 {
		t.Fatalf("查當前庫沒有結果：%v", res)
	}
	rows := sets[0].(map[string]any)["rows"].([]any)
	got := rows[0].([]any)[0].(string)
	if got != before {
		t.Errorf("切庫被拒後當前庫變成 %q，期望維持 %q", got, before)
	}

	denied := false
	for _, a := range l.env.auditRows(t) {
		if strings.Contains(a.RequestBody, consoleKindSwitch) && a.Status == model.StatusDenied {
			denied = true
		}
	}
	if !denied {
		t.Errorf("切庫被拒未留痕")
	}
	_ = c.ws.Close()
	l.waitSessionGone(t, sessionID)
}
