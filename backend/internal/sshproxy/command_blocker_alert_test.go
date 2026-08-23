package sshproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ---------------------------------------------------------------------------
// 阻斷告警離機留痕的結果證明
//
// 本檔刻意**不驗「有沒有呼叫 EnqueueAlert」**。呼叫是手段，離機留痕才是目的；
// 驗呼叫的測試在「呼叫了但轉發器把它丟掉」「呼叫順序錯在入庫前」等形態下照樣綠。
// 這裡起一個真的 syslog 接收端（TCP，RFC6587 octet-counting），走完整條
// 阻斷 → 落地面 → 入庫 → tee 的路徑，斷言**那個行程外的接收端真的收到那一筆**。
//
// 修復前的同一條路徑在此必然轉紅：收口前 recordBlocked 只 db.Create ＋ Enqueue 通知，
// 從不呼叫 SyslogForwarder.EnqueueAlert，接收端永遠收不到 blocked 那筆。
// ---------------------------------------------------------------------------

// setupAlertDB 檔案型 sqlite（不用 :memory:——連線池會讓不同連線看到不同的庫，
// 這是本 repo 已知的「單獨跑綠、整包跑紅」來源）
func setupAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "alerts.db")
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("開啟 sqlite 失敗: %v", err)
	}
	if err := db.AutoMigrate(&model.CommandAlert{}, &model.SyslogSetting{}, &model.AlertRule{}); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	return db
}

// syslogSink 一個真的 syslog 接收端（TCP）。received 逐則交付解析後的 payload。
type syslogSink struct {
	addr     *net.TCPAddr
	received chan map[string]any
	raw      chan string
}

func startSyslogSink(t *testing.T) *syslogSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	s := &syslogSink{
		addr:     ln.Addr().(*net.TCPAddr),
		received: make(chan map[string]any, 8),
		raw:      make(chan string, 8),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					// RFC6587 octet-counting：LEN SP MSG
					lenStr, err := r.ReadString(' ')
					if err != nil {
						return
					}
					var n int
					if _, err := fmt.Sscanf(strings.TrimSpace(lenStr), "%d", &n); err != nil || n <= 0 {
						return
					}
					buf := make([]byte, n)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					msg := string(buf)
					select {
					case s.raw <- msg:
					default:
					}
					if i := strings.Index(msg, "{"); i >= 0 {
						var payload map[string]any
						if json.Unmarshal([]byte(msg[i:]), &payload) == nil {
							select {
							case s.received <- payload:
							default:
							}
						}
					}
				}
			}(conn)
		}
	}()
	return s
}

// await 等一則轉發事件；逾時即失敗（本測試的「沒收到」必須是紅，不是靜默通過）
func (s *syslogSink) await(t *testing.T, what string) map[string]any {
	t.Helper()
	select {
	case p := <-s.received:
		return p
	case <-time.After(5 * time.Second):
		t.Fatalf("等不到 %s 的 syslog 轉發（5s）：離機留痕未發生", what)
		return nil
	}
}

// expectSilence 斷言指定時間內沒有任何轉發（對照組用）
func (s *syslogSink) expectSilence(t *testing.T, d time.Duration, what string) {
	t.Helper()
	select {
	case msg := <-s.raw:
		t.Fatalf("%s 期間不應有任何轉發，卻收到: %s", what, msg)
	case <-time.After(d):
	}
}

// enableSyslog 註冊並啟動轉發器單例，指向測試接收端。
//
// **收尾必須把單例關掉**：syslogForwarderInstance 沒有對外的清除入口（既有設計），
// 故以「停用設定 → Reload → Stop」使它對後續測試無害，而不是留一個指向已關閉
// listener 的啟用中轉發器。
func enableSyslog(t *testing.T, db *gorm.DB, sink *syslogSink) *audit.SyslogForwarder {
	t.Helper()
	if err := db.Create(&model.SyslogSetting{
		ID: 1, Enabled: true, Host: "127.0.0.1", Port: sink.addr.Port,
		Protocol: model.SyslogProtocolTCP,
	}).Error; err != nil {
		t.Fatalf("寫入 syslog 設定失敗: %v", err)
	}
	f := audit.InitSyslogForwarder(db)
	f.Start()
	t.Cleanup(func() {
		db.Model(&model.SyslogSetting{}).Where("id = ?", 1).Update("enabled", false)
		f.Reload()
		f.Stop()
	})
	if !f.Enabled() {
		t.Fatal("轉發器未啟用：測試前提不成立（設定未讀到或 Host 為空）")
	}
	return f
}

// alertRow 讀取用的投影列。
//
// **不直接 Find(&model.CommandAlert{})**：該型別的 triggered_at 標 `timestamptz`
// （Postgres 的正式型別），sqlite 存成 TEXT 後掃不回 time.Time。本檔的斷言全在
// 識別與分類欄，時間欄不參與，故以投影列讀取——比為了測試去改動生產 model 的
// 欄位標籤誠實得多。
type alertRow struct {
	ID          uint
	RuleID      uint
	RuleName    string
	SessionID   uint
	UserID      uint
	AssetID     *uint
	Command     string
	Severity    string
	Disposition string
	Blocked     bool
}

func readAlertRows(t *testing.T, db *gorm.DB) []alertRow {
	t.Helper()
	var rows []alertRow
	if err := db.Table("command_alerts").Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("查詢 command_alerts 失敗: %v", err)
	}
	return rows
}

func blockRule() *model.AlertRule {
	return &model.AlertRule{
		ID:       7,
		Name:     "遞迴強制刪除",
		Pattern:  `rm\s+-(rf|fr)\b`,
		Severity: model.AlertSeverityHigh,
		Action:   "block",
		Enabled:  true,
	}
}

// TestBlockedAlertReachesSyslogDestination 離機留痕的結果證明：
// 阻斷告警寫入資料庫後，確實被轉發到行程外的 syslog 目的地。
func TestBlockedAlertReachesSyslogDestination(t *testing.T) {
	db := setupAlertDB(t)
	sink := startSyslogSink(t)
	enableSyslog(t, db, sink)

	// 對照組 1（證明接收端不是在收環境噪音）：什麼都還沒發生時應完全安靜
	sink.expectSilence(t, 300*time.Millisecond, "尚未觸發任何告警")

	rule := blockRule()
	const (
		wantSessionID = uint(42)
		wantUserID    = uint(9)
		wantAssetID   = uint(3)
	)
	b := newCommandBlocker(&alwaysBlockMatcher{rule: rule}, audit.NewAlertRecorder(db),
		wantSessionID, wantUserID, wantAssetID, string(model.ProtocolSSH))
	if b == nil {
		t.Fatal("阻斷器建立失敗：matcher 非 nil 時 SHALL 回傳可用實例")
	}

	if got := b.Inspect([]byte("rm -rf /data\r")); got == nil {
		t.Fatal("命中 block 規則卻未回傳規則：阻斷本身失效，後續斷言無意義")
	}

	// (1) 入庫：先證明業務列確實成立——否則「有沒有 tee」根本無從談起
	rows := readAlertRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("command_alerts 應有 1 列，實得 %d 列", len(rows))
	}
	row := rows[0]
	if !row.Blocked {
		t.Error("blocked 欄應為 true：這一筆正是「實際被阻斷的指令」")
	}

	// (2) 離機：接收端真的收到那一筆，且是**同一筆**（以 DB 主鍵比對，
	//     不是「收到某則 alert 就算數」）
	payload := sink.await(t, "阻斷告警")
	if got, want := fmt.Sprintf("%v", payload["id"]), fmt.Sprintf("%d", row.ID); got != want {
		t.Errorf("轉發出去的 id=%s，資料庫落地列 id=%s：轉發的不是同一筆", got, want)
	}
	if got := payload["command"]; got != "rm -rf /data" {
		t.Errorf("轉發 payload 的 command=%v，應為被阻斷的那條指令", got)
	}
	if got := payload["rule_name"]; got != rule.Name {
		t.Errorf("轉發 payload 的 rule_name=%v，應為 %q", got, rule.Name)
	}
	if got, want := fmt.Sprintf("%v", payload["session_id"]), fmt.Sprintf("%d", wantSessionID); got != want {
		t.Errorf("轉發 payload 的 session_id=%v，應為 %s", payload["session_id"], want)
	}

	// (3) 內容正確性：只綁「是不是那一筆」不夠——一個把嚴重度、
	//     行為人、資產全部寫錯的 tee 曾能完整通過本測試（實證：severity 偽造成
	//     "low"、user_id 歸零、asset_id 抹成 nil，全庫零紅）。SIEM 端據以分級、
	//     究責與關聯的正是這三欄，離機值錯＝離機證據無用。
	//
	//     斷言軸是**落地列與規則**，不是常數複寫：payload 必須同時等於 DB 落地列
	//     （證明離機的與存查的一致）且等於規則／會話的既知事實（證明兩邊不是一起錯）。
	if row.Severity != rule.Severity {
		t.Errorf("落地列 severity=%q，應沿規則的 %q：內容比對的基準本身不成立", row.Severity, rule.Severity)
	}
	if got, want := fmt.Sprintf("%v", payload["severity"]), row.Severity; got != want {
		t.Errorf("轉發 payload 的 severity=%q，落地列為 %q："+
			"離機的嚴重度與存查的不一致，SIEM 端的分級與告警門檻會據錯值判定", got, want)
	}
	if got, want := fmt.Sprintf("%v", payload["user_id"]), fmt.Sprintf("%d", row.UserID); got != want {
		t.Errorf("轉發 payload 的 user_id=%s，落地列為 %s：離機證據的行為人錯了＝無法究責", got, want)
	}
	if row.UserID != wantUserID {
		t.Errorf("落地列 user_id=%d，應為阻斷當下的 %d", row.UserID, wantUserID)
	}
	if row.AssetID == nil {
		t.Fatalf("落地列 asset_id 為 NULL，應為 %d：內容比對的基準本身不成立", wantAssetID)
	}
	if got, want := fmt.Sprintf("%v", payload["asset_id"]), fmt.Sprintf("%d", *row.AssetID); got != want {
		t.Errorf("轉發 payload 的 asset_id=%s，落地列為 %s："+
			"離機證據的目標資產錯了＝SIEM 端無法把事件關聯到受影響系統", got, want)
	}
	if *row.AssetID != wantAssetID {
		t.Errorf("落地列 asset_id=%d，應為阻斷當下的 %d", *row.AssetID, wantAssetID)
	}
	// rule_name／command 的內容正確性由上方 (2) 的既有斷言承擔（直接比對規則與指令原文），
	// 此處不重複比對——三欄（severity／user_id／asset_id）才是原本完全無人承擔的那些。
}

// TestBlockedAlertNotForwardedWhenSyslogDisabled 對照組 2：轉發停用時不外送。
//
// 沒有這一格，上一格的「收到了」有可能只是因為測試環境什麼都轉發；
// 有了它才知道那條 tee 受既有設定管制，與比對路徑同軌（而非另開一條無視設定的通道）。
func TestBlockedAlertNotForwardedWhenSyslogDisabled(t *testing.T) {
	db := setupAlertDB(t)
	sink := startSyslogSink(t)
	// 設定存在但停用
	if err := db.Create(&model.SyslogSetting{
		ID: 1, Enabled: false, Host: "127.0.0.1", Port: sink.addr.Port,
		Protocol: model.SyslogProtocolTCP,
	}).Error; err != nil {
		t.Fatalf("寫入 syslog 設定失敗: %v", err)
	}
	f := audit.InitSyslogForwarder(db)
	f.Start()
	t.Cleanup(f.Stop)

	b := newCommandBlocker(&alwaysBlockMatcher{rule: blockRule()}, audit.NewAlertRecorder(db),
		42, 9, 3, string(model.ProtocolSSH))
	if got := b.Inspect([]byte("rm -rf /data\r")); got == nil {
		t.Fatal("命中 block 規則卻未回傳規則")
	}

	var n int64
	db.Model(&model.CommandAlert{}).Count(&n)
	if n != 1 {
		t.Fatalf("阻斷告警仍應入庫（轉發停用只影響離機），實得 %d 列", n)
	}
	sink.expectSilence(t, 500*time.Millisecond, "syslog 轉發停用")
}

// TestBothAlertPathsWriteIdenticalShape 兩條路徑的告警欄位同構。
//
// 阻斷路徑（command_blocker）與比對路徑（alert_matcher）針對同一條規則各產一筆，
// 逐欄比對。收口前阻斷路徑的 disposition 為空字串、asset_id 恆為 NULL——
// 前者讓「未審閱」篩選漏掉阻斷告警，後者讓阻斷告警在資產維度上查不到。
func TestBothAlertPathsWriteIdenticalShape(t *testing.T) {
	db := setupAlertDB(t)
	recorder := audit.NewAlertRecorder(db)
	rule := blockRule()
	assetID := uint(3)

	// 阻斷路徑
	b := newCommandBlocker(&alwaysBlockMatcher{rule: rule}, recorder, 42, 9, assetID, string(model.ProtocolSSH))
	if got := b.Inspect([]byte("rm -rf /data\r")); got == nil {
		t.Fatal("命中 block 規則卻未回傳規則")
	}

	// 比對路徑（同一條規則、同一個會話／使用者／資產）
	if err := db.Create(rule).Error; err != nil {
		t.Fatalf("寫入規則失敗: %v", err)
	}
	m := audit.NewAlertMatcher(db, recorder)
	if err := m.LoadRules(); err != nil {
		t.Fatalf("載入規則快取失敗: %v", err)
	}
	m.MatchAndStore([]model.SessionCommand{{
		SessionID: 42, UserID: 9, AssetID: &assetID,
		Command: "rm -rf /data", ExecutedAt: time.Now(),
	}}, string(model.ProtocolSSH))

	rows := readAlertRows(t, db)
	if len(rows) != 2 {
		t.Fatalf("兩條路徑各應產生 1 列，實得 %d 列", len(rows))
	}
	blocked, matched := rows[0], rows[1]
	if !blocked.Blocked || matched.Blocked {
		t.Fatalf("列的順序或 blocked 欄不符預期：blocked=%v matched=%v", blocked.Blocked, matched.Blocked)
	}

	if blocked.Disposition != model.AlertDispositionPending {
		t.Errorf("阻斷告警的 disposition=%q，應為 %q（收口前為空字串。"+
			"現況的未審閱篩選走 reviewed_at IS NULL、不看本欄，故這是欄位一致性補齊而非"+
			"修正已知漏篩；兩種值並存會讓未來任何以 disposition='pending' 寫的查詢靜默漏掉整類）",
			blocked.Disposition, model.AlertDispositionPending)
	}
	if blocked.Disposition != matched.Disposition {
		t.Errorf("兩條路徑的 disposition 不一致：阻斷=%q、比對=%q", blocked.Disposition, matched.Disposition)
	}
	if blocked.AssetID == nil || *blocked.AssetID != assetID {
		t.Errorf("阻斷告警的 asset_id=%v，應為 %d（收口前恆為 NULL）", blocked.AssetID, assetID)
	}
	if matched.AssetID == nil || *blocked.AssetID != *matched.AssetID {
		t.Errorf("兩條路徑的 asset_id 不一致：阻斷=%v、比對=%v", blocked.AssetID, matched.AssetID)
	}
	if blocked.RuleName != matched.RuleName || blocked.RuleID != matched.RuleID {
		t.Errorf("規則快照欄不一致：阻斷=(%d,%q)、比對=(%d,%q)",
			blocked.RuleID, blocked.RuleName, matched.RuleID, matched.RuleName)
	}
	if blocked.UserID != matched.UserID || blocked.SessionID != matched.SessionID {
		t.Errorf("會話／使用者欄不一致：阻斷=(%d,%d)、比對=(%d,%d)",
			blocked.SessionID, blocked.UserID, matched.SessionID, matched.UserID)
	}
	if blocked.Severity != matched.Severity {
		t.Errorf("severity 不一致：阻斷=%q、比對=%q", blocked.Severity, matched.Severity)
	}
}

// TestBlockedAlertAssetIsNullWhenAbsent 資產不適用時 SHALL 為可辨識的無值，不得寫 0。
func TestBlockedAlertAssetIsNullWhenAbsent(t *testing.T) {
	db := setupAlertDB(t)
	b := newCommandBlocker(&alwaysBlockMatcher{rule: blockRule()}, audit.NewAlertRecorder(db),
		42, 9, 0 /* 無資產 */, string(model.ProtocolSSH))
	if got := b.Inspect([]byte("rm -rf /data\r")); got == nil {
		t.Fatal("命中 block 規則卻未回傳規則")
	}
	rows := readAlertRows(t, db)
	if len(rows) != 1 {
		t.Fatalf("應落地 1 列，實得 %d 列", len(rows))
	}
	row := rows[0]
	if row.AssetID != nil {
		t.Errorf("asset_id=%d，應為 NULL：0 不是任何一筆資產的 ID，"+
			"卻在查詢與 JOIN 上看起來像個值", *row.AssetID)
	}
}

// TestBlockedAlertSinkMissingIsLoudNotSilent fail-close 三件套（呼叫側）。
//
//	成功對照：注入 sink 時同一條輸入確實落地 1 列（下面第一段）
//	指定故障：sink 未注入時回的是 gatewayapi.ErrAlertSinkMissing（以 log 內容比對，
//	          它是呼叫側唯一能觀察到該哨兵的出口）
//	業務效果：告警列確實不存在，且**阻斷本身仍然生效**——告警接線缺失
//	          SHALL NOT 連帶讓安全控制失效
func TestBlockedAlertSinkMissingIsLoudNotSilent(t *testing.T) {
	// 成功對照
	db := setupAlertDB(t)
	ok := newCommandBlocker(&alwaysBlockMatcher{rule: blockRule()}, audit.NewAlertRecorder(db),
		42, 9, 3, string(model.ProtocolSSH))
	if got := ok.Inspect([]byte("rm -rf /data\r")); got == nil {
		t.Fatal("對照組：命中 block 規則卻未回傳規則")
	}
	var n int64
	db.Model(&model.CommandAlert{}).Count(&n)
	if n != 1 {
		t.Fatalf("對照組：無故障時應落地 1 列，實得 %d 列——"+
			"若此處為 0，下方「未注入時沒有列」可能本來就成立，故障格會真空通過", n)
	}

	// 指定故障：sink 未注入
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	missDB := setupAlertDB(t)
	miss := newCommandBlocker(&alwaysBlockMatcher{rule: blockRule()}, nil,
		42, 9, 3, string(model.ProtocolSSH))
	if miss == nil {
		t.Fatal("sink 未注入時 SHALL NOT 連阻斷器一起關掉：阻斷是安全控制，告警是它的紀錄")
	}
	if got := miss.Inspect([]byte("rm -rf /data\r")); got == nil {
		t.Error("sink 未注入時阻斷仍 SHALL 生效（缺紀錄不該讓控制一起失效）")
	}

	logged := buf.String()
	if !strings.Contains(logged, gatewayapi.ErrAlertSinkMissing.Error()) {
		t.Errorf("未注入 sink 時應留下 ErrAlertSinkMissing 的紀錄，實得 log：%q\n"+
			"  SHALL NOT 靜默 no-op——那正是這類缺陷「沒有任何東西變紅」的成因", logged)
	}
	missDB.Model(&model.CommandAlert{}).Count(&n)
	if n != 0 {
		t.Errorf("未注入 sink 時不該有任何列落地，實得 %d 列", n)
	}
}
