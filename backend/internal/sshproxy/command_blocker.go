package sshproxy

import (
	"context"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// blockMatcher 阻斷規則查詢介面（測試注入）
type blockMatcher interface {
	MatchBlock(command, protocol string) (*model.AlertRule, bool)
}

// commandBlocker 指令阻斷器（command-blocking 輪 B）：
// 行緩衝 Enter 提交且可信時查 block 規則；命中即指示 bridge 不轉發。
// 阻斷事件照常入告警庫（嚴重度沿規則）、推通知並離機轉發
type commandBlocker struct {
	buf     *InputLineBuffer
	matcher blockMatcher
	// alerts 告警落地面：取代原本的 *gorm.DB 直寫。
	// 型別是介面而非 *gorm.DB 正是修法本體——本型別自此沒有「自己寫一列」的能力，
	// 入庫、通知與 syslog tee 三件事一起發生或一起不發生
	alerts    gatewayapi.AlertSink
	sessionID uint
	userID    uint
	assetID   uint
	protocol  string // 依會話協議分流 block 規則（shell/SQL 不互掃）
}

// newCommandBlocker 建立阻斷器；matcher 為 nil（未初始化）時回 nil＝直通。
//
// **alerts 為 nil 時不回 nil**（＝不因為告警接線缺失而關掉阻斷）：阻斷是安全控制，
// 告警是它的紀錄；缺紀錄不該連控制一起失效。未注入的後果由兩道閘承擔——
// 組裝根 requireAlertSink 使啟動失敗，呼叫側 gatewayapi.RecordAlert 回
// ErrAlertSinkMissing 使其可觀測（見 recordBlocked），SHALL NOT 靜默 no-op。
func newCommandBlocker(matcher blockMatcher, alerts gatewayapi.AlertSink, sessionID, userID, assetID uint, protocol string) *commandBlocker {
	if matcher == nil {
		return nil
	}
	return &commandBlocker{
		buf:       NewInputLineBuffer(),
		matcher:   matcher,
		alerts:    alerts,
		sessionID: sessionID,
		userID:    userID,
		assetID:   assetID,
		protocol:  protocol,
	}
}

// Inspect 檢視一段輸入：命中 block 規則時回傳規則，未命中回 nil；
// 緩衝失準（ESC 後）fail-open。
//
// 不再回傳注入用警告字串——警告改由 bridge 送 MsgNotice 控制幀
// （Code＋zh fallback＋params{rule}），文案與 ANSI 上色歸前端。
func (c *commandBlocker) Inspect(data []byte) *model.AlertRule {
	line, submitted, trusted := c.buf.Feed(data)
	if !submitted || !trusted || line == "" {
		return nil
	}
	rule, ok := c.matcher.MatchBlock(line, c.protocol)
	if !ok {
		return nil
	}

	c.recordBlocked(rule, line)
	return rule
}

// recordBlocked 阻斷事件經告警落地面入庫＋推送通知＋離機 syslog 轉發。
//
// # 為何離機轉發收在這個落地面
//
// 收口前本函式 `db.Create(&alert)` 後只 Enqueue 到 AlertNotifier，**不呼叫
// SyslogForwarder.EnqueueAlert**——而 EnqueueAlert 當時全庫唯一呼叫點在
// alert_matcher.go 的比對路徑。結果是「實際被阻斷的危險指令」這一類價值最高的
// 安全證據**恰好只存在本機一份**，而離機轉發的存在理由正是「本機資料庫可能被
// 竄改或清除」。改走 AlertSink 後入庫→通知→tee 三件事收在同一個落地面，
// 不再可能只做前兩件。
//
// **錯誤處置維持「只記 log 不阻斷」**：告警寫入失敗時指令**已經**被擋下，
// 沒有可回滾的業務交易；把它升級為中斷會話會讓告警系統故障變成使用者被踢線。
// 未注入（ErrAlertSinkMissing）與寫入失敗落在同一格，兩者都會留下 log。
func (c *commandBlocker) recordBlocked(rule *model.AlertRule, command string) {
	// payload 衛生：RuleName 存規則原名（原為 name+"（已阻斷）"，把 UI 文案
	// 混進機器欄，害通知與列表無法在非中文語系正確呈現）；阻斷事實改由
	// Blocked 布林欄承載
	ruleID := rule.ID
	alert := gatewayapi.CommandAlert{
		// 阻斷仍是規則類：它由一條可 CRUD 的規則觸發，rule_id 指得出來
		Kind:     model.AlertKindRule,
		RuleID:   &ruleID,
		RuleName: rule.Name,
		Level:    rule.Severity,
		Command:  command,
		// 阻斷在送往目標前發生，無 ExecutedAt 可用（matcher 路徑取 cmd.ExecutedAt），
		// 取阻斷當下時刻；既有零值行為是漏填而非語義
		OccurredAt: time.Now(),
		SessionID:  c.sessionID,
		Actor:      gatewayapi.Actor{UserID: c.userID},
		AssetID:    c.assetRef(),
		// 與 matcher 路徑統一。收口前本路徑未設此欄（DB 收到空字串），
		// matcher 路徑寫 pending——同一張表兩種處置值。
		//
		// **這是欄位一致性補齊，不是修正已知的消費端差異**：
		// 現況無任何消費者依賴本欄判定未審閱——`command_alert_service.go` 的
		// Unreviewed 篩選、`daily_review_service.go` 的 PCI 10.4.1 未審閱計數、
		// `Alerts.vue` 的三個呈現函式一律走 `reviewed_at IS NULL`，故收口前的阻斷告警
		// **本來就出現在未審閱清單裡**。統一的價值在防未來：兩種值並存之下，
		// 任何人寫 `WHERE disposition = 'pending'` 都會靜默漏掉整類阻斷告警
		//（歷史列無 backfill，仍為空字串）。
		Disposition: model.AlertDispositionPending,
		Blocked:     true,
	}
	// ctx 取 Background：本函式在 bridge 的輸入泵上同步呼叫，沒有請求級 ctx 可承接；
	// 硬綁會話 ctx 會讓「會話正在結束」變成「最後一筆阻斷告警寫不進去」
	if err := gatewayapi.RecordAlert(context.Background(), c.alerts, alert); err != nil {
		log.Printf("[CommandBlocker] 阻斷告警落地失敗（指令已阻斷，紀錄未留存）: %v", err)
	}
}

// assetRef 資產外鍵的可空形態。
//
// command_alerts.asset_id 在 DB 為 nullable（手動連線可能無資產，與 session_commands
// 一致）。以值型 uint 承載會把「無資產」寫成 0，而 0 不是任何一筆資產的 ID，
// 卻在查詢與 JOIN 上看起來像個值。
func (c *commandBlocker) assetRef() *uint {
	if c.assetID == 0 {
		return nil
	}
	id := c.assetID
	return &id
}
