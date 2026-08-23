package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/branding"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 推送參數：
//   - queue 64：告警是低頻事件，64 足以吸收突發批次；滿載代表下游嚴重異常，
//     丟棄並記 log 優於阻塞 recorder 路徑（與 recorder 滿載丟棄同哲學）
//   - timeout 5s + 重試 3 次（1s/2s/4s 指數退避）：webhook 收端短暫抖動可自癒，
//     持續失敗則放棄——投遞不持久化追蹤（proposal non-goal）
const (
	notifyQueueSize    = 64
	notifyHTTPTimeout  = 5 * time.Second
	signatureHeaderKey = "X-OT-Signature"
)

// defaultNotifyBackoff 重試退避序列；長度即重試次數（3 次 -> 最多 4 次嘗試）
var defaultNotifyBackoff = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

// notifyPayload 推送 payload 形狀：
// 扁平三段（event/alert/session）讓收端（Slack bot、自建系統）免查庫即可呈現脈絡
type notifyPayload struct {
	Event   string            `json:"event"`
	Alert   notifyAlertBody   `json:"alert"`
	Session notifySessionBody `json:"session"`
}

type notifyAlertBody struct {
	ID       uint   `json:"id"`
	Command  string `json:"command"`
	Severity string `json:"severity"`
	RuleName string `json:"rule_name"`
	// Kind／ReasonCode 告警來源類別與機器碼。
	// **收端需要它們才分得出「規則命中」與「該輪內容無法還原」**：
	// 降級類沒有規則可指，rule_name 存的是機器碼，只讀 rule_name 的收端會把
	// 一個機器碼當成規則名。純加法，既有欄位語義不變。
	Kind       string `json:"kind"`
	ReasonCode string `json:"reason_code,omitempty"`
	// Blocked 規則是否為阻斷型：阻斷事實以布林欄承載，
	// 不再靠 RuleName 後綴散文——散文零入 webhook payload
	Blocked     bool      `json:"blocked"`
	TriggeredAt time.Time `json:"triggered_at"`
}

// notifyEventPayload 系統事件 webhook payload：
// event 機器識別字＋結構化 params，散文一律不出站。
// Degraded=true 代表 notifycat 目錄／參數契約異常，內容降級但仍投遞——
// 合規告警永不因目錄問題靜默消失
type notifyEventPayload struct {
	Event    string            `json:"event"`
	Params   map[string]string `json:"params"`
	Degraded bool              `json:"degraded,omitempty"`
	SentAt   string            `json:"sent_at"`
}

// 指令告警的 webhook event 識別字（與 notifycat.Event 不同軸：
// 前者是告警 payload 的事件欄，後者是系統訊息的翻譯鍵）
const (
	alertEventCommandAlert = "command_alert"
	alertEventTest         = "test"
	// testRuleName 測試發送的規則名：機器識別字，不譯不組字
	testRuleName = "test"
)

type notifySessionBody struct {
	ID      uint  `json:"id"`
	UserID  uint  `json:"user_id"`
	AssetID *uint `json:"asset_id"`
	// Username／AssetName 主體名稱：
	// 純加法，既有欄位的名稱、型別與語義不變，收端不需改動即可繼續解析。
	// omitempty——名稱解析不到時整個欄位不出現，而非送出空字串。
	Username  string `json:"username,omitempty"`
	AssetName string `json:"asset_name,omitempty"`
}

// alertSubjectNames 一則告警的主體名稱（查不到即為空字串，由呈現層降級）。
type alertSubjectNames struct {
	User  string
	Asset string
}

// buildAlertPayload 將告警組裝為推送 payload
func buildAlertPayload(alert model.CommandAlert, names alertSubjectNames) notifyPayload {
	return notifyPayload{
		Event: "command_alert",
		Alert: notifyAlertBody{
			ID:          alert.ID,
			Command:     alert.Command,
			Severity:    alert.Severity,
			RuleName:    alert.RuleName,
			Kind:        alert.Kind,
			ReasonCode:  alert.ReasonCode,
			Blocked:     alert.Blocked,
			TriggeredAt: alert.TriggeredAt,
		},
		Session: notifySessionBody{
			ID:        alert.SessionID,
			UserID:    alert.UserID,
			AssetID:   alert.AssetID,
			Username:  names.User,
			AssetName: names.Asset,
		},
	}
}

// signBody 計算 HMAC-SHA256 簽名（hex digest）；
// 收端以共享 secret 對 body 原文重算比對，防止偽造告警通知
func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// slackEscape 轉義 Slack mrkdwn 控制字元：& < > 須手動轉為 HTML 實體，
// 否則告警指令常見的重導向/運算子（> < &&）會被 Slack 當連結/引用語法解析致破版。
// 順序重要：& 先轉，否則會二次轉義後續產生的實體。Slack 顯示時會還原實體。
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// severityEmoji 依告警等級給 emoji；未知/空值落 default（不留空字串）
func severityEmoji(severity string) string {
	switch severity {
	case model.AlertSeverityHigh:
		return "🔴"
	case model.AlertSeverityMedium:
		return "🟠"
	case model.AlertSeverityLow:
		return "🟡"
	default:
		return "⚪"
	}
}

// buildSlackText 組 Slack mrkdwn 訊息文字：
// 首行 emoji＋規則名＋等級（＋阻斷標示）、次行指令（三引號 code block）、末行脈絡。
//
// 系統文案（測試通知標題內文、等級與阻斷標示）一律走 notifycat 的通道語系渲染；
// 使用者資料（規則名、指令）原樣呈現只做 slackEscape——翻譯目錄不碰使用者資料。
// 分隔以「·」而非各語系全形括號：標點不是文案，不進翻譯目錄
func buildSlackText(lang, event string, alert model.CommandAlert, names alertSubjectNames) string {
	var header string
	if event == alertEventTest {
		title, text := notifycat.Render(lang, notifycat.EventTest,
			map[string]string{"product": branding.Name})
		header = "🔔 *" + title + "*\n" + text
	} else {
		header = fmt.Sprintf("%s *%s* · %s",
			severityEmoji(alert.Severity), slackEscape(alert.RuleName),
			notifycat.Phrase(lang, notifycat.LexiconSeverity, alert.Severity))
		if alert.Blocked {
			header += " · " + notifycat.Phrase(lang, notifycat.LexiconAlertState,
				notifycat.AlertStateBlocked)
		}
	}
	cmd := fmt.Sprintf("```\n%s\n```", slackEscape(alert.Command))
	return header + "\n" + cmd + "\n" + buildAlertContext(lang, alert, names)
}

// buildAlertContext 組脈絡行：**誰 → 哪台 → 哪個會話 → 何時**。
//
// 順序是刻意的：稽核與資安讀告警的第一個問題是
// 「誰做的」、第二個是「在哪台機器」；會話識別碼是**追查用的索引**而非判讀用的資訊，
// 故後置。原順序把最不可讀的欄位放在最前面。
//
// 名稱在前、識別碼在括號內：讀者先看到可辨識的部分，需要追查時括號內的值可直接查詢。
// 名稱解析不到時該欄退化為僅識別碼——通知的價值在於送到，不因輔助資訊缺失而靜默。
func buildAlertContext(lang string, alert model.CommandAlert, names alertSubjectNames) string {
	label := func(key string) string { return notifycat.Phrase(lang, notifycat.LexiconEntity, key) }
	// subject 組「標籤 名稱 (#id)」；名稱為空時退化為「標籤 #id」
	subject := func(key, name string, id uint) string {
		if name == "" {
			return fmt.Sprintf("%s #%d", label(key), id)
		}
		return fmt.Sprintf("%s %s (#%d)", label(key), slackEscape(name), id)
	}

	parts := []string{subject(notifycat.EntityUser, names.User, alert.UserID)}
	if alert.AssetID != nil {
		parts = append(parts, subject(notifycat.EntityAsset, names.Asset, *alert.AssetID))
	}
	parts = append(parts,
		fmt.Sprintf("%s #%d", label(notifycat.EntitySession), alert.SessionID),
		alert.TriggeredAt.Format(time.RFC3339))
	// 分隔以「·」而非各語系全形標點：標點不是文案，不進翻譯目錄（既有定調）
	return strings.Join(parts, " · ")
}

// buildChannelBody 依通道類型建推送 body：
// webhook 送通用 JSON（event 可覆寫為 command_alert/test）；slack 送 {"text": mrkdwn}。
func buildChannelBody(ch *model.NotificationChannel, event string, alert model.CommandAlert,
	names alertSubjectNames) ([]byte, error) {
	if ch.Type == model.NotificationChannelTypeSlack {
		return json.Marshal(map[string]string{"text": buildSlackText(ch.Language, event, alert, names)})
	}
	payload := buildAlertPayload(alert, names)
	payload.Event = event
	return json.Marshal(payload)
}

// AlertNotifier 告警 webhook 推送器：
// 與 AlertMatcher 同模式——RWMutex 保護的啟用通道全量快取 + CUD Reload；
// 推送走 buffered channel + 單 worker goroutine，確保告警入庫路徑零阻塞
type AlertNotifier struct {
	db     *gorm.DB
	client *http.Client

	// codec 通道 url/secret 信封解密：
	// 快取載入時解密一次，worker 投遞用明文；nil＝明文直通（單測路徑）。
	// **ColumnCodec**：
	// 本路徑只讀不寫，但持有帶 Encrypt(plaintext) 的介面等同於把「無 AAD 寫入
	// 能力」發給服務層——收斂為 ColumnCodec 後建構上不可能誤用。
	// **建構時注入、無 SetCodec 事後覆寫**（原 SetCodec 須在 LoadChannels 前
	// 呼叫的時序陷阱一併消除）
	codec crypto.ColumnCodec

	// backoff 可注入：單元測試以極短退避驗證重試次數，避免測試 sleep 7 秒
	backoff []time.Duration

	mu       sync.RWMutex
	channels []model.NotificationChannel

	queue chan model.CommandAlert
	// startOnce 確保 worker 只起一條：推送順序與 log 可讀性依賴單 worker
	startOnce sync.Once
}

// 套件級單例：Enqueue 掛在 AlertMatcher.MatchAndStore（recorder 路徑深處），
// 與 AlertMatcher 同理由——逐層傳遞建構參數不划算，main 啟動時注入、getter 取用
var (
	alertNotifierMu       sync.RWMutex
	alertNotifierInstance *AlertNotifier
)

// NewAlertNotifier 建立推送器（不含單例註冊、不啟動 worker，供測試直接使用）；
// codec 為 url/secret 的信封解密器，nil＝明文直通（單測路徑）
func NewAlertNotifier(db *gorm.DB, codec crypto.ColumnCodec) *AlertNotifier {
	return &AlertNotifier{
		db:      db,
		codec:   codec,
		client:  &http.Client{Timeout: notifyHTTPTimeout},
		backoff: defaultNotifyBackoff,
		queue:   make(chan model.CommandAlert, notifyQueueSize),
	}
}

// InitAlertNotifier 建立並註冊單例、啟動 worker；main 啟動時呼叫一次
func InitAlertNotifier(db *gorm.DB, codec crypto.ColumnCodec) *AlertNotifier {
	n := NewAlertNotifier(db, codec)
	n.Start()
	alertNotifierMu.Lock()
	alertNotifierInstance = n
	alertNotifierMu.Unlock()
	return n
}

// GetAlertNotifier 取得單例；未初始化（單元測試環境）回 nil，呼叫端需 nil 檢查
func GetAlertNotifier() *AlertNotifier {
	alertNotifierMu.RLock()
	defer alertNotifierMu.RUnlock()
	return alertNotifierInstance
}

// ReloadAlertNotifier 通道 CUD 後刷新單例快取（同進程直接刷新）。
// 未初始化時 no-op；刷新失敗僅記 log——舊快取仍可用，下次 Reload 補上
func ReloadAlertNotifier() {
	n := GetAlertNotifier()
	if n == nil {
		return
	}
	if err := n.Reload(); err != nil {
		log.Printf("[AlertNotifier] 通道快取刷新失敗（沿用舊快取）: %v", err)
	}
}

// setChannels 全量替換快取（Reload 與單元測試共用的注入點）；
// 只留啟用通道——停用通道不該收到任何推送，過濾在快取層一次做完。
// url/secret 於此解密為投遞用明文（僅存在記憶體快取，與既有行為等價）；
// 解不開的通道跳過並記 log——寧缺勿以密文當 URL 投遞
func (n *AlertNotifier) setChannels(channels []model.NotificationChannel) int {
	enabled := make([]model.NotificationChannel, 0, len(channels))
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		plainURL, err := readChannelValue(n.codec, keyvault.RefChannelURL, ch.URL)
		if err != nil {
			log.Printf("[AlertNotifier] 通道 %q (id=%d) URL 解密失敗，跳過: %v", ch.Name, ch.ID, err)
			continue
		}
		plainSecret, err := readChannelValue(n.codec, keyvault.RefChannelSecret, ch.Secret)
		if err != nil {
			log.Printf("[AlertNotifier] 通道 %q (id=%d) secret 解密失敗，跳過: %v", ch.Name, ch.ID, err)
			continue
		}
		ch.URL = plainURL
		ch.Secret = plainSecret
		enabled = append(enabled, ch)
	}
	n.mu.Lock()
	n.channels = enabled
	n.mu.Unlock()
	return len(enabled)
}

// LoadChannels 從 DB 全量載入通道並重建快取
func (n *AlertNotifier) LoadChannels() error {
	var channels []model.NotificationChannel
	if err := n.db.Find(&channels).Error; err != nil {
		return fmt.Errorf("載入通知通道失敗: %w", err)
	}
	count := n.setChannels(channels)
	log.Printf("[AlertNotifier] 通道快取已載入 (%d 條啟用通道)", count)
	return nil
}

// Reload 重新載入通道（通道 CUD 後呼叫）
func (n *AlertNotifier) Reload() error {
	return n.LoadChannels()
}

// Start 啟動推送 worker（冪等）
func (n *AlertNotifier) Start() {
	n.startOnce.Do(func() {
		go n.worker()
	})
}

// Enqueue 非阻塞投遞告警至推送佇列：
// 呼叫點在告警入庫路徑上，滿載時丟棄記 log 而非阻塞——
// 通知是告警的附加價值，絕不反向影響告警入庫與會話
func (n *AlertNotifier) Enqueue(alert model.CommandAlert) {
	select {
	case n.queue <- alert:
	default:
		log.Printf("[AlertNotifier] 推送佇列已滿，丟棄告警通知 (alert_id=%d, rule=%s)", alert.ID, alert.RuleName)
	}
}

// worker 單 goroutine 消費佇列，逐告警推送至所有啟用通道
func (n *AlertNotifier) worker() {
	for alert := range n.queue {
		n.notify(alert)
	}
}

// NotifyEvent 發送結構化系統事件至所有啟用通道（取代散文版
// NotifyMessage）。頻率極低（每日個位數），直接起 goroutine 投遞不佔用告警佇列；
// 失敗僅 log，與告警通知同語義。
//
// 兩通道分工：
//   - webhook：送 {event, params, sent_at} 機器形狀，散文零出站
//   - Slack：由 notifycat 依**該通道語系**渲染（per-channel language）
//
// 降級：params 不合契約（含 event 未註冊）時**不拒發**——
// webhook 加 degraded 旗標、Slack 走 RenderDegraded 的通道語系 generic 文案。
// 合規告警不因目錄或呼叫端契約問題靜默消失，寧可露出機器碼。
// 降級時 params 收斂到 EventSpec 宣告鍵，未註冊 event 則 params 全空——
// event 身分永不丟（合規告警的識別靠它），值層出站面則收到最緊
func (n *AlertNotifier) NotifyEvent(event notifycat.Event, params map[string]string) {
	channels := n.snapshotChannels()
	if len(channels) == 0 {
		return
	}

	clean, err := notifycat.Validate(event, params)
	degraded := err != nil
	if degraded {
		// 降級 payload 的出站面收斂到 EventSpec 宣告鍵：
		// 未驗證不等於未淨化，也不等於「什麼都能出站」——未宣告鍵（呼叫端誤傳的
		// forensic detail、錯字鍵）值全數剔除；未註冊 event 則一鍵不留，
		// 只送 {event, degraded, sent_at}。被剔除的鍵名記本地 log（信任邊界內）
		var dropped []string
		clean, dropped = notifycat.FilterDeclared(event, params)
		log.Printf("[AlertNotifier] 事件 %s 參數不合契約，降級投遞（剔除未宣告鍵 %v）: %v",
			event, dropped, err)
	}

	go func() {
		for i := range channels {
			ch := &channels[i]
			var body []byte
			var marshalErr error
			if ch.Type == model.NotificationChannelTypeSlack {
				var title, text string
				if degraded {
					// 降級文案亦走通道語系（per-channel language 對降級
					// 路徑同樣適用）
					title, text = notifycat.RenderDegraded(ch.Language, event, clean)
				} else {
					title, text = notifycat.Render(ch.Language, event, clean)
				}
				// notifycat 已對插值的 opaque 值轉義；此處只套外框，
				// 不得再 slackEscape（二次轉義會把實體吃成字面量）
				body, marshalErr = json.Marshal(map[string]string{
					"text": fmt.Sprintf(":warning: *%s*\n%s", title, text),
				})
			} else {
				body, marshalErr = json.Marshal(notifyEventPayload{
					Event:    string(event),
					Params:   clean,
					Degraded: degraded,
					SentAt:   time.Now().Format(time.RFC3339),
				})
			}
			if marshalErr != nil {
				log.Printf("[AlertNotifier] 系統事件 payload 序列化失敗 (event=%s): %v", event, marshalErr)
				continue
			}
			n.deliverWithRetry(ch, body, 0)
		}
	}()
}

// snapshotChannels 讀鎖下取快取快照；推送期間 Reload 全量替換不影響已取得的快照
func (n *AlertNotifier) snapshotChannels() []model.NotificationChannel {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.channels
}

// resolveSubjectNames 取告警主體的顯示名。
//
// 查不到一律回空字串交由呈現層降級——**不回錯誤**：通知的價值在於送到，
// 為了補一個顯示欄位而讓告警靜默，是把輔助資訊放在主要目的之上。
// 零值識別碼（測試通知的 payload 即為 UserID=0）直接跳過查詢。
func (n *AlertNotifier) resolveSubjectNames(alert model.CommandAlert) alertSubjectNames {
	var out alertSubjectNames
	if alert.UserID != 0 {
		out.User = lookupUserNamesDB(n.db, []uint{alert.UserID})[alert.UserID]
	}
	if alert.AssetID != nil && *alert.AssetID != 0 {
		out.Asset = lookupAssetNamesDB(n.db, []uint{*alert.AssetID})[*alert.AssetID]
	}
	return out
}

// notify 推送單筆告警至所有啟用通道（worker 呼叫；測試亦可直接同步呼叫）。
// 任何失敗僅 log——投遞不持久化追蹤（proposal non-goal）
func (n *AlertNotifier) notify(alert model.CommandAlert) {
	channels := n.snapshotChannels()
	if len(channels) == 0 {
		return
	}

	// 主體名稱在此解析而非入庫時快照：本函式由 worker 呼叫，
	// 不在告警入庫路徑上；且每則告警只查一次，所有通道共用同一份結果。
	// channels 為空時已提前返回，不會產生無用查詢。
	names := n.resolveSubjectNames(alert)

	// per-channel 建 body：不同類型格式不同（webhook JSON / slack text），
	// 故不再迴圈外共用單一 body（通道量級個位數到數十，per-channel marshal 成本可忽略）
	for i := range channels {
		body, err := buildChannelBody(&channels[i], alertEventCommandAlert, alert, names)
		if err != nil {
			log.Printf("[AlertNotifier] 通道 %q (id=%d) payload 序列化失敗 (alert_id=%d): %v",
				channels[i].Name, channels[i].ID, alert.ID, err)
			continue
		}
		n.deliverWithRetry(&channels[i], body, alert.ID)
	}
}

// SanitizeDeliveryError 投遞錯誤脫敏：url.Error 的 Error() 內嵌完整請求
// URL（webhook 路徑即持有型 secret），url.Error 只留 op+host；此外任何
// 分支最後都把已知目標 URL 及其敏感片段從訊息抹除——底層錯誤（redirect、
// 自訂 transport）可能原樣夾帶完整 target，op+host 收口擋不到
// （安全紅線：密鑰不落日誌）
func SanitizeDeliveryError(err error, targetURL string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		msg = fmt.Sprintf("%s %s: %v", uerr.Op, host, uerr.Err)
	}
	return scrubSecretURL(msg, targetURL)
}

// scrubSecretURL 從訊息抹除已知 bearer URL 的完整字串與敏感片段
// （path/query/userinfo 密碼），只留 scheme://host 供維運定位
func scrubSecretURL(msg, targetURL string) string {
	if targetURL == "" {
		return msg
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return strings.ReplaceAll(msg, targetURL, "***")
	}
	msg = strings.ReplaceAll(msg, targetURL, u.Scheme+"://"+u.Host+"/***")
	if u.Path != "" && u.Path != "/" {
		msg = strings.ReplaceAll(msg, u.Path, "/***")
	}
	if u.RawQuery != "" {
		msg = strings.ReplaceAll(msg, u.RawQuery, "***")
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		msg = strings.ReplaceAll(msg, pw, "***")
	}
	return msg
}

// deliverWithRetry 對單一通道投遞，失敗時按退避序列重試
func (n *AlertNotifier) deliverWithRetry(ch *model.NotificationChannel, body []byte, alertID uint) {
	attempts := len(n.backoff) + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		status, err := deliverOnce(n.client, ch, body)
		if err == nil && status >= 200 && status < 300 {
			return
		}
		if err != nil {
			log.Printf("[AlertNotifier] 通道 %q (id=%d) 推送失敗 (alert_id=%d, 第 %d/%d 次): %s",
				ch.Name, ch.ID, alertID, attempt, attempts, SanitizeDeliveryError(err, ch.URL))
		} else {
			log.Printf("[AlertNotifier] 通道 %q (id=%d) 推送被拒 (alert_id=%d, 第 %d/%d 次): HTTP %d",
				ch.Name, ch.ID, alertID, attempt, attempts, status)
		}
		if attempt < attempts {
			time.Sleep(n.backoff[attempt-1])
		}
	}
	log.Printf("[AlertNotifier] 通道 %q (id=%d) 推送最終失敗，放棄 (alert_id=%d)", ch.Name, ch.ID, alertID)
}

// deliverOnce 單次 HTTP 投遞：POST JSON body，secret 非空時附 HMAC 簽名 header。
// 回傳 HTTP 狀態碼供呼叫端判斷重試；body 讀畢丟棄以利連線重用
func deliverOnce(client *http.Client, ch *model.NotificationChannel, body []byte) (int, error) {
	req, err := http.NewRequest(http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("建立請求失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// slack 不簽名（Slack 不驗自訂標頭；附了只是誤導），僅 webhook 且 secret 非空才簽
	if ch.Type != model.NotificationChannelTypeSlack && ch.Secret != "" {
		req.Header.Set(signatureHeaderKey, signBody(ch.Secret, body))
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// 排空回應 body：讓 http.Client 重用底層連線，重試/多通道時省握手成本
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// SendTestNotification 同步發送測試 payload 至指定通道：
// admin 點「測試發送」要即時回饋，單次嘗試不重試——失敗原因直接回給操作者，
// 由人決定修正後重試，自動退避只會拖慢回饋
func SendTestNotification(ch *model.NotificationChannel) (int, error) {
	testAlert := model.CommandAlert{
		Command:  "echo " + branding.Slug + " notification test",
		Severity: model.AlertSeverityLow,
		// 機器識別字：webhook 的 rule_name 欄不再是散文，
		// Slack 側的可讀標題改由 notifycat 依通道語系渲染
		RuleName:    testRuleName,
		TriggeredAt: time.Now(),
	}
	// 測試 payload 無真實主體（SessionID／UserID 皆為 0），故不解析名稱——
	// 脈絡行會走降級路徑只顯示識別碼，那是預期形態
	body, err := buildChannelBody(ch, alertEventTest, testAlert, alertSubjectNames{})
	if err != nil {
		return 0, fmt.Errorf("測試 payload 序列化失敗: %w", err)
	}
	client := &http.Client{Timeout: notifyHTTPTimeout}
	return deliverOnce(client, ch, body)
}
