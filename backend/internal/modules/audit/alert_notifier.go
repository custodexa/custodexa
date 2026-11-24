package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/branding"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 送出參數：
//   - timeout 5s：每次送出的 HTTP 逾時（投遞程序、測試發送與稽核失效退路共用）
//   - 稽核失效退路重試 3 次（1s/2s/4s 指數退避），之後放棄
const (
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
	// Notification 三種形狀共用的新物件（純加法；既有欄位不動）。
	Notification *notificationObject `json:"notification,omitempty"`
}

type notifyAlertBody struct {
	Output   *OutputAlertMetadata `json:"possible_sensitive_output,omitempty"`
	ID       uint                 `json:"id"`
	Command  string               `json:"command"`
	Severity string               `json:"severity"`
	RuleName string               `json:"rule_name"`
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
	Event string `json:"event"`
	// Params 日期清單參數展開成 JSON 陣列（notifycat.WireParams），其餘為字串
	Params   map[string]any `json:"params"`
	Degraded bool           `json:"degraded,omitempty"`
	SentAt   string         `json:"sent_at"`
	// Notification 三種形狀共用的新物件（純加法；既有欄位不動）。
	Notification *notificationObject `json:"notification,omitempty"`
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
	// ClientIP 該會話建線當下的來源位址。同樣是純加法的可選欄——
	// 新來源位址類的告警，位址就是告警的內容本身；收端不需改動即可繼續解析
	ClientIP string `json:"client_ip,omitempty"`
}

// alertSubjectNames 一則告警的主體名稱（查不到即為空字串，由呈現層降級）。
type alertSubjectNames struct {
	User  string
	Asset string
	// ClientIP 所屬會話建線當下的來源位址（查不到即空字串）。
	// 名字叫 subjectNames 而它不是名字——放在這裡是因為它與兩個名稱同源、
	// 同一次解析取得、同樣「查不到就降級不報錯」
	ClientIP string
	// DegradeReason 指令稽核降級告警所屬那一段的降級原因碼（僅該類告警查詢；
	// 查不到即空字串）。只用於 Slack 的白話說明行，不進 webhook payload。
	DegradeReason string
}

// buildAlertPayload 將告警組裝為推送 payload
func buildAlertPayload(alert model.CommandAlert, names alertSubjectNames) notifyPayload {
	var output *OutputAlertMetadata
	if meta, ok := ParseOutputAlert(alert.ReasonCode); ok {
		output = &meta
	}
	return notifyPayload{
		Event: "command_alert",
		Alert: notifyAlertBody{
			Output:      output,
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
			ClientIP:  names.ClientIP,
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

// slackInlineText 使用者輸入（規則名、使用者名、資產名等）放進 Slack 文字的一行之中前的處理：先經共用的
// 不透明文字淨化（換行與行分隔符折成空白、控制字元與雙向控制等格式字元移除），再轉義 & < >。
// 使用者輸入因此不能讓訊息多出一行或段落。
func slackInlineText(s string) string {
	return slackEscape(notifycat.SanitizeOpaque(s))
}

// slackBoldText 放進粗體標題（*…*）的使用者輸入：在 slackInlineText 之外把星號換成全形星號，
// 名稱不能提前結束粗體、也不能在標題中另開粗體。
func slackBoldText(s string) string {
	return strings.ReplaceAll(slackInlineText(s), "*", "＊")
}

// slackCodeBlockText 放進三引號程式碼區塊的指令：換行留在區塊之內，不會形成區塊外的段落，所以維持原樣；
// 連續三個反引號會提前結束區塊，換成外觀相近的字元。其餘只轉義 & < >。
func slackCodeBlockText(s string) string {
	return strings.ReplaceAll(slackEscape(s), "```", "ˋˋˋ")
}

// severityEmoji 依告警等級給開頭符號；與系統事件共用同一份對照（未知/空值落中性符號，不留空字串）
func severityEmoji(severity string) string {
	return notifycat.SeveritySymbol(severity)
}

// buildSlackText 組 Slack mrkdwn 訊息文字：
// 首行 emoji＋規則名＋等級（＋阻斷標示）、次行指令（三引號 code block）、末行脈絡。
//
// 系統文案（測試通知標題內文、等級與阻斷標示）一律走 notifycat 的通道語系渲染；
// 使用者資料（規則名、指令）不經翻譯目錄；規則名經 slackBoldText、指令經 slackCodeBlockText，
// 使它們不能多出行或改變標記的邊界。
// 分隔以「·」而非各語系全形括號：標點不是文案，不進翻譯目錄
func buildSlackText(lang, event string, alert model.CommandAlert, names alertSubjectNames) string {
	// 非規則類告警沒有規則名與指令可呈現，改走白話版型；規則類的組字路徑不變
	if event != alertEventTest && !isRuleKindAlert(alert.Kind) {
		return buildNonRuleSlackText(lang, alert, names)
	}
	if event == alertEventTest {
		return buildTestSlackText(lang, "", alert.TriggeredAt)
	}
	header := fmt.Sprintf("%s *%s* · %s",
		severityEmoji(alert.Severity), slackBoldText(alert.RuleName),
		notifycat.Phrase(lang, notifycat.LexiconSeverity, alert.Severity))
	if alert.Blocked {
		header += " · " + notifycat.Phrase(lang, notifycat.LexiconAlertState,
			notifycat.AlertStateBlocked)
	}
	cmd := fmt.Sprintf("```\n%s\n```", slackCodeBlockText(alert.Command))
	if meta, ok := ParseOutputAlert(alert.ReasonCode); ok {
		cmd = fmt.Sprintf("%s (%d)", notifycat.Phrase(lang, notifycat.LexiconAlertState, notifycat.AlertStatePossibleSensitive), meta.Count)
	}
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
		name = slackInlineText(name)
		if name == "" {
			return fmt.Sprintf("%s #%d", label(key), id)
		}
		return fmt.Sprintf("%s %s (#%d)", label(key), name, id)
	}

	parts := []string{subject(notifycat.EntityUser, names.User, alert.UserID)}
	if alert.AssetID != nil {
		parts = append(parts, subject(notifycat.EntityAsset, names.Asset, *alert.AssetID))
	}
	if alert.SessionID != 0 {
		parts = append(parts, fmt.Sprintf("%s #%d", label(notifycat.EntitySession), alert.SessionID))
	}
	parts = append(parts, notifycat.SlackDate(alert.TriggeredAt))
	// 分隔以「·」而非各語系全形標點：標點不是文案，不進翻譯目錄（既有定調）
	return strings.Join(parts, " · ") + notifycat.SlackLinkSuffix(lang, commandAlertLink(alert), notifycat.LinkLabelAction)
}

// commandAlertLink 指令告警的去處：有會話時是會話頁，沒有會話時是告警記錄頁；未設基準網址時為空字串。
func commandAlertLink(alert model.CommandAlert) string {
	if alert.SessionID != 0 {
		return composeNotificationLink(fmt.Sprintf("/sessions/%d", alert.SessionID))
	}
	return composeNotificationLink("/alerts")
}

// buildTestSlackText 測試通知的 Slack 文字：第一行寫明是測試、不需處理，內文帶通道名稱，最後一行為時間；
// 不附連結，也沒有虛構的指令、使用者或會話編號。
func buildTestSlackText(lang, channelName string, at time.Time) string {
	params := map[string]string{"product": branding.Name}
	if channelName != "" {
		params["channel_name"] = channelName
	}
	title, text := notifycat.Render(lang, notifycat.EventTest, params)
	if at.IsZero() {
		at = time.Now()
	}
	return notifycat.ComposeSlack(lang, notifycat.SlackMessage{Prefix: notifycat.TestSymbol, Title: title, Body: text, Occurred: at})
}

// eventSeverity 系統事件在事件規格宣告的分級；未登錄或沿用類型目錄的事件回空字串（不加分級標籤）。
func eventSeverity(event notifycat.Event) string {
	spec, ok := notifycat.Spec(event)
	if !ok || spec.Severity == notifycat.SeverityFromCatalog {
		return ""
	}
	return spec.Severity
}

// buildChannelBody 依通道類型建推送 body：
// webhook 送通用 JSON（event 可覆寫為 command_alert/test）並附新物件 obj（nil 時不附）；slack 送 {"text": mrkdwn}。
func buildChannelBody(ch *model.NotificationChannel, event string, alert model.CommandAlert,
	names alertSubjectNames, obj *notificationObject) ([]byte, error) {
	dest := destinationFromChannel(ch)
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return nil, fmt.Errorf("通道型別 %q 不在登錄中", ch.Type)
	}
	if desc.Caps.RendersText {
		text := buildSlackText(ch.Language, event, alert, names)
		if event == alertEventTest {
			text = buildTestSlackText(ch.Language, ch.Name, alert.TriggeredAt)
		}
		return desc.BuildBody(dest, OutboundMessage{Text: text})
	}
	payload := buildAlertPayload(alert, names)
	payload.Event = event
	payload.Notification = obj
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return desc.BuildBody(destinationFromChannel(ch), OutboundMessage{JSON: raw})
}

// AlertNotifier 通知的排入介面持有者。
//
// 產生點經它排入指令告警與系統事件（EnqueueInTx／EnqueueStandalone，notification_enqueue.go），
// 投遞由 SystemAlertOutboxWorker 持久進行；本型別不快取通道、不經佇列投遞。
//
// 唯一的直接送出路徑是稽核失效一族的退路（EnqueueAuditFailureNotice）：內容寫不進資料庫時，
// 以同一套渲染直接送往啟用中的通道（通道清單見 AuditFallbackList）。
type AlertNotifier struct {
	db *gorm.DB

	// codec 通道 url/secret 信封解密（退路讀通道用）；nil＝明文直通（單測路徑）。
	codec crypto.ColumnCodec

	// backoff 退路直接送出的重試退避序列（可注入）
	backoff []time.Duration

	// stats 排入成敗計數，交給投遞程序的回報檢查點讀取。
	stats *EnqueueStats
	// now 寫入內容列的時刻來源（可由測試覆寫）。
	now func() time.Time

	// fallback 退路的通道清單（投遞程序每輪換新）。
	fallback *AuditFallbackList
	// auditHooks 稽核失效一族的測試掛點；全部可為 nil。
	auditHooks auditNoticeHooks
	// sleep 退路重試的等待（測試可覆寫）；transport 退路送出的傳輸（測試可覆寫）。
	sleep     func(time.Duration)
	transport http.RoundTripper

	// auditNotices 稽核失效一族的背景工作（測試可等待其結束）；auditInFlight 為其計數（純觀測）
	auditNotices  sync.WaitGroup
	auditInFlight atomic.Int64
}

// auditNoticeHooks 稽核失效一族的測試掛點。
type auditNoticeHooks struct {
	// beforeWrite 寫內容列之前（在 goroutine 的 recover 之內）；回錯視同寫入失敗。
	beforeWrite func(event notifycat.Event) error
	// beforeChannelRead 退路讀資料庫通道之前；回錯視同讀不到。
	beforeChannelRead func() error
}

// 套件級單例：產生點分散在各模組與背景迴圈，main 啟動時注入、getter 取用
var (
	alertNotifierMu       sync.RWMutex
	alertNotifierInstance *AlertNotifier
)

// NewAlertNotifier 建立排入介面（不含單例註冊，供測試直接使用）；
// codec 為 url/secret 的信封解密器，nil＝明文直通（單測路徑）
func NewAlertNotifier(db *gorm.DB, codec crypto.ColumnCodec) *AlertNotifier {
	return &AlertNotifier{
		db:       db,
		codec:    codec,
		backoff:  defaultNotifyBackoff,
		stats:    &EnqueueStats{},
		fallback: &AuditFallbackList{},
		sleep:    time.Sleep,
	}
}

// InitAlertNotifier 建立並註冊單例；main 啟動時呼叫一次
func InitAlertNotifier(db *gorm.DB, codec crypto.ColumnCodec) *AlertNotifier {
	n := NewAlertNotifier(db, codec)
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

func (n *AlertNotifier) clock() time.Time {
	if n.now != nil {
		return n.now().UTC()
	}
	return time.Now().UTC()
}

// BackgroundInFlight 尚未完成的背景工作數（稽核失效通知的背景寫入與直接送出）；純觀測介面。
func (n *AlertNotifier) BackgroundInFlight() int64 {
	return n.auditInFlight.Load()
}

// AuditFallbackList 稽核失效退路的通道清單（明文網址與秘密，只給直接送出使用）。
//
// 由投遞程序在啟動時與每一輪開頭讀取全部啟用通道後整份換掉；讀取失敗時沿用上一份。
// 內容與舊版的通道推送快取相同，不多存任何東西；通道停用或刪除後，下一次成功讀取即不在清單內。
type AuditFallbackList struct {
	mu       sync.RWMutex
	channels []model.NotificationChannel
	loaded   bool
}

// replace 整份換掉清單。
func (l *AuditFallbackList) replace(channels []model.NotificationChannel) {
	if l == nil {
		return
	}
	cp := append([]model.NotificationChannel(nil), channels...)
	l.mu.Lock()
	l.channels = cp
	l.loaded = true
	l.mu.Unlock()
}

// snapshot 回傳清單的副本。
func (l *AuditFallbackList) snapshot() []model.NotificationChannel {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]model.NotificationChannel(nil), l.channels...)
}

// AuditFallbackList 退路的通道清單（組裝根交給投遞程序，由它每輪換新）。
func (n *AlertNotifier) AuditFallbackList() *AuditFallbackList {
	if n == nil {
		return nil
	}
	return n.fallback
}

// auditChannelReadTimeout 退路讀資料庫通道的逾時。
const auditChannelReadTimeout = 2 * time.Second

// EnqueueAuditFailureNotice 稽核失效一族（失效、恢復、持續）的專屬排入入口。
//
// 呼叫端可能持有稽核失效服務的鎖，所以本函式只複製參數、起一個 goroutine 就返回；寫入、讀通道與
// 直接送出都在 goroutine 內、鎖之外進行。成功與失敗都不呼叫 Report／Resolve，也不計入排入計數，
// 所以這一族不會回頭進入稽核失效服務。goroutine 以 recover 包住，panic 只記 log 並丟棄這則通知。
func (n *AlertNotifier) EnqueueAuditFailureNotice(event notifycat.Event, params map[string]string) {
	if n == nil {
		return
	}
	copied := make(map[string]string, len(params))
	for k, v := range params {
		copied[k] = v
	}
	occurred := n.clock()
	n.auditNotices.Add(1)
	n.auditInFlight.Add(1)
	go func() {
		defer n.auditNotices.Done()
		defer n.auditInFlight.Add(-1)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[NotificationEnqueue] 稽核失效通知處理時發生 panic，已丟棄 (event=%s): %v", event, r)
			}
		}()
		if err := n.writeAuditFailureNotice(event, copied, occurred); err != nil {
			log.Printf("[NotificationEnqueue] 稽核失效通知寫入失敗，改為直接送出 (event=%s): %v", event, err)
			n.directSendAuditNotice(event, copied, occurred)
		}
	}()
}

// writeAuditFailureNotice 獨立寫一列稽核失效通知的內容。
func (n *AlertNotifier) writeAuditFailureNotice(event notifycat.Event, params map[string]string, occurred time.Time) error {
	if n.auditHooks.beforeWrite != nil {
		if err := n.auditHooks.beforeWrite(event); err != nil {
			return err
		}
	}
	if n.db == nil {
		return errors.New("排入介面未注入資料庫")
	}
	notice := SystemEventNotice(event, params)
	notice.OccurredAt = occurred
	row, err := buildNotificationMessage(notice, n.clock())
	if err != nil {
		return err
	}
	return n.db.Create(&row).Error
}

// directSendAuditNotice 退路：以同一套渲染直接送往啟用中的通道（盡力送出、不持久、不進投遞紀錄）。
// 先以短逾時讀資料庫的啟用通道，讀不到才用投遞程序保留的清單；每個通道失敗時依 backoff 短重試。
func (n *AlertNotifier) directSendAuditNotice(event notifycat.Event, params map[string]string, occurred time.Time) {
	channels, err := n.readChannelsForFallback()
	if err != nil {
		log.Printf("[NotificationEnqueue] 退路讀不到資料庫的通道，改用最近一次讀到的清單: %v", err)
		channels = n.fallback.snapshot()
	}
	if len(channels) == 0 {
		log.Printf("[NotificationEnqueue] 退路沒有可送的通道，稽核失效通知未送出 (event=%s)", event)
		return
	}
	msg := model.NotificationMessage{
		Category:   model.NotificationCategorySystemEvent,
		EventKey:   string(event),
		OccurredAt: occurred,
		LinkPath:   notifycat.LinkPath(event, params),
	}
	// 直接送出沒有投遞紀錄；同一則通知送往各通道共用一個投遞識別，收端可據以去重。
	deliveryID, _ := newDeliveryKey()
	for i := range channels {
		ch := &channels[i]
		dest := destinationFromChannel(ch)
		body, err := renderSystemEventBody(msg, params, dest, deliveryID, n.clock())
		if err != nil {
			log.Printf("[NotificationEnqueue] 退路渲染失敗 (channel_id=%d, event=%s): %v", ch.ID, event, err)
			continue
		}
		n.directSendOne(ch, dest, body, event)
	}
}

// directSendOne 對單一通道直接送出，失敗時依 backoff 重試；全部失敗只記 log。
func (n *AlertNotifier) directSendOne(ch *model.NotificationChannel, dest ChannelDestination, body []byte, event notifycat.Event) {
	client := newNotificationHTTPClient(dest.Type, dest.URL, notifyHTTPTimeout, nil, n.transport)
	attempts := len(n.backoff) + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		res, err := sendRenderedBody(client, dest, body)
		if err == nil && res.OK() {
			return
		}
		if err != nil {
			log.Printf("[NotificationEnqueue] 退路送出失敗 (channel_id=%d, event=%s, 第 %d/%d 次): %s",
				ch.ID, event, attempt, attempts, SanitizeChannelError(err, dest.URL, dest.Secret))
		} else {
			log.Printf("[NotificationEnqueue] 退路送出被拒 (channel_id=%d, event=%s, 第 %d/%d 次): HTTP %d %s",
				ch.ID, event, attempt, attempts, res.Status, res.PlatformError)
		}
		if attempt < attempts {
			n.sleep(n.backoff[attempt-1])
		}
	}
	log.Printf("[NotificationEnqueue] 退路送出最終失敗，放棄 (channel_id=%d, event=%s)", ch.ID, event)
}

// sendRenderedBody 送出已依型別組好的本文（標頭與回應判讀由型別描述決定）。
func sendRenderedBody(client *http.Client, dest ChannelDestination, body []byte) (DeliveryResult, error) {
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return DeliveryResult{}, fmt.Errorf("通道型別 %q 不在登錄中", dest.Type)
	}
	req, err := desc.NewRequest(dest, body)
	if err != nil {
		return DeliveryResult{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return DeliveryResult{}, err
	}
	defer resp.Body.Close()
	return desc.ReadResult(resp), nil
}

// readChannelsForFallback 以短逾時讀資料庫的啟用通道並解密。
func (n *AlertNotifier) readChannelsForFallback() ([]model.NotificationChannel, error) {
	if n.auditHooks.beforeChannelRead != nil {
		if err := n.auditHooks.beforeChannelRead(); err != nil {
			return nil, err
		}
	}
	if n.db == nil {
		return nil, errors.New("排入介面未注入資料庫")
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditChannelReadTimeout)
	defer cancel()
	return loadEnabledChannelsPlain(n.db.WithContext(ctx), n.codec)
}

// waitAuditNotices 等待進行中的稽核失效通知背景工作結束（測試用）。
func (n *AlertNotifier) waitAuditNotices() { n.auditNotices.Wait() }

// loadEnabledChannelsPlain 讀資料庫中啟用的通道並解開網址與秘密；解不開的通道跳過並記 log。
// 讀取本身失敗時回錯（呼叫端據此決定沿用舊清單）。
func loadEnabledChannelsPlain(db *gorm.DB, codec crypto.ColumnCodec) ([]model.NotificationChannel, error) {
	var channels []model.NotificationChannel
	if err := db.Where("enabled = ?", true).Order("id").Find(&channels).Error; err != nil {
		return nil, err
	}
	out := make([]model.NotificationChannel, 0, len(channels))
	for _, ch := range channels {
		plainURL, err := readChannelValue(codec, keyvault.RefChannelURL, ch.URL)
		if err != nil {
			log.Printf("[AlertNotifier] 通道 id=%d 網址無法讀取，跳過", ch.ID)
			continue
		}
		plainSecret, err := readChannelValue(codec, keyvault.RefChannelSecret, ch.Secret)
		if err != nil {
			log.Printf("[AlertNotifier] 通道 id=%d 秘密無法讀取，跳過", ch.ID)
			continue
		}
		ch.URL = plainURL
		ch.Secret = plainSecret
		out = append(out, ch)
	}
	return out, nil
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
	if alert.SessionID != 0 && n.db != nil {
		var ip string
		// 查不到（會話列已清除、或測試通知的零值）一律留空，不回錯誤——
		// 理由同上：不為了補一個欄位而讓告警靜默
		_ = n.db.Model(&model.Session{}).
			Select("client_ip").
			Where("id = ?", alert.SessionID).
			Limit(1).
			Scan(&ip).Error
		out.ClientIP = ip
	}
	out.DegradeReason = lookupDegradeReason(n.db, alert)
	return out
}

// severityRank 告警等級的序位（low < medium < high）；不在三值內回 0
func severityRank(s string) int {
	switch s {
	case model.AlertSeverityLow:
		return 1
	case model.AlertSeverityMedium:
		return 2
	case model.AlertSeverityHigh:
		return 3
	default:
		return 0
	}
}

// channelAdmitsSeverity 通道推送門檻是否放行此等級的告警。
//   - 告警等級為空或不在三值內：照送——無法分類的告警不應被門檻靜默略過；
//   - 通道門檻為空或不在三值內（DB CHECK 之下只會出現在繞過 DB 的測試路徑）：
//     視同 low（全部告警），即門檻欄存在前的行為。
func channelAdmitsSeverity(minSeverity, severity string) bool {
	alertRank := severityRank(severity)
	if alertRank == 0 {
		return true
	}
	return alertRank >= severityRank(minSeverity)
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
	return ScrubChannelTokens(scrubSecretURL(msg, targetURL))
}

// SanitizeChannelError 同 SanitizeDeliveryError，另抹除該通道的秘密字面（slack_app 的機器人 token）。
func SanitizeChannelError(err error, targetURL, secret string) string {
	return ScrubChannelTokens(SanitizeDeliveryError(err, targetURL), secret)
}

// slackTokenPattern Slack token 的字面（xoxb-、xoxp-、xapp- 等開頭的片段）。
var slackTokenPattern = regexp.MustCompile(`\b(xox[a-zA-Z]|xapp)-[A-Za-z0-9-]*`)

// slackTokenMask 抹除後的替代字樣。
const slackTokenMask = "xox*-***"

// ScrubChannelTokens 從訊息抹除 token：已知的秘密字面一律抹除，Slack token 形狀的片段也一律抹除。
// 投遞錯誤、落庫錯誤、log 與 API 回應經這個函式（秘密不出現在任何輸出）。
func ScrubChannelTokens(msg string, secrets ...string) string {
	for _, s := range secrets {
		if len(s) >= 4 {
			msg = strings.ReplaceAll(msg, s, slackTokenMask)
		}
	}
	return slackTokenPattern.ReplaceAllString(msg, slackTokenMask)
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

// deliverOnce 單次 HTTP 投遞：本文已依型別組好，標頭（簽章或授權）與回應判讀由型別描述決定。
// 回傳 HTTP 狀態碼供呼叫端判斷重試；平台回報的錯誤（HTTP 2xx 而本文表明失敗）以 error 回傳
func deliverOnce(client *http.Client, ch *model.NotificationChannel, body []byte) (int, error) {
	dest := destinationFromChannel(ch)
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return 0, fmt.Errorf("通道型別 %q 不在登錄中", ch.Type)
	}
	req, err := desc.NewRequest(dest, body)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	res := desc.ReadResult(resp)
	// 不跟隨轉址的型別收到 3xx：以狀態碼回報（呼叫端判為失敗），不當成平台錯誤碼
	if res.Status >= 300 && res.Status < 400 {
		return res.Status, nil
	}
	if res.PlatformError != "" {
		return res.Status, &ChannelPlatformError{Status: res.Status, Code: res.PlatformError}
	}
	return res.Status, nil
}

// ChannelPlatformError 對方已回應、但回應表明失敗（Slack 應用程式的 ok 不是 true，或回應無法判讀）。
// 與連線層失敗（DNS、逾時、拒連）分開：請求已送達平台，原因是平台回報的錯誤碼。
// Code 已淨化（只含 [a-z0-9_]、最長 64 字元，否則為 unparseable_response）。
type ChannelPlatformError struct {
	Status int
	Code   string
}

func (e *ChannelPlatformError) Error() string { return "platform error: " + e.Code }

// ChannelTestRedirectReason 測試發送的錯誤若是轉址規則擋下（轉址次數過多、轉址目的地不符傳輸政策），回傳與投遞紀錄
// 相同的原因代碼（redirect_too_many、redirect_policy）；其他錯誤回空字串。
func ChannelTestRedirectReason(err error) string {
	switch {
	case errors.Is(err, errRedirectTooMany):
		return "redirect_too_many"
	case errors.Is(err, errRedirectPolicy):
		return "redirect_policy"
	}
	return ""
}

// ChannelTestStatusReason 測試發送收到不跟隨的 3xx 時的原因代碼（與投遞紀錄相同）；其他狀態回空字串。
func ChannelTestStatusReason(status int) string {
	if status >= 300 && status < 400 {
		return "redirect_not_followed"
	}
	return ""
}

// 測試發送可選的 webhook 形狀（請求本文的 shape）；空字串＝指令告警形狀（升級前的行為）。
const (
	TestShapeCommandAlert        = "command_alert"
	TestShapeSystemSecurityAlert = "system_security_alert"
	TestShapeSystemEvent         = "system_event"
)

// ValidTestShape 測試發送的形狀是否合法（空字串合法，代表省略）。
func ValidTestShape(shape string) bool {
	switch shape {
	case "", TestShapeCommandAlert, TestShapeSystemSecurityAlert, TestShapeSystemEvent:
		return true
	}
	return false
}

// SendTestNotification 同步發送測試 payload 至指定通道（指令告警形狀）。
func SendTestNotification(ch *model.NotificationChannel) (int, error) {
	return SendTestNotificationShape(ch, "")
}

// SendTestNotificationShape 同步發送測試 payload 至指定通道：
// admin 點「測試發送」要即時回饋，單次嘗試不重試——失敗原因直接回給操作者，
// 由人決定修正後重試，自動退避只會拖慢回饋。
//
// shape 只對 webhook 有作用（三種形狀都附 category 為 test 的新物件）；渲染文字的型別忽略它。
// 目的地只來自呼叫端以通道識別碼取出的已存設定，本函式不接受其他網址或秘密；不建立任何待投遞紀錄。
func SendTestNotificationShape(ch *model.NotificationChannel, shape string) (int, error) {
	now := time.Now()
	testAlert := model.CommandAlert{
		Command:  "echo " + branding.Slug + " notification test",
		Severity: model.AlertSeverityLow,
		// 機器識別字：webhook 的 rule_name 欄不再是散文，
		// Slack 側的可讀標題改由 notifycat 依通道語系渲染
		RuleName:    testRuleName,
		TriggeredAt: now,
	}
	obj := testObject(now)
	var body []byte
	var err error
	switch {
	case channelRendersText(destinationFromChannel(ch).Type), shape == "", shape == TestShapeCommandAlert:
		// 測試 payload 無真實主體（SessionID／UserID 皆為 0），故不解析名稱——
		// 脈絡行會走降級路徑只顯示識別碼，那是預期形態
		body, err = buildChannelBody(ch, alertEventTest, testAlert, alertSubjectNames{}, obj)
	case shape == TestShapeSystemSecurityAlert:
		body, err = buildTestWebhookBody(ch, systemAlertWebhookPayload{
			Event: systemAlertWebhookEvent,
			Alert: systemAlertWebhookAlert{Type: alertEventTest, Severity: model.AlertSeverityLow,
				OccurredAt: now.UTC().Format(time.RFC3339), Params: map[string]any{}},
			DeliveryID: obj.DeliveryID, SentAt: now.Format(time.RFC3339), Notification: obj,
		})
	case shape == TestShapeSystemEvent:
		body, err = buildTestWebhookBody(ch, notifyEventPayload{Event: alertEventTest, Params: map[string]any{},
			SentAt: now.In(time.Local).Format(time.RFC3339), Notification: obj})
	default:
		return 0, fmt.Errorf("不支援的測試形狀 %q", shape)
	}
	if err != nil {
		return 0, fmt.Errorf("測試 payload 序列化失敗: %w", err)
	}
	client := newNotificationHTTPClient(destinationFromChannel(ch).Type, ch.URL, notifyHTTPTimeout, nil, nil)
	return deliverOnce(client, ch, body)
}

// buildTestWebhookBody 以型別描述把測試用的結構化本文組成請求本文。
func buildTestWebhookBody(ch *model.NotificationChannel, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	dest := destinationFromChannel(ch)
	return buildRenderedBody(dest.Type, dest, OutboundMessage{JSON: raw})
}
