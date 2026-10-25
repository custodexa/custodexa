package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 通道驗證錯誤：handler 以 errors.Is 區分 400（輸入問題）與 500（系統問題）
var (
	ErrChannelNotFound   = errors.New("通知通道不存在")
	ErrInvalidChannelURL = errors.New("URL 必須為 http 或 https")
	ErrInvalidChannelTyp = errors.New("通道類型必須為 webhook 或 slack")
	// ErrInvalidChannelLanguage 語系非白名單三值；
	// Update 顯式給空字串或白名單外值都回此錯——省略（nil）才是「保留舊值」
	ErrInvalidChannelLanguage = errors.New("語系必須為 zh-TW、en-US 或 ja-JP")
	// ErrInvalidChannelMinSeverity 推送門檻非 low／medium／high；
	// 語義同 language：省略（nil）＝保留舊值，顯式空字串或白名單外都拒
	ErrInvalidChannelMinSeverity = errors.New("推送門檻必須為 low、medium 或 high")
)

// NotificationChannelRequest 通道建立/更新請求（Create 與 Update 欄位相同，共用一個結構）。
// URL 不再 binding 必填：回應已遮罩、前端無從回填，
// Update 時空字串＝沿用既有（與 secret 同語義）；Create 時空 URL 由 validate 擋下
type NotificationChannelRequest struct {
	Name        string `json:"name" binding:"required"`
	Type        string `json:"type"` // 未傳預設 webhook
	URL         string `json:"url"`
	Secret      string `json:"secret"`       // Update 時空字串＝沿用既有（secret 不回傳，前端無從回填）
	ClearSecret bool   `json:"clear_secret"` // Update 時顯式清除簽名（改為不簽名推送）；Create 忽略
	Enabled     *bool  `json:"enabled"`      // 指標區分「未傳」與「false」；未傳預設啟用

	// Language per-channel 語系。指標區分「未傳」
	// 與「顯式空字串」——與 URL/secret 的「空字串＝沿用既有」語義不同：
	// nil＝省略＝Create 預設 zh-TW／Update 保留舊值；非 nil 一律驗證，
	// 空字串或白名單外值都拒（ErrInvalidChannelLanguage），不可能靜默留下非法值
	Language *string `json:"language"`

	// MinSeverity 推送門檻。語義同 Language：nil＝省略＝Create 預設 low／
	// Update 保留舊值（列表的啟用開關只送 name、type、enabled，不得因此重設門檻）；
	// 非 nil 一律驗證，空字串或白名單外都拒（ErrInvalidChannelMinSeverity）
	MinSeverity *string `json:"min_severity"`

	// RiskAcknowledged 傳輸風險確認聲明：
	// warn 檔存 http URL 時必須為 true，聲明入審計
	RiskAcknowledged bool `json:"risk_acknowledged"`
	// Actor* 操作者（handler 從 JWT 填入，比照 CreateAssetRequest.CreatedBy 慣例）
	ActorID   uint   `json:"-"`
	ActorName string `json:"-"`
	ActorIP   string `json:"-"`
}

// ChannelInventoryProvider 的實作在 audit 側（環相依拆解）：介面由 policy
// 宣告、由本型別滿足，方向 audit→policy 單向合法。編譯期斷言寫在此處而非 policy 側，
// 理由同 audit_failure_service.go 的 keyvault.AuditFailureReporter 斷言。
var _ policy.ChannelInventoryProvider = (*NotificationChannelService)(nil)

// NotificationChannelService 通知通道 CRUD 服務。
// secret 與 url 信封加密落庫：url 本身即
// bearer secret（Slack webhook），API 回應一律遮罩、DB 不落明文
type NotificationChannelService struct {
	db *gorm.DB
	// codec 信封加解密。**ColumnCodec**：介面上**沒有**
	// Encrypt(plaintext)，故持有者在**建構上**不可能
	// 寫出無 AAD 的 enc:v 密文。**建構時注入、無 SetCodec 事後覆寫**——
	// 消除「組裝順序錯置時以錯誤 codec 寫出密文」的窗口。
	// nil＝明文直通（僅單測建構路徑，生產組裝一律注入）
	codec crypto.ColumnCodec

	// systemAlerts 通道變更時產生系統告警的交易內落地面。
	// 建構後由組裝根注入；未注入時需要它的路徑回 port.ErrSystemAlertSinkMissing。
	systemAlerts port.SystemAlertSink
	// transmission 傳輸政策閘；nil＝閘不生效
	transmission *policy.TransmissionPolicyService
	// auditTx 通道變更的服務層審計落地面（與變更同交易，寫不進去變更就不成立）。
	// 建構後由組裝根注入；未注入時三個寫入操作回 port.ErrTxSinkMissing。
	auditTx port.TxSink
}

// ChannelActor 通道寫入操作的操作者（審計與系統告警都需要可指認的人）。
type ChannelActor struct {
	ID   uint
	Name string
	IP   string
}

func (r *NotificationChannelRequest) actor() ChannelActor {
	return ChannelActor{ID: r.ActorID, Name: r.ActorName, IP: r.ActorIP}
}

// SetAuditTxSink 注入交易內審計落地面（組裝根）。
func (s *NotificationChannelService) SetAuditTxSink(sink port.TxSink) {
	s.auditTx = sink
}

// NewNotificationChannelService 創建通知通道服務；codec 為 secret/url 的信封
// 加解密器（ColumnCodec），單測可傳 nil＝明文直通
func NewNotificationChannelService(db *gorm.DB, codec crypto.ColumnCodec) *NotificationChannelService {
	return &NotificationChannelService{db: db, codec: codec}
}

// SetSystemAlertSink 注入交易內系統告警落地面（組裝根）。
func (s *NotificationChannelService) SetSystemAlertSink(sink port.SystemAlertSink) {
	s.systemAlerts = sink
}

// SetTransmissionPolicy 注入傳輸政策閘（main 組裝時）
func (s *NotificationChannelService) SetTransmissionPolicy(tp *policy.TransmissionPolicyService) {
	s.transmission = tp
}

// checkTransmissionGate 存檔閘：以「存檔後生效的 URL」判定。
// 通過且屬 warn 確認情境時回傳被確認的風險項，由呼叫端併入同交易的通道審計列
// （URL 屬 secret 不落審計，風險項本身不含網址）
func (s *NotificationChannelService) checkTransmissionGate(effectiveURL string, req *NotificationChannelRequest) ([]policy.RiskItem, error) {
	if s.transmission == nil {
		return nil, nil
	}
	risks := s.transmission.NotifyRisks(effectiveURL)
	if err := s.transmission.CheckSettingSave(policy.TransportChannelNotify, risks, req.RiskAcknowledged); err != nil {
		return nil, err
	}
	if len(risks) > 0 && req.RiskAcknowledged &&
		s.transmission.ChannelLevel(policy.TransportChannelNotify) == policy.TransportLevelWarn {
		return risks, nil
	}
	return nil, nil
}

// channelSettingChange 變更詳情的單筆形狀（沿安全政策端點的 changes[] 慣例）
type channelSettingChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// 通道變更型態（系統告警 change 參數與審計詳情共用）。
const (
	channelChangeCreated  = "created"
	channelChangeUpdated  = "updated"
	channelChangeDisabled = "disabled"
	channelChangeEnabled  = "enabled"
	channelChangeDeleted  = "deleted"
)

// channelAuditDetails 通道變更審計列的詳情。
//
// 不含 secret 與完整網址：網址只以遮罩形出現（保留 scheme、host 與末 4 碼），secret 只記
// 「已設定／已清除」。傳輸風險確認與門檻前後值併在同一列，而不是另寫根 DB 的旁路列。
type channelAuditDetails struct {
	Event            string                 `json:"event"`
	Change           string                 `json:"change"`
	Name             string                 `json:"name"`
	CorrelationID    string                 `json:"correlation_id"`
	Changes          []channelSettingChange `json:"changes"`
	URLBefore        string                 `json:"url_before,omitempty"`
	URLAfter         string                 `json:"url_after,omitempty"`
	TransportRiskAck []policy.RiskItem      `json:"transport_risk_ack,omitempty"`
}

// channelAlertRaiser 系統告警落地面的內部變體：可附加額外目的地快照。
// 公開 port 只有 RaiseInTx；通道變更需要把變更前後的目的地併入，所以組裝根注入的實作
// 必須同時滿足本介面，否則通道寫入回錯（不降級成漏送）。
type channelAlertRaiser interface {
	raise(tx *gorm.DB, ev port.SystemAlertEvent, extra []systemAlertDestination) (port.SystemAlertReceipt, error)
}

var errChannelAlertRaiserUnsupported = errors.New("系統告警落地面不支援附加目的地，通道變更無法產生告警")

func newChannelCorrelationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生關聯識別失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// plainChannel 通道列的明文視圖（只在記憶體內短暫存在，不入審計與回應）。
type plainChannel struct {
	row    model.NotificationChannel
	url    string
	secret string
	// unreadable 網址或密鑰任一解不開：審計與差異仍用解得開的那一欄，
	// 但這一側不作為額外投遞目的地（避免以空密鑰對原本有簽章的端點送出未簽章通知）。
	unreadable bool
}

func (s *NotificationChannelService) plain(ch model.NotificationChannel) (plainChannel, error) {
	u, err := readChannelValue(s.codec, keyvault.RefChannelURL, ch.URL)
	if err != nil {
		return plainChannel{}, fmt.Errorf("解密通道 URL 失敗: %w", err)
	}
	sec, err := readChannelValue(s.codec, keyvault.RefChannelSecret, ch.Secret)
	if err != nil {
		return plainChannel{}, fmt.Errorf("解密通道 secret 失敗: %w", err)
	}
	return plainChannel{row: ch, url: u, secret: sec}, nil
}

// plainOrUnreadable 同 plain，但解不開的欄位以空值繼續：管理員必須能修復或刪除設定壞掉的通道，
// 否則只能進資料庫刪列。網址與密鑰各自解，只有解不開的那一欄當成空值——密鑰壞掉時改網址，
// 審計與告警仍記得到遮罩後的前後網址。原因只記伺服器日誌。
func (s *NotificationChannelService) plainOrUnreadable(ch model.NotificationChannel) plainChannel {
	p := plainChannel{row: ch}
	if u, err := readChannelValue(s.codec, keyvault.RefChannelURL, ch.URL); err != nil {
		log.Printf("[NotificationChannel] 通道 %d（%s）的網址無法解讀，以空值繼續: %v", ch.ID, ch.Name, err)
		p.unreadable = true
	} else {
		p.url = u
	}
	if sec, err := readChannelValue(s.codec, keyvault.RefChannelSecret, ch.Secret); err != nil {
		log.Printf("[NotificationChannel] 通道 %d（%s）的簽章密鑰無法解讀，以空值繼續: %v", ch.ID, ch.Name, err)
		p.unreadable = true
	} else {
		p.secret = sec
	}
	return p
}

// diffChannels 比較變更前後（任一側可為 nil）並回傳欄位差異與變更型態。
// URL 與 secret 以明文比較，但輸出只有遮罩形與「已設定／已清除」。
func diffChannels(before, after *plainChannel) (changes []channelSettingChange, fields []string, kind string) {
	add := func(field, old, new string) {
		changes = append(changes, channelSettingChange{Field: field, Old: old, New: new})
		fields = append(fields, field)
	}
	switch {
	case before == nil && after != nil:
		kind = channelChangeCreated
		add("name", "", after.row.Name)
		add("type", "", after.row.Type)
		add("url", "", maskChannelURL(after.url))
		if after.secret != "" {
			add("secret", "", "set")
		}
		add("enabled", "", strconv.FormatBool(after.row.Enabled))
		add("language", "", after.row.Language)
		add("min_severity", "", after.row.MinSeverity)
		return changes, fields, kind
	case before != nil && after == nil:
		kind = channelChangeDeleted
		add("name", before.row.Name, "")
		add("type", before.row.Type, "")
		add("url", maskChannelURL(before.url), "")
		add("enabled", strconv.FormatBool(before.row.Enabled), "")
		return changes, fields, kind
	}
	if before.row.Name != after.row.Name {
		add("name", before.row.Name, after.row.Name)
	}
	if before.row.Type != after.row.Type {
		add("type", before.row.Type, after.row.Type)
	}
	if before.url != after.url {
		add("url", maskChannelURL(before.url), maskChannelURL(after.url))
	}
	if before.secret != after.secret {
		switch {
		case after.secret == "":
			add("secret", "set", "cleared")
		case before.secret == "":
			add("secret", "unset", "set")
		default:
			add("secret", "set", "set")
		}
	}
	if before.row.Enabled != after.row.Enabled {
		add("enabled", strconv.FormatBool(before.row.Enabled), strconv.FormatBool(after.row.Enabled))
	}
	if before.row.Language != after.row.Language {
		add("language", before.row.Language, after.row.Language)
	}
	if before.row.MinSeverity != after.row.MinSeverity {
		add("min_severity", before.row.MinSeverity, after.row.MinSeverity)
	}
	kind = channelChangeUpdated
	if before.row.Enabled != after.row.Enabled {
		if after.row.Enabled {
			kind = channelChangeEnabled
		} else {
			kind = channelChangeDisabled
		}
	}
	return changes, fields, kind
}

// recordChannelChange 在呼叫方交易內寫服務層審計並產生 notification_channel_changed 系統告警。
// 任一步失敗回錯，由呼叫方讓錯誤逸出交易閉包使整筆回滾。
//
// 告警目的地＝其他啟用通道 ∪ 本通道變更前快照 ∪ 本通道變更後快照（由落地面去重）：
// 停用或刪除時舊目的地仍收到通知，建立即停用的通道也收到「已建立」。
func (s *NotificationChannelService) recordChannelChange(tx *gorm.DB, actor ChannelActor, action model.AuditAction,
	channelID uint, before, after *plainChannel, riskAck []policy.RiskItem) error {
	changes, fields, kind := diffChannels(before, after)
	corr, err := newChannelCorrelationID()
	if err != nil {
		return err
	}
	name := ""
	details := channelAuditDetails{Event: "notification_channel_change", Change: kind, CorrelationID: corr,
		Changes: changes, TransportRiskAck: riskAck}
	if before != nil {
		name = before.row.Name
		details.URLBefore = maskChannelURL(before.url)
	}
	if after != nil {
		name = after.row.Name
		details.URLAfter = maskChannelURL(after.url)
	}
	details.Name = name
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("編碼通道審計詳情失敗: %w", err)
	}
	id := channelID
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		Actor:      gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
		Action:     string(action),
		Resource:   string(model.ResourceNotifyChannel),
		ResourceID: &id,
		Status:     string(model.StatusSuccess),
		Request:    gatewayapi.RequestMeta{ClientIP: actor.IP},
		Details:    string(raw),
	}); err != nil {
		return fmt.Errorf("通道變更審計留痕失敗: %w", err)
	}

	// 沒有任何欄位變動的重複存檔不產生告警（沒有發生值得通知的事）；審計列仍留。
	if kind == channelChangeUpdated && len(changes) == 0 {
		return nil
	}
	// 前後快照直接用已解開的明文；任一欄解不開的一側不作為額外目的地
	// （仍啟用的通道由落地面以「解不開」留下放棄紀錄）。
	var extra []systemAlertDestination
	for _, side := range []*plainChannel{before, after} {
		if side == nil || side.unreadable || side.url == "" {
			continue
		}
		id := side.row.ID
		extra = append(extra, systemAlertDestination{
			Type: side.row.Type, Name: side.row.Name, Language: side.row.Language,
			SourceChannelID: &id, URL: side.url, Secret: side.secret,
		})
	}
	params := map[string]string{"change": kind}
	if kind != channelChangeCreated && kind != channelChangeDeleted && len(fields) > 0 {
		params["changed_fields"] = strings.Join(fields, ",")
	}
	if details.URLBefore != "" {
		params["url_before"] = details.URLBefore
	}
	if details.URLAfter != "" {
		params["url_after"] = details.URLAfter
	}
	ev := port.SystemAlertEvent{
		Type:          port.SystemAlertNotificationChannelChanged,
		Actor:         port.SystemAlertActor{UserID: actor.ID, Username: actor.Name},
		ClientIP:      actor.IP,
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetNotificationChannel, ID: strconv.FormatUint(uint64(channelID), 10)},
		CorrelationID: corr,
		Params:        params,
	}
	if s.systemAlerts == nil {
		return port.ErrSystemAlertSinkMissing
	}
	raiser, ok := s.systemAlerts.(channelAlertRaiser)
	if !ok {
		return errChannelAlertRaiserUnsupported
	}
	if _, err := raiser.raise(tx, ev, extra); err != nil {
		return fmt.Errorf("產生通道變更系統告警失敗: %w", err)
	}
	return nil
}

// sealChannelValue 加密落庫值；codec 未注入時明文直通（單測路徑）。
// ref 為欄位身分（keyvault.RefChannelURL／keyvault.RefChannelSecret），AAD 綁 table|column——
// 故 url 的密文搬到 secret 欄（或反之）即解不開
func sealChannelValue(codec crypto.ColumnCodec, ref crypto.CipherRef, v string) (string, error) {
	if v == "" || codec == nil {
		return v, nil
	}
	return codec.EncryptFor(context.Background(), ref, v)
}

// readChannelValue 讀出明文：信封格式解密；非信封（遷移前殘留或單測明文）原樣回傳。
// **plaintext: true 登記語義不變**（envelopeMigrationTargets：notification_channels
// 的 url／secret 遷移前現值為明文）——非 `enc:` 前綴者一律原樣回傳，不送解密
func readChannelValue(codec crypto.ColumnCodec, ref crypto.CipherRef, v string) (string, error) {
	if v == "" || !crypto.IsEnvelope(v) {
		return v, nil
	}
	if codec == nil {
		return "", errors.New("通道值為信封格式但未注入解密器")
	}
	return codec.DecryptFor(context.Background(), ref, v)
}

// maskChannelURL 遮罩顯示（G8/spec）：保留 scheme+host
// 與末 4 碼，路徑整段以 **** 取代——url 可能整段等同密碼（Slack webhook）
func maskChannelURL(plain string) string {
	parsed, err := url.Parse(plain)
	if err != nil || parsed.Host == "" {
		// 不可解析的殘值不外洩原文
		return "****"
	}
	rest := plain[len(parsed.Scheme)+3+len(parsed.Host):]
	if rest == "" || rest == "/" {
		return parsed.Scheme + "://" + parsed.Host
	}
	tail := rest
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return parsed.Scheme + "://" + parsed.Host + "/****" + tail
}

// toDisplay 轉為 API 回應形（就地）：url 遮罩、has_secret 以儲存值判定
func (s *NotificationChannelService) toDisplay(ch *model.NotificationChannel) error {
	ch.HasSecret = ch.Secret != ""
	plainURL, err := readChannelValue(s.codec, keyvault.RefChannelURL, ch.URL)
	if err != nil {
		// 解不開的 url 不阻列表，以全遮罩呈現（清冊/遷移告警另行提示）
		ch.URL = "****"
		return nil
	}
	// 傳輸偏離標示（3.1）：存量 http 通道誠實標示，不回溯停用
	if s.transmission != nil {
		ch.TransmissionDeviation = len(s.transmission.NotifyRisks(plainURL)) > 0
	}
	ch.URL = maskChannelURL(plainURL)
	return nil
}

// validateChannelURL URL 僅允許 http/https scheme——
// 擋掉 file:// 等非 web 協議與格式錯誤；內網位址首版信任 admin 輸入（design 風險註記）
func validateChannelURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ErrInvalidChannelURL
	}
	return nil
}

// validateChannel Create 用全量驗證（URL 必填）
func validateChannel(req *NotificationChannelRequest) error {
	if req.Type != "" && !model.ValidNotificationChannelType(req.Type) {
		return ErrInvalidChannelTyp
	}
	return validateChannelURL(req.URL)
}

// validateChannelLanguage 語系合法性檢查：嚴格匹配三值，
// 空字串與白名單外一律拒。呼叫端以 *string 是否為 nil 判別「省略」
// （不呼叫本函式、沿用既有語義）與「顯式提供」（呼叫本函式驗證）
func validateChannelLanguage(lang string) error {
	if !model.ValidNotificationChannelLanguage(lang) {
		return ErrInvalidChannelLanguage
	}
	return nil
}

// validateChannelMinSeverity 推送門檻合法性檢查：嚴格匹配 low／medium／high，
// 呼叫端以 *string 是否為 nil 判別省略與顯式提供（同 validateChannelLanguage）
func validateChannelMinSeverity(v string) error {
	if !model.ValidNotificationChannelMinSeverity(v) {
		return ErrInvalidChannelMinSeverity
	}
	return nil
}

// List 列出所有通道（量級個位數到數十，不分頁）；url 一律遮罩
func (s *NotificationChannelService) List() ([]model.NotificationChannel, error) {
	var channels []model.NotificationChannel
	if err := s.db.Order("id ASC").Find(&channels).Error; err != nil {
		return nil, fmt.Errorf("查詢通知通道失敗: %w", err)
	}
	for i := range channels {
		_ = s.toDisplay(&channels[i])
	}
	return channels, nil
}

// getStored 取原始儲存列（內部用，url/secret 為落庫密文）
func (s *NotificationChannelService) getStored(id uint) (*model.NotificationChannel, error) {
	var channel model.NotificationChannel
	if err := s.db.First(&channel, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrChannelNotFound
		}
		return nil, fmt.Errorf("查詢通知通道失敗: %w", err)
	}
	return &channel, nil
}

// GetByID 取得單一通道（API 顯示用；url 遮罩、secret 不外洩）
func (s *NotificationChannelService) GetByID(id uint) (*model.NotificationChannel, error) {
	channel, err := s.getStored(id)
	if err != nil {
		return nil, err
	}
	_ = s.toDisplay(channel)
	return channel, nil
}

// GetForDelivery 取得投遞用通道（url/secret 解密為明文）：僅供測試發送
// 與推送路徑，不得作為 API 回應
func (s *NotificationChannelService) GetForDelivery(id uint) (*model.NotificationChannel, error) {
	channel, err := s.getStored(id)
	if err != nil {
		return nil, err
	}
	plainURL, err := readChannelValue(s.codec, keyvault.RefChannelURL, channel.URL)
	if err != nil {
		return nil, fmt.Errorf("解密通道 URL 失敗: %w", err)
	}
	plainSecret, err := readChannelValue(s.codec, keyvault.RefChannelSecret, channel.Secret)
	if err != nil {
		return nil, fmt.Errorf("解密通道 secret 失敗: %w", err)
	}
	channel.URL = plainURL
	channel.Secret = plainSecret
	channel.HasSecret = plainSecret != ""
	return channel, nil
}

// Create 建立通道；成功後刷新推送快取
func (s *NotificationChannelService) Create(req *NotificationChannelRequest) (*model.NotificationChannel, error) {
	if err := validateChannel(req); err != nil {
		return nil, err
	}
	// language 未給＝預設 zh-TW；顯式提供則驗證
	language := model.NotificationChannelLanguageDefault
	if req.Language != nil {
		if err := validateChannelLanguage(*req.Language); err != nil {
			return nil, err
		}
		language = *req.Language
	}
	minSeverity := model.NotificationChannelMinSeverityDefault
	if req.MinSeverity != nil {
		if err := validateChannelMinSeverity(*req.MinSeverity); err != nil {
			return nil, err
		}
		minSeverity = *req.MinSeverity
	}

	channelType := req.Type
	if channelType == "" {
		channelType = model.NotificationChannelTypeWebhook
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	// slack 不簽名，secret 對其無意義——強制清空使 has_secret 恆 false
	secret := req.Secret
	if channelType == model.NotificationChannelTypeSlack {
		secret = ""
	}
	// 傳輸政策閘：驗證之後、落庫之前
	riskAck, err := s.checkTransmissionGate(req.URL, req)
	if err != nil {
		return nil, err
	}

	sealedURL, err := sealChannelValue(s.codec, keyvault.RefChannelURL, req.URL)
	if err != nil {
		return nil, fmt.Errorf("加密通道 URL 失敗: %w", err)
	}
	sealedSecret, err := sealChannelValue(s.codec, keyvault.RefChannelSecret, secret)
	if err != nil {
		return nil, fmt.Errorf("加密通道 secret 失敗: %w", err)
	}
	channel := model.NotificationChannel{
		Name:        req.Name,
		Type:        channelType,
		URL:         sealedURL,
		Secret:      sealedSecret,
		Enabled:     enabled,
		Language:    language,
		MinSeverity: minSeverity,
	}
	// 寫入、服務層審計與系統告警同一個交易：任一步失敗整筆回滾，推送快取不重載。
	//
	// `Enabled` 欄帶 default:true，而 GORM 對帶 default 的欄位遇零值會改用預設值
	// ——直接 Create 會讓「建立時就停用」靜默變成啟用、照常推送。落庫後在同一交易內
	// 補寫請求值（沿 rotation_report_schedule_service.Create 的作法）
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&channel).Error; err != nil {
			return fmt.Errorf("建立通知通道失敗: %w", err)
		}
		if !enabled {
			channel.Enabled = false
			if err := tx.Model(&model.NotificationChannel{}).Where("id = ?", channel.ID).
				Update("enabled", false).Error; err != nil {
				return fmt.Errorf("建立通知通道失敗: %w", err)
			}
		}
		after, perr := s.plain(channel)
		if perr != nil {
			return perr
		}
		return s.recordChannelChange(tx, req.actor(), model.ActionCreate, channel.ID, nil, &after, riskAck)
	}); err != nil {
		return nil, err
	}

	_ = s.toDisplay(&channel)
	ReloadAlertNotifier()
	return &channel, nil
}

// Update 更新通道；成功後刷新推送快取。
// url 空字串＝沿用既有（G8：回應已遮罩，前端無從回填，
// 語義與 secret 一致），有帶值才驗證、加密、落庫
func (s *NotificationChannelService) Update(id uint, req *NotificationChannelRequest) (*model.NotificationChannel, error) {
	if req.Type != "" && !model.ValidNotificationChannelType(req.Type) {
		return nil, ErrInvalidChannelTyp
	}
	if req.URL != "" {
		if err := validateChannelURL(req.URL); err != nil {
			return nil, err
		}
	}
	// language：nil＝省略＝保留舊值；非 nil 一律驗證（空字串或白名單外都拒）
	if req.Language != nil {
		if err := validateChannelLanguage(*req.Language); err != nil {
			return nil, err
		}
	}
	// min_severity：同 language 語義（nil＝保留；啟用開關不帶此欄）
	if req.MinSeverity != nil {
		if err := validateChannelMinSeverity(*req.MinSeverity); err != nil {
			return nil, err
		}
	}

	channel, err := s.getStored(id)
	if err != nil {
		return nil, err
	}

	// 傳輸政策閘：以存檔後生效的 URL 判定——
	// 未帶 URL＝沿用既有（解密評估；解不開的殘留列跳過閘，缺陷已由列表全遮罩呈現）。
	// 存量不安全通道不被回溯停用，但「再次存檔」即受閘（spec 場景鎖定此語義）
	effectiveURL := req.URL
	if effectiveURL == "" {
		if plain, readErr := readChannelValue(s.codec, keyvault.RefChannelURL, channel.URL); readErr == nil {
			effectiveURL = plain
		}
	}
	riskAck, err := s.checkTransmissionGate(effectiveURL, req)
	if err != nil {
		return nil, err
	}

	updates := map[string]interface{}{
		"name": req.Name,
	}
	if req.URL != "" {
		sealedURL, err := sealChannelValue(s.codec, keyvault.RefChannelURL, req.URL)
		if err != nil {
			return nil, fmt.Errorf("加密通道 URL 失敗: %w", err)
		}
		updates["url"] = sealedURL
	}
	if req.Type != "" {
		updates["type"] = req.Type
	}
	// 更新後的生效類型（未帶 type 則沿用既有）決定 secret 處理
	effectiveType := channel.Type
	if req.Type != "" {
		effectiveType = req.Type
	}
	// slack 恆無 secret（含 webhook→slack 轉換時清掉殘留）；
	// webhook 則：空字串＝沿用既有（secret 不回傳、編輯表單無從回填，避免任何編輯靜默清空），
	// clear_secret＝顯式清除
	switch {
	case effectiveType == model.NotificationChannelTypeSlack:
		updates["secret"] = ""
	case req.ClearSecret:
		updates["secret"] = ""
	case req.Secret != "":
		sealedSecret, err := sealChannelValue(s.codec, keyvault.RefChannelSecret, req.Secret)
		if err != nil {
			return nil, fmt.Errorf("加密通道 secret 失敗: %w", err)
		}
		updates["secret"] = sealedSecret
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.Language != nil {
		updates["language"] = *req.Language
	}
	if req.MinSeverity != nil {
		updates["min_severity"] = *req.MinSeverity
	}

	// 讀前列、更新、審計與系統告警同一個交易：任一步失敗整筆回滾，推送快取不重載
	var stored model.NotificationChannel
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		// 變更前快照在交易內讀（PostgreSQL 加列鎖）：兩人同時改同一通道時，
		// 後者的「變更前」是前者提交後的值，實際的前一個目的地才會收到通知。
		// 解不開的通道仍可修復。
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = tx.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var current model.NotificationChannel
		if err := q.First(&current, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrChannelNotFound
			}
			return fmt.Errorf("查詢通知通道失敗: %w", err)
		}
		before := s.plainOrUnreadable(current)
		if err := tx.Model(&model.NotificationChannel{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return fmt.Errorf("更新通知通道失敗: %w", err)
		}
		if err := tx.First(&stored, id).Error; err != nil {
			return fmt.Errorf("讀回通知通道失敗: %w", err)
		}
		after := s.plainOrUnreadable(stored)
		return s.recordChannelChange(tx, req.actor(), model.ActionUpdate, id, &before, &after, riskAck)
	}); err != nil {
		return nil, err
	}

	// 回應用落庫後的列（沿用時保留的舊值已隨讀回一併呈現）
	result := stored
	_ = s.toDisplay(&result)
	ReloadAlertNotifier()
	return &result, nil
}

// Delete 刪除通道；成功後刷新推送快取。
// 刪除前的快照併入告警目的地，故舊目的地在通道列已不存在之後仍會收到「已刪除」通知。
func (s *NotificationChannelService) Delete(id uint, actor ChannelActor) error {
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		var row model.NotificationChannel
		if err := tx.First(&row, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrChannelNotFound
			}
			return fmt.Errorf("查詢通知通道失敗: %w", err)
		}
		// 解不開的通道也要能刪。
		before := s.plainOrUnreadable(row)
		res := tx.Delete(&model.NotificationChannel{}, id)
		if res.Error != nil {
			return fmt.Errorf("刪除通知通道失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrChannelNotFound
		}
		return s.recordChannelChange(tx, actor, model.ActionDelete, id, &before, nil, nil)
	}); err != nil {
		return err
	}

	ReloadAlertNotifier()
	return nil
}
