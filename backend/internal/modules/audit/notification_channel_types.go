package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 通知通道型別登錄。
//
// 每個型別一個描述：設定欄位、能力、每個目的地每秒送出上限，以及三個函式（驗證設定、從共通內容產生請求、
// 解讀回應）。投遞程序、測試發送與通道服務只經描述操作，不以型別字面分支；型別常數在本套件的非測試檔中
// 只准出現在本檔（守衛 TestChannelTypeLiteralsOnlyInRegistry）。新增型別＝在 channelTypeRegistry 加一個描述、
// migration 擴充兩條型別約束、前端表單加選項（守衛 TestChannelTypeRegistryMatchesConstraintsAndForm 核對三者）。

// ChannelSecretKind 秘密欄位的種類。
type ChannelSecretKind string

const (
	// ChannelSecretNone 這個型別沒有秘密；寫入時一律清空。
	ChannelSecretNone ChannelSecretKind = "none"
	// ChannelSecretSigningKey 簽章密鑰：只用來對本文算 HMAC，本身不出站。
	ChannelSecretSigningKey ChannelSecretKind = "signing_key"
	// ChannelSecretBearerToken 機器人 token：原樣放在授權標頭送出。
	ChannelSecretBearerToken ChannelSecretKind = "bearer_token"
)

// ChannelFields 型別的設定欄位。
type ChannelFields struct {
	// NeedsURL 是否需要網址（三個型別都需要；slack_app 的網址是 Slack API 基準網址）。
	NeedsURL bool
	// DefaultURL 建立時未填網址可帶入的預設值（空字串＝沒有預設值）。
	DefaultURL string
	// NeedsTarget 是否需要目標（slack_app 的頻道識別碼）。
	NeedsTarget bool
	// Secret 秘密的種類；SecretRequired 是否必填。
	Secret         ChannelSecretKind
	SecretRequired bool
}

// ChannelCapabilities 型別的能力宣告。
type ChannelCapabilities struct {
	// CanTargetUser 能否以個人為對象投遞（對個人派送只能在宣告此能力的型別上開啟；描述須同時提供 lookupUser）。
	CanTargetUser bool
	// SupportsLinks 能否帶可點的連結。
	SupportsLinks bool
	// SignsBody 有簽章密鑰時是否附本文簽章標頭。
	SignsBody bool
	// RendersText 是否依通道語系渲染文字（否＝送結構化 JSON）。
	RendersText bool
}

// ChannelDestination 一次送出的目的地（通道當下的設定或帶快照紀錄的快照）。
type ChannelDestination struct {
	Type     string
	URL      string
	Secret   string
	Target   string
	Language string
}

// OutboundMessage 已渲染的一則通知：渲染文字的型別取 Text，送結構化 JSON 的型別取 JSON。
type OutboundMessage struct {
	Text string
	JSON []byte
}

// DeliveryResult 一次送出的結果判讀。
type DeliveryResult struct {
	// Status HTTP 狀態碼（連線錯誤時為 0）。
	Status int
	// PlatformError 平台回報的錯誤碼（已淨化：只含 [a-z0-9_]、最長 64 字元，否則為 unparseable_response）。
	PlatformError string
	// RetryAfter 回應的 Retry-After 標頭原文（判讀與上限由投遞程序依規則處理）。
	RetryAfter string
}

// OK 回應是否判為成功。
func (r DeliveryResult) OK() bool {
	return r.Status >= 200 && r.Status < 300 && r.PlatformError == ""
}

// ChannelTypeDescriptor 一個通道型別的描述。
type ChannelTypeDescriptor struct {
	Key string
	// NameKey、HelpKey 前端三語詞條的鍵（名稱與說明）。
	NameKey string
	HelpKey string
	Fields  ChannelFields
	Caps    ChannelCapabilities
	// MaxPerSecond 每個目的地每秒送出上限；0＝不宣告、不節流。它是收件對象為通道（audience channel）時的上限；
	// 其他收件對象的上限宣告在 MaxPerSecondByAudience（沒有宣告時沿用本值）。
	MaxPerSecond float64
	// MaxPerSecondByAudience 依收件對象分別宣告的每秒上限（slack_app 的個人訊息另受查詢方法的速率約束）。
	MaxPerSecondByAudience map[string]float64
	// FollowRedirects 送出時是否跟隨轉址。跟隨時每一跳都要通過傳輸政策檢查（notificationCheckRedirect）；
	// 不跟隨時 3xx 判為單筆失敗。
	FollowRedirects bool

	validate   func(dest ChannelDestination) error
	buildBody  func(dest ChannelDestination, msg OutboundMessage) ([]byte, error)
	decorate   func(req *http.Request, dest ChannelDestination, body []byte)
	readResult func(resp *http.Response) DeliveryResult
	// requestURL 由保存的網址算出實際送出的網址（nil＝原樣送出）。
	requestURL func(saved string) string
	// lookupUser 以電子郵件查平台帳號的請求（CanTargetUser 的型別才有）；readLookup 判讀其回應。
	lookupUser func(dest ChannelDestination, email string) (*http.Request, error)
	readLookup func(resp *http.Response) UserLookupResult
}

// UserLookupResult 以電子郵件查平台帳號的結果判讀。
type UserLookupResult struct {
	// Status HTTP 狀態碼。
	Status int
	// PlatformError 平台錯誤碼（已淨化，規則同 DeliveryResult.PlatformError）。
	PlatformError string
	// RetryAfter 回應的 Retry-After 標頭原文。
	RetryAfter string
	// UserID 查到的平台使用者識別碼（只含英數字、最長 64 字元，否則為空）。
	UserID string
	// Deleted、IsBot 平台回報該帳號已停用、是機器人。
	Deleted bool
	IsBot   bool
	// DisplayName 平台上的顯示名稱（已淨化、限長；只給「傳給我自己」回報請求者本人）。
	DisplayName string
}

// NewLookupRequest 以電子郵件查平台帳號的請求；型別沒有這項能力時回錯。電子郵件放在請求本文，不放在網址。
func (d ChannelTypeDescriptor) NewLookupRequest(dest ChannelDestination, email string) (*http.Request, error) {
	if d.lookupUser == nil {
		return nil, fmt.Errorf("通道型別 %q 不能以個人為對象", d.Key)
	}
	return d.lookupUser(dest, email)
}

// ReadLookupResult 判讀以電子郵件查平台帳號的回應；回應本文最多讀 channelResponseReadLimit 位元組。
func (d ChannelTypeDescriptor) ReadLookupResult(resp *http.Response) UserLookupResult {
	if d.readLookup == nil {
		return UserLookupResult{Status: resp.StatusCode, PlatformError: platformErrorUnparseable}
	}
	return d.readLookup(resp)
}

// Validate 驗證這個型別的設定（網址格式與傳輸政策另由通道服務檢查）。
func (d ChannelTypeDescriptor) Validate(dest ChannelDestination) error {
	if d.validate == nil {
		return nil
	}
	return d.validate(dest)
}

// BuildBody 從已渲染的通知產生這個型別的請求本文。
func (d ChannelTypeDescriptor) BuildBody(dest ChannelDestination, msg OutboundMessage) ([]byte, error) {
	body, err := d.buildBody(dest, msg)
	if err != nil {
		return nil, fmt.Errorf("組出請求本文失敗: %w", err)
	}
	return body, nil
}

// BuildRequest 從已渲染的通知產生 HTTP 請求。
func (d ChannelTypeDescriptor) BuildRequest(dest ChannelDestination, msg OutboundMessage) (*http.Request, error) {
	body, err := d.BuildBody(dest, msg)
	if err != nil {
		return nil, err
	}
	return d.NewRequest(dest, body)
}

// NewRequest 以已組好的本文產生 HTTP 請求（標頭、簽章或授權由型別決定）。
func (d ChannelTypeDescriptor) NewRequest(dest ChannelDestination, body []byte) (*http.Request, error) {
	target := dest.URL
	if d.requestURL != nil {
		target = d.requestURL(dest.URL)
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("建立請求失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if d.decorate != nil {
		d.decorate(req, dest, body)
	}
	return req, nil
}

// ReadResult 判讀回應；回應本文最多讀 channelResponseReadLimit 位元組。
func (d ChannelTypeDescriptor) ReadResult(resp *http.Response) DeliveryResult {
	if d.readResult == nil {
		return readStatusOnly(resp)
	}
	return d.readResult(resp)
}

// channelResponseReadLimit 回應本文的讀取上限（網址可改寫，回應由對方控制）。
const channelResponseReadLimit = 64 << 10

// slackDefaultAPIURL slack_app 的預設網址：Slack Web API 的基底，送出時接上方法名。
// 同一個基底供其他 Web API 方法共用。
const slackDefaultAPIURL = "https://slack.com/api"

// slackPostMessageMethod 送訊息使用的 Web API 方法名。
const slackPostMessageMethod = "chat.postMessage"

// slackLookupByEmailMethod 以電子郵件查使用者的 Web API 方法名（權限 users:read.email）。
const slackLookupByEmailMethod = "users.lookupByEmail"

// slackLookupPerMinute 查詢方法的速率等級（Tier 3）每分鐘次數。個人訊息每一則至多查一次，
// 所以個人訊息這一組的每秒上限取這個值除以 60，查詢與送訊息都不超過官方速率。
const slackLookupPerMinute = 50

// slackMethodURL 由保存的基底網址算出某個方法的網址。保存的網址已以該方法名結尾時（早期建立的通道
// 保存的是完整方法網址）原樣使用，不重複接上。查詢字串與片段不在網址設定的預期內，原樣保留在路徑之後。
func slackMethodURL(saved, method string) string {
	u, err := url.Parse(saved)
	if err != nil {
		return saved
	}
	path := strings.TrimRight(u.Path, "/")
	if strings.HasSuffix(path, "/"+method) {
		return saved
	}
	u.Path = path + "/" + method
	u.RawPath = ""
	return u.String()
}

// slackTargetMaxLen 頻道識別碼的長度上限。
const slackTargetMaxLen = 64

var (
	slackTargetPattern   = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	platformErrorPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// platformErrorUnparseable 平台錯誤碼不合格或無法解析時落庫的值。
const platformErrorUnparseable = "unparseable_response"

var channelTypeRegistry = map[string]ChannelTypeDescriptor{
	model.NotificationChannelTypeWebhook: {
		Key:             model.NotificationChannelTypeWebhook,
		NameKey:         "alerts.channelTypeWebhook",
		HelpKey:         "alerts.channelTypeWebhookHelp",
		Fields:          ChannelFields{NeedsURL: true, Secret: ChannelSecretSigningKey},
		Caps:            ChannelCapabilities{SupportsLinks: true, SignsBody: true},
		FollowRedirects: true,
		buildBody: func(_ ChannelDestination, msg OutboundMessage) ([]byte, error) {
			if msg.JSON == nil {
				return nil, errors.New("webhook 需要結構化本文")
			}
			return msg.JSON, nil
		},
		decorate: func(req *http.Request, dest ChannelDestination, body []byte) {
			if dest.Secret != "" {
				req.Header.Set(signatureHeaderKey, signBody(dest.Secret, body))
			}
		},
	},
	model.NotificationChannelTypeSlack: {
		Key:             model.NotificationChannelTypeSlack,
		NameKey:         "alerts.channelTypeSlack",
		HelpKey:         "alerts.channelTypeSlackHelp",
		Fields:          ChannelFields{NeedsURL: true, Secret: ChannelSecretNone},
		Caps:            ChannelCapabilities{SupportsLinks: true, RendersText: true},
		FollowRedirects: true,
		buildBody:       buildSlackWebhookBody,
	},
	model.NotificationChannelTypeSlackApp: {
		Key:                    model.NotificationChannelTypeSlackApp,
		NameKey:                "alerts.channelTypeSlackApp",
		HelpKey:                "alerts.channelTypeSlackAppHelp",
		Fields:                 ChannelFields{NeedsURL: true, DefaultURL: slackDefaultAPIURL, NeedsTarget: true, Secret: ChannelSecretBearerToken, SecretRequired: true},
		Caps:                   ChannelCapabilities{CanTargetUser: true, SupportsLinks: true, RendersText: true},
		MaxPerSecond:           1,
		MaxPerSecondByAudience: map[string]float64{model.NotificationAudienceUser: float64(slackLookupPerMinute) / 60},
		validate:               validateSlackAppDestination,
		buildBody:              buildSlackAppBody,
		decorate: func(req *http.Request, dest ChannelDestination, _ []byte) {
			req.Header.Set("Authorization", "Bearer "+dest.Secret)
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		},
		readResult: readSlackAppResult,
		requestURL: func(saved string) string { return slackMethodURL(saved, slackPostMessageMethod) },
		lookupUser: newSlackLookupRequest,
		readLookup: readSlackLookupResult,
	},
}

func init() {
	for key := range channelTypeRegistry {
		model.RegisterNotificationChannelType(key)
	}
}

// channelTypeDefault 建立通道時未給型別的預設值。
const channelTypeDefault = model.NotificationChannelTypeWebhook

// ChannelType 取型別描述；不在登錄中回 ok=false。
func ChannelType(key string) (ChannelTypeDescriptor, bool) {
	d, ok := channelTypeRegistry[key]
	return d, ok
}

// ChannelTypeKeys 登錄的全部型別鍵（排序後）。
func ChannelTypeKeys() []string {
	out := make([]string, 0, len(channelTypeRegistry))
	for k := range channelTypeRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// slackTextBody Slack 兩型共用的文字本文成分：關閉連結與媒體的自動抓取。
type slackTextBody struct {
	Channel     string `json:"channel,omitempty"`
	Text        string `json:"text"`
	UnfurlLinks bool   `json:"unfurl_links"`
	UnfurlMedia bool   `json:"unfurl_media"`
}

func buildSlackWebhookBody(_ ChannelDestination, msg OutboundMessage) ([]byte, error) {
	return json.Marshal(slackTextBody{Text: msg.Text})
}

func buildSlackAppBody(dest ChannelDestination, msg OutboundMessage) ([]byte, error) {
	if dest.Target == "" {
		return nil, errors.New("slack_app 缺少目標頻道")
	}
	return json.Marshal(slackTextBody{Channel: dest.Target, Text: msg.Text})
}

// 設定驗證的錯誤（通道服務以 errors.Is 轉成 400 的機器碼）。
var (
	ErrInvalidChannelTarget = errors.New("頻道識別碼須為 1 到 64 個英數字")
	ErrInvalidChannelSecret = errors.New("機器人 token 須以 xoxb- 開頭且不含空白")
)

// validateSlackAppDestination token（有給時）以 xoxb- 開頭、無空白；目標非空、限英數字與長度。
// token 是否必填由通道服務依 Fields.SecretRequired 判斷（更新時空值代表沿用）。
func validateSlackAppDestination(dest ChannelDestination) error {
	if dest.Target == "" || len(dest.Target) > slackTargetMaxLen || !slackTargetPattern.MatchString(dest.Target) {
		return ErrInvalidChannelTarget
	}
	if dest.Secret != "" && (!strings.HasPrefix(dest.Secret, "xoxb-") || strings.ContainsAny(dest.Secret, " \t\r\n")) {
		return ErrInvalidChannelSecret
	}
	return nil
}

// readStatusOnly 只看 HTTP 狀態；排空最多 channelResponseReadLimit 位元組以利連線重用。
func readStatusOnly(resp *http.Response) DeliveryResult {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, channelResponseReadLimit))
	return DeliveryResult{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
}

// readSlackAppResult HTTP 狀態不是 2xx，或本文的 ok 不是 true，都判為失敗並記錄淨化後的平台錯誤碼。
func readSlackAppResult(resp *http.Response) DeliveryResult {
	out := DeliveryResult{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, channelResponseReadLimit))
	var parsed struct {
		OK    *bool  `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.OK == nil {
		out.PlatformError = platformErrorUnparseable
		return out
	}
	if !*parsed.OK {
		out.PlatformError = sanitizePlatformError(parsed.Error)
	}
	return out
}

// newSlackLookupRequest users.lookupByEmail 的請求：以表單本文帶電子郵件（不進網址與存取紀錄），授權標頭帶 token。
func newSlackLookupRequest(dest ChannelDestination, email string) (*http.Request, error) {
	form := url.Values{"email": {email}}.Encode()
	req, err := http.NewRequest(http.MethodPost, slackMethodURL(dest.URL, slackLookupByEmailMethod), strings.NewReader(form))
	if err != nil {
		return nil, fmt.Errorf("建立請求失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+dest.Secret)
	return req, nil
}

// slackUserIDPattern 平台使用者識別碼的形狀。
var slackUserIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// slackDisplayNameMax 回報給請求者本人的顯示名稱長度上限（字元）。
const slackDisplayNameMax = 80

// readSlackLookupResult 判讀 users.lookupByEmail 的回應：ok 不是 true 時記淨化後的錯誤碼；ok 為 true 時取使用者
// 識別碼、停用與機器人旗標、顯示名稱。回應不回顯到任何紀錄。
func readSlackLookupResult(resp *http.Response) UserLookupResult {
	out := UserLookupResult{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, channelResponseReadLimit))
	var parsed struct {
		OK    *bool  `json:"ok"`
		Error string `json:"error"`
		User  *struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			RealName string `json:"real_name"`
			Deleted  bool   `json:"deleted"`
			IsBot    bool   `json:"is_bot"`
			Profile  struct {
				DisplayName string `json:"display_name"`
				RealName    string `json:"real_name"`
			} `json:"profile"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.OK == nil {
		out.PlatformError = platformErrorUnparseable
		return out
	}
	if !*parsed.OK {
		out.PlatformError = sanitizePlatformError(parsed.Error)
		return out
	}
	if parsed.User == nil || !slackUserIDPattern.MatchString(parsed.User.ID) {
		out.PlatformError = platformErrorUnparseable
		return out
	}
	out.UserID = parsed.User.ID
	out.Deleted, out.IsBot = parsed.User.Deleted, parsed.User.IsBot
	for _, n := range []string{parsed.User.Profile.DisplayName, parsed.User.Profile.RealName, parsed.User.RealName, parsed.User.Name} {
		if n = strings.TrimSpace(n); n != "" {
			out.DisplayName = truncateRunes(sanitizeDisplayName(n), slackDisplayNameMax)
			break
		}
	}
	return out
}

// sanitizePlatformError 平台錯誤碼只留 [a-z0-9_]、最長 64 字元；不合格記成 unparseable_response。
func sanitizePlatformError(code string) string {
	if platformErrorPattern.MatchString(code) {
		return code
	}
	return platformErrorUnparseable
}

// sendToDestination 依型別描述送出一則已渲染的通知並判讀回應；err 只在無法送出（請求建立失敗或連線錯誤）時非空。
func sendToDestination(client *http.Client, dest ChannelDestination, msg OutboundMessage) (DeliveryResult, error) {
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return DeliveryResult{}, fmt.Errorf("通道型別 %q 不在登錄中", dest.Type)
	}
	req, err := desc.BuildRequest(dest, msg)
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

// destinationFromChannel 通道列（明文）轉成目的地。型別為空的通道列（資料表預設值之前建立的記憶體物件、
// 單元測試）視為預設型別，與資料表的欄位預設值一致。
func destinationFromChannel(ch *model.NotificationChannel) ChannelDestination {
	t := ch.Type
	if t == "" {
		t = channelTypeDefault
	}
	return ChannelDestination{Type: t, URL: ch.URL, Secret: ch.Secret, Target: ch.Target, Language: ch.Language}
}

// channelRendersText 通道型別是否渲染文字；不在登錄中視為否（送結構化本文）。
func channelRendersText(channelType string) bool {
	d, ok := ChannelType(channelType)
	return ok && d.Caps.RendersText
}

// buildRenderedBody 依型別把已渲染的通知組成請求本文；型別不在登錄中回錯。
func buildRenderedBody(channelType string, dest ChannelDestination, msg OutboundMessage) ([]byte, error) {
	desc, ok := ChannelType(channelType)
	if !ok {
		return nil, fmt.Errorf("通道型別 %q 不在登錄中", channelType)
	}
	return desc.BuildBody(dest, msg)
}

// channelSecretKind 型別的秘密種類；不在登錄中視為沒有秘密（不保存任何秘密）。
func channelSecretKind(channelType string) ChannelSecretKind {
	d, ok := ChannelType(channelType)
	if !ok {
		return ChannelSecretNone
	}
	return d.Fields.Secret
}
