package audit

import (
	"errors"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
	"unicode"
)

// 通知連結的對外基準網址。
//
// 沿用部署設定 PUBLIC_BASE_URL（與 OIDC 同一個設定值）；這裡的驗證只決定「通知要不要附連結」，
// 不改 OIDC 對同一設定的判讀。不合格視同未設定（記一行警告），通知照常送出、不附連結。

var notificationBaseURL atomic.Value // string：已驗證、去掉尾端斜線的基準網址；空字串＝不附連結

// errNotificationBaseURL 基準網址不合格的原因（只進伺服器日誌，不含設定值本身）。
var (
	errBaseURLScheme   = errors.New("須為 http 或 https")
	errBaseURLHost     = errors.New("缺少主機名稱")
	errBaseURLUserinfo = errors.New("不得帶使用者資訊")
	errBaseURLQuery    = errors.New("不得帶查詢字串")
	errBaseURLFragment = errors.New("不得帶片段")
	errBaseURLChars    = errors.New("不得含空白、控制字元或 < > |")
)

// ParseNotificationBaseURL 驗證對外基準網址並回傳去掉尾端斜線的形式；空字串回空字串與 nil。
// 規則：http 或 https、有主機名稱；不得帶使用者資訊、查詢字串或片段；不得含空白、控制字元或
// `<`、`>`、`|`（會弄壞 Slack 的 `<網址|文字>` 語法）；可帶路徑前綴。
func ParseNotificationBaseURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '<' || r == '>' || r == '|' {
			return "", errBaseURLChars
		}
	}
	if strings.Contains(raw, "#") {
		return "", errBaseURLFragment
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errBaseURLScheme
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errBaseURLScheme
	}
	if u.User != nil {
		return "", errBaseURLUserinfo
	}
	if u.Hostname() == "" {
		return "", errBaseURLHost
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", errBaseURLQuery
	}
	if u.Fragment != "" {
		return "", errBaseURLFragment
	}
	return strings.TrimRight(raw, "/"), nil
}

// SetNotificationBaseURL 設定通知連結的基準網址（啟動時呼叫一次；之後的投遞以當下的值組成完整網址）。
// 不合格時視同未設定並記一行警告，回傳該錯誤供呼叫端判斷。
func SetNotificationBaseURL(raw string) error {
	base, err := ParseNotificationBaseURL(strings.TrimSpace(raw))
	if err != nil {
		log.Printf("[Notification] 對外基準網址不合格（%v），通知不附連結", err)
		notificationBaseURL.Store("")
		return err
	}
	notificationBaseURL.Store(base)
	return nil
}

// currentNotificationBaseURL 目前的基準網址；未設定或不合格時為空字串。
func currentNotificationBaseURL() string {
	v, _ := notificationBaseURL.Load().(string)
	return v
}

// composeNotificationLink 以當下的基準網址接上站內路徑；基準網址或路徑任一為空時回空字串（不附連結）。
func composeNotificationLink(path string) string {
	base := currentNotificationBaseURL()
	if base == "" || path == "" || !strings.HasPrefix(path, "/") {
		return ""
	}
	return base + path
}
