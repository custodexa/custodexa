package audit

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 通知送出的 HTTP client 與轉址規則。
//
// 投遞程序、測試發送與稽核失效的直接送出三條路徑都經 newNotificationHTTPClient 取得 client，
// 轉址規則依型別描述的 FollowRedirects 決定（守衛 TestNotificationHTTPClientsUseSharedRedirect 核對
// 本套件非測試檔的每個 http.Client 字面量都出自這裡）：
//   - 不跟隨（slack_app）：回傳最後一個回應，3xx 由呼叫端判為單筆失敗。授權標頭原樣帶 token，
//     同主機轉址時標準函式庫會照帶，所以一律不跟隨。
//   - 跟隨（webhook、slack）：每一跳檢查「前一跳 https 而這一跳 http」與「這一跳的傳輸風險項
//     必須是保存網址風險項的子集合」，不通過就停止、不送出那一跳；最多跟隨 notifyRedirectMax 次；
//     通過後移除 Referer，轉址目的地拿不到前一跳的網址。

// notifyRedirectMax 跟隨轉址的次數上限。
const notifyRedirectMax = 5

var (
	// errRedirectPolicy 轉址目的地不符傳輸政策（單筆失敗）。
	errRedirectPolicy = errors.New("轉址目的地不符傳輸政策")
	// errRedirectTooMany 轉址次數過多（單筆失敗）。
	errRedirectTooMany = errors.New("轉址次數過多")
)

// notifyRedirectNotFollowedText 不跟隨轉址的型別收到 3xx 時記錄的原因。
const notifyRedirectNotFollowedText = "HTTP 3xx（不跟隨轉址）"

// notifyRiskEvaluator 傳輸政策對通知網址的風險判定（TransmissionPolicyService 滿足此介面）。
type notifyRiskEvaluator interface {
	NotifyRisks(url string) []model.TransmissionRisk
}

var (
	notifyRiskMu      sync.RWMutex
	notifyRiskDefault notifyRiskEvaluator
)

// SetNotificationTransmissionPolicy 注入轉址逐跳檢查所用的傳輸政策（組裝根呼叫一次；nil＝只檢查 https 降為 http）。
func SetNotificationTransmissionPolicy(p notifyRiskEvaluator) {
	notifyRiskMu.Lock()
	notifyRiskDefault = p
	notifyRiskMu.Unlock()
}

func currentNotifyRiskEvaluator() notifyRiskEvaluator {
	notifyRiskMu.RLock()
	defer notifyRiskMu.RUnlock()
	return notifyRiskDefault
}

// newNotificationHTTPClient 依型別產生送出用的 client。savedURL 是通道保存的網址（風險項比較的基準）；
// risks 為 nil 時取組裝根注入的傳輸政策；transport 為 nil 時用預設傳輸。
func newNotificationHTTPClient(destType, savedURL string, timeout time.Duration, risks notifyRiskEvaluator, transport http.RoundTripper) *http.Client {
	if risks == nil {
		risks = currentNotifyRiskEvaluator()
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: notificationCheckRedirect(destType, savedURL, risks),
	}
}

// notificationCheckRedirect 依型別產生 CheckRedirect（見檔頭）。型別不在登錄中時不跟隨。
func notificationCheckRedirect(destType, savedURL string, risks notifyRiskEvaluator) func(req *http.Request, via []*http.Request) error {
	desc, ok := ChannelType(destType)
	if !ok || !desc.FollowRedirects {
		return func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > notifyRedirectMax {
			return errRedirectTooMany
		}
		if len(via) > 0 {
			prev := via[len(via)-1]
			if strings.EqualFold(prev.URL.Scheme, "https") && strings.EqualFold(req.URL.Scheme, "http") {
				return errRedirectPolicy
			}
		}
		if risks != nil && !riskSubset(risks.NotifyRisks(req.URL.String()), risks.NotifyRisks(savedURL)) {
			return errRedirectPolicy
		}
		req.Header.Del("Referer")
		return nil
	}
}

// riskSubset hop 的風險項是否都出現在 saved 之中（以風險項的識別比較集合包含，不比筆數）。
func riskSubset(hop, saved []model.TransmissionRisk) bool {
	allowed := make(map[string]bool, len(saved))
	for _, r := range saved {
		allowed[r.Key] = true
	}
	for _, r := range hop {
		if !allowed[r.Key] {
			return false
		}
	}
	return true
}

// redirectFailureText 送出錯誤若是轉址規則擋下的，回傳固定原因；否則回空字串。
func redirectFailureText(err error) string {
	switch {
	case errors.Is(err, errRedirectPolicy):
		return errRedirectPolicy.Error()
	case errors.Is(err, errRedirectTooMany):
		return errRedirectTooMany.Error()
	default:
		return ""
	}
}
