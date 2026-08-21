package sourceip

// 唯一實作的行為釘（audit-coverage-closure 批 8）。
//
// cmd/server 的 AST 守衛只保證「沒有人繞過本包」，不保證**本包自己**做對。
// 這兩件事必須各有釘子：把 From 改成無條件回 `c.ClientIP()`，AST 守衛照樣全綠。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	spoofValue = "198.51.100.77" // 攻擊者想寫進審計列的位址
	peerAddr   = "192.0.2.1"     // socket 對端（httptest 預設）
)

// spoofHeaders 六種由請求方控制的來源位址標頭
var spoofHeaders = map[string]string{
	"X-Forwarded-For":  spoofValue,
	"X-Real-IP":        spoofValue,
	"Forwarded":        "for=" + spoofValue,
	"True-Client-IP":   spoofValue,
	"CF-Connecting-IP": spoofValue,
	"X-Client-IP":      spoofValue,
}

// spoofedContext 造一個帶六種偽造標頭的 gin.Context。
//
// trustedProxy 為真時把 socket 對端登記為 engine 的可信代理——`c.ClientIP()` 是否
// 採信標頭由 engine 判定，只設旗標而不設 engine 的話反向格會因錯誤的理由通過。
func spoofedContext(t *testing.T, trustedProxy bool) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	if trustedProxy {
		if err := engine.SetTrustedProxies([]string{peerAddr}); err != nil {
			t.Fatalf("SetTrustedProxies: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	for k, v := range spoofHeaders {
		req.Header.Set(k, v)
	}
	c := gin.CreateTestContextOnly(httptest.NewRecorder(), engine)
	c.Request = req
	return c
}

// TestFromIgnoresForwardedHeadersWhenProxyUntrusted 未約定可信代理＝六種標頭全數不採信
func TestFromIgnoresForwardedHeadersWhenProxyUntrusted(t *testing.T) {
	got := From(spoofedContext(t, false), false)
	if got == spoofValue {
		t.Fatalf("From = %q——採信了請求自帶的轉送標頭，來源位址等於由攻擊者填寫", got)
	}
	if got != peerAddr {
		t.Fatalf("From = %q，want %q（socket 對端）", got, peerAddr)
	}
}

// TestFromHonorsForwardedHeaderWhenProxyTrusted 反向斷言：已約定可信代理時才採信。
// 沒有這格，「永遠取 socket 對端」與正確實作不可區分。
func TestFromHonorsForwardedHeaderWhenProxyTrusted(t *testing.T) {
	if got := From(spoofedContext(t, true), true); got != spoofValue {
		t.Fatalf("From = %q，want %q：已約定可信代理鏈時仍忽略標頭，"+
			"等於反向代理後的部署每一列都記成代理位址", got, spoofValue)
	}
}

// TestOfReadsTrustedProxyConfig Of 的判定確實來自 TRUSTED_PROXIES（兩個方向都驗）。
//
// 只驗「未設時安全」不夠：把 Of 寫死成 `From(c, false)` 也會過，而那會讓
// TRUSTED_PROXIES 這個設定路徑對全部 24＋8 個呼叫點靜默失效。
func TestOfReadsTrustedProxyConfig(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	if got := Of(spoofedContext(t, false)); got != peerAddr {
		t.Fatalf("未設 TRUSTED_PROXIES 時 Of = %q，want %q（socket 對端）", got, peerAddr)
	}

	t.Setenv("TRUSTED_PROXIES", peerAddr)
	if got := Of(spoofedContext(t, true)); got != spoofValue {
		t.Fatalf("已設 TRUSTED_PROXIES=%s 時 Of = %q，want %q："+
			"Of 未讀組態，可信代理設定路徑對全部呼叫點失效", peerAddr, got, spoofValue)
	}
}

// TestFromToleratesMissingRequest 無請求脈絡時回空字串而非 panic
// （sealgate 佔位與部分測試會以空 Context 呼叫）
func TestFromToleratesMissingRequest(t *testing.T) {
	if got := From(nil, false); got != "" {
		t.Fatalf("From(nil) = %q，want 空字串", got)
	}
	c := gin.CreateTestContextOnly(httptest.NewRecorder(), gin.New())
	if got := From(c, true); got != "" {
		t.Fatalf("From(無 Request) = %q，want 空字串", got)
	}
}
