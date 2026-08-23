package api

import (
	"net/http"
	"time"

	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
)

// refresh 憑證 cookie 的名稱與 Path。
//
// **不用 `__Host-` 前綴**：該前綴強制 `Path=/`，與下方的 Path 收斂互斥。
// 在「前綴保護」與「Path 收斂」之間選後者——對本案的威脅模型，
// 「其他 API 請求一律不攜帶此憑證」比「防子網域覆寫 cookie」更有意義。
const (
	// RefreshCookieName refresh 憑證的 cookie 名
	RefreshCookieName = "custodexa_refresh"

	// RefreshCookiePath cookie 的 Path 屬性。
	//
	// **這個值是認證端點群的前綴，不是 refresh 端點本身**——鎖死到
	// `/api/v1/auth/refresh` 會讓 `/api/v1/auth/logout` 收不到 cookie，
	// 登出撤銷靜默退化為 no-op，連帶「登出提交已輪替憑證＝分叉訊號 → 家族撤銷」
	// 這道防線一起失效，而且**不會有任何既有測試轉紅**（logout 本就容忍空憑證）。
	// 由守衛測試 G3（refresh_cookie_guard_test.go）以本常數對兩條路由做前綴斷言釘住。
	RefreshCookiePath = "/api/v1/auth/"
)

// RefreshCookieSecurePolicy refresh cookie 的 Secure 屬性事實源（安全政策服務）。
//
// 只要 `GetBool`：writer 需要的就只是「這個鍵現在是不是 true」，
// 介面收到這個寬度即可，測試也只需一個兩行的假物件。
type RefreshCookieSecurePolicy interface {
	GetBool(key string) bool
}

// RefreshCookieWriter 統一下發／清除 refresh cookie。
//
// 屬性收在單一處：底層以 `http.SetCookie` 顯式建構 `http.Cookie`，
// 不用 gin 的 `c.SetCookie`——後者的 SameSite 依賴 context 全域狀態
// （`c.SetSameSite`），屬性會散落在呼叫端，守衛測試也就得比對多種序列化形狀。
type RefreshCookieWriter struct {
	// policy Secure 屬性的事實源：
	// **發放時現讀**，不持啟動期常數——管理員在政策頁改了即生效、不需重啟，
	// 而那正是設錯時唯一好走的復原路徑
	policy RefreshCookieSecurePolicy
}

// NewRefreshCookieWriter 建立 writer；policy 為安全政策服務（cmd/server 注入）。
func NewRefreshCookieWriter(policySource RefreshCookieSecurePolicy) *RefreshCookieWriter {
	return &RefreshCookieWriter{policy: policySource}
}

// defaultRefreshCookieWriter handler 建構時的 fail-safe 預設（無政策源）。
//
// 政策源由 cmd/server 於接線時注入；未接線時 `resolve` 落在安全側（見該函式）。
// 本函式因此只是讓 handler 欄位非 nil 的佔位，不再自行推導任何值——
// 執行期事實源只有政策鍵一個，handler 建構期讀 env 會製造第二個。
func defaultRefreshCookieWriter() *RefreshCookieWriter {
	return NewRefreshCookieWriter(nil)
}

// resolve 取 Secure 屬性的現值：每次發放／清除時自政策現讀。
//
// **未接線一律回 true（安全方向）**：Secure 改為自政策現讀後，「沒有政策源」
// 在生產中的唯一意義是接線遺漏，而其失敗方向必須是「多保護」——回 false
// 等於讓一個接線 bug 靜默地把傳輸保護關掉，且沒有任何症狀。
// 回 true 的代價是純 HTTP 部署下多出重新登入（畫面上有成因說明），看得見、
// 改得掉。功能仍不因未接線而斷：cookie 照發，只是帶 Secure。
func (w *RefreshCookieWriter) resolve() bool {
	if w == nil || w.policy == nil {
		return true
	}
	return w.policy.GetBool(policy.PolicyRefreshCookieSecure)
}

// Set 下發 refresh cookie。
//
// expiresAt 為該憑證的**絕對到期時刻**，cookie 效期取「expiresAt − now」：
// 輪替沿用原 `expires_at`（不重算絕對壽命），故輪替時**不得**再給滿額效期
// ——給滿額則 cookie 活得比憑證久（誤導），反之則提前掉線。
func (w *RefreshCookieWriter) Set(c *gin.Context, plain string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		// 已到期的憑證不該走到這裡；真發生時給最小正值而非 0/負值——
		// Go 的 MaxAge==0 表示「不帶 Max-Age」、<0 表示「立即刪除」，
		// 兩者都會把「發放」寫成別的語義
		maxAge = 1
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    plain,
		Path:     RefreshCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   w.resolve(),
		SameSite: http.SameSiteStrictMode,
		// Domain 刻意不設：省略即 host-only，射程最窄
	})
}

// Clear 清除 refresh cookie（登出）。
//
// 屬性**必須與 Set 一致**（Name／Path／Secure／SameSite）：瀏覽器以
// (name, domain, path) 為鍵，屬性不一致的清除在部分瀏覽器不會命中原 cookie，
// 於是「登出了但 cookie 還在」。
func (w *RefreshCookieWriter) Clear(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Path:     RefreshCookiePath,
		MaxAge:   -1, // Go 序列化為 Max-Age=0＝立即到期
		HttpOnly: true,
		Secure:   w.resolve(),
		SameSite: http.SameSiteStrictMode,
	})
}

// SetFromLogin 自登入類回應下發 refresh cookie。
//
// **未發正式會話的分支零動作**：MFA 第一階段、強制註冊、強制改密三種 gate 回應
// 都沒有 refresh 憑證（`buildLoginResponse` 未被呼叫），RefreshToken 為空。
// 判準取「有沒有憑證」而非「走的是哪個分支」——分支清單會長，憑證有無不會。
func (w *RefreshCookieWriter) SetFromLogin(c *gin.Context, resp *identity.LoginResponse) {
	if resp == nil || resp.RefreshToken == "" {
		return
	}
	w.Set(c, resp.RefreshToken, resp.RefreshExpiresAt)
}

// readRefreshCookie 取請求攜帶的 refresh 憑證；缺失回空字串。
//
// 這是刷新與登出**唯一**的取值來源——不留 body fallback
// （proposal Non-goals：不做向下相容）。
func readRefreshCookie(c *gin.Context) string {
	v, err := c.Cookie(RefreshCookieName)
	if err != nil {
		return ""
	}
	return v
}
