package api

import (
	"net/http"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// refresh 憑證 cookie 的名稱與 Path（refresh-token-httponly-cookie 決策 1）。
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

// RefreshCookieWriter 統一下發／清除 refresh cookie。
//
// 屬性收在單一處：底層以 `http.SetCookie` 顯式建構 `http.Cookie`，
// 不用 gin 的 `c.SetCookie`——後者的 SameSite 依賴 context 全域狀態
// （`c.SetSameSite`），屬性會散落在呼叫端，守衛測試也就得比對多種序列化形狀。
type RefreshCookieWriter struct {
	// secure 部署期常數，由 config 於啟動時推導（決策 2），不逐請求重算
	secure bool
}

// NewRefreshCookieWriter 建立 writer；secure 由呼叫端自 config 取得推導結果。
func NewRefreshCookieWriter(secure bool) *RefreshCookieWriter {
	return &RefreshCookieWriter{secure: secure}
}

// defaultRefreshCookieWriter handler 建構時的 fail-safe 預設。
//
// **不讓「忘了接線」變成靜默的保護降級**：writer 若未注入而回落到零值，
// Secure 會無聲地變成 false；故各 handler 建構時即自 env 推導一份
// （沿 `NewAuthHandler` 已有的 `config.LoadSeal()` 先例），
// cmd/server 再以同一推導結果覆寫為共用實例——兩者同源，不構成第二個事實源。
func defaultRefreshCookieWriter() *RefreshCookieWriter {
	return NewRefreshCookieWriter(config.LoadRefreshCookieSecure().Secure)
}

// resolve 取 writer 的實際屬性；nil 接收者（未經建構函式的測試佔位）視為非 Secure，
// 使 cookie 仍能正常下發——**功能不因未接線而斷**，只是少一層降級攻擊防護。
func (w *RefreshCookieWriter) resolve() bool {
	if w == nil {
		return false
	}
	return w.secure
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
