package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 守衛 G3（refresh-token-httponly-cookie 決策 1／5／9）：
// **登出端點收得到 refresh cookie，且撤銷確實發生**。
//
// # 這是為了補哪一個洞
//
// cookie 的 Path 若被收窄成 `/api/v1/auth/refresh`（看起來更嚴、更收斂，是很自然的
// 一手「加強」），登出端點就再也收不到 cookie：
//
//   - 登出撤銷靜默退化為 no-op（`Logout` 對空憑證的處置本就是「不阻擋登出」）；
//   - 連帶「登出提交已輪替憑證＝分叉訊號 → 家族撤銷」（F1）這道防線一起失效；
//   - **不會有任何既有測試轉紅**——沒有任何斷言會注意到憑證其實沒被撤銷。
//
// 使用者端看到的只是「登出了」，而攻擊者手上竊得的憑證仍存活至絕對壽命。
//
// # 兩段
//
//	G3a 機械前綴斷言：以 Path 常數對**實際註冊的路由**做 HasPrefix，
//	    路由字串自 gin 的路由表取得而非寫死——端點改名時本格照樣有效。
//	G3b 行為斷言：登入取得 cookie → 帶 cookie 登出 → 回應含清除性 Set-Cookie →
//	    原憑證再打刷新得 401。第三步是「撤銷真的發生」的唯一證據；
//	    只驗前兩步的話，一個什麼都沒撤銷的 logout 照樣全綠。
//
// # 突變自檢
//
//	把 RefreshCookiePath 改成 "/api/v1/auth/refresh" ⇒ G3a 的 logout 格轉紅。
//	把 Logout 的 `readRefreshCookie(c)` 換成恆回空字串 ⇒ G3b 的 401 斷言轉紅。
//	把 Logout 的 `h.refreshCookies.Clear(c)` 拿掉 ⇒ G3b 的清除斷言轉紅。

// cookieBearingAuthRoutes 需要攜帶 refresh cookie 才能正確運作的端點。
//
// 兩條都要：刷新是憑證的用途，登出是憑證的終點。少一條都會讓 Path 收斂的
// 手滑無人攔阻
var cookieBearingAuthRoutes = []string{"/auth/refresh", "/auth/logout"}

// TestRefreshCookiePathCoversRefreshAndLogout G3a：Path 常數涵蓋兩條路由。
func TestRefreshCookiePathCoversRefreshAndLogout(t *testing.T) {
	e := setupRefreshCookieEnv(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	e.h.RegisterRoutes(r.Group("/api/v1"), e.auth)

	registered := map[string]string{}
	for _, route := range r.Routes() {
		for _, suffix := range cookieBearingAuthRoutes {
			if strings.HasSuffix(route.Path, suffix) {
				registered[suffix] = route.Path
			}
		}
	}

	for _, suffix := range cookieBearingAuthRoutes {
		full, ok := registered[suffix]
		if !ok {
			t.Fatalf("路由表找不到 %s——本守衛的輸入已殘缺，拒絕在殘缺輸入上判定"+
				"（端點改名了？請同步 cookieBearingAuthRoutes）", suffix)
		}
		if !strings.HasPrefix(full, RefreshCookiePath) {
			t.Errorf("路由 %s 不在 cookie 的 Path 射程（%s）內——瀏覽器不會對它附帶 refresh cookie。\n"+
				"若這是 logout：登出撤銷會靜默退化為 no-op，連帶分叉偵測的家族撤銷失效，"+
				"而不會有任何其他測試轉紅。", full, RefreshCookiePath)
		}
	}
}

// TestLogoutReceivesCookieAndRevokes G3b：登出收得到 cookie、清除 cookie、且撤銷生效。
func TestLogoutReceivesCookieAndRevokes(t *testing.T) {
	e := setupRefreshCookieEnv(t)

	loginResp := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
	issued := findRefreshCookie(loginResp)
	if issued == nil {
		t.Fatal("前提不成立：登入未下發 refresh cookie")
	}

	// 帶 cookie 登出（不掛 AuthMiddleware：本格驗的是 handler 對 cookie 的處置，
	// 認證與否不改變撤銷語義）
	logoutResp := e.post(t, "/api/v1/auth/logout", e.h.Logout, map[string]string{}, "",
		&http.Cookie{Name: RefreshCookieName, Value: issued.Value})
	if logoutResp.Code != http.StatusOK {
		t.Fatalf("登出應回 200，實得 %d：%s", logoutResp.Code, logoutResp.Body.String())
	}

	cleared := findRefreshCookie(logoutResp)
	if cleared == nil {
		t.Fatalf("登出回應未清除 refresh cookie（無 Set-Cookie）——瀏覽器會留著一枚"+
			"使用者以為已失效的憑證。Set-Cookie=%q", logoutResp.Header().Values("Set-Cookie"))
	}
	if cleared.Value != "" || cleared.MaxAge > 0 {
		t.Errorf("清除性 Set-Cookie 應為空值＋立即到期，實得 value=%q MaxAge=%d",
			cleared.Value, cleared.MaxAge)
	}
	// 屬性須與下發時一致：瀏覽器以 (name, domain, path) 為鍵，
	// 屬性不一致的清除在部分瀏覽器根本命不中原 cookie
	if cleared.Path != issued.Path || cleared.HttpOnly != issued.HttpOnly ||
		cleared.SameSite != issued.SameSite || cleared.Secure != issued.Secure {
		t.Errorf("清除的 cookie 屬性與下發時不一致：清除=(path=%q,httpOnly=%v,sameSite=%v,secure=%v) "+
			"下發=(path=%q,httpOnly=%v,sameSite=%v,secure=%v)",
			cleared.Path, cleared.HttpOnly, cleared.SameSite, cleared.Secure,
			issued.Path, issued.HttpOnly, issued.SameSite, issued.Secure)
	}

	// **撤銷真的發生**：原憑證再打刷新必須被拒。少了這一步，一個什麼都沒撤銷的
	// logout 照樣通過上面全部斷言
	refreshResp := e.post(t, "/api/v1/auth/refresh", e.h.Refresh, map[string]string{}, "",
		&http.Cookie{Name: RefreshCookieName, Value: issued.Value})
	if refreshResp.Code != http.StatusUnauthorized {
		t.Fatalf("登出後原憑證仍可刷新（狀態碼 %d）——撤銷是 no-op，"+
			"登出只清了瀏覽器端，伺服器端的會話仍活著：%s",
			refreshResp.Code, refreshResp.Body.String())
	}
}

// TestLogoutWithoutCookieStillSucceedsAndClears 無 cookie 的登出不被阻擋，且照樣清除。
//
// 既有語義（「body 可空不阻擋登出」）換了載體後必須原樣成立：使用者的 cookie
// 早已過期或被其他分頁清掉時，登出仍要能走完並把本地狀態帶乾淨
func TestLogoutWithoutCookieStillSucceedsAndClears(t *testing.T) {
	e := setupRefreshCookieEnv(t)

	w := e.post(t, "/api/v1/auth/logout", e.h.Logout, map[string]string{}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("無憑證的登出應回 200，實得 %d：%s", w.Code, w.Body.String())
	}
	cleared := findRefreshCookie(w)
	if cleared == nil {
		t.Fatalf("登出回應一律應帶清除性 Set-Cookie，實得 %q", w.Header().Values("Set-Cookie"))
	}
	if cleared.Value != "" || cleared.MaxAge > 0 {
		t.Errorf("清除性 Set-Cookie 應為空值＋立即到期，實得 value=%q MaxAge=%d",
			cleared.Value, cleared.MaxAge)
	}
}

// TestRefreshRejectsBodyCarriedCredential 刷新僅認 cookie（決策 4 ／ spec 場景
// 「刷新僅認 cookie」）：body 傳遞路徑不存在。
//
// 這一格釘的是「不留 fallback」：body 帶著一枚**真的有效**的憑證而不帶 cookie，
// 仍須被拒。留了 fallback 的實作在此會回 200
func TestRefreshRejectsBodyCarriedCredential(t *testing.T) {
	e := setupRefreshCookieEnv(t)

	loginResp := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
	issued := findRefreshCookie(loginResp)
	if issued == nil {
		t.Fatal("前提不成立：登入未下發 refresh cookie")
	}

	w := e.post(t, "/api/v1/auth/refresh", e.h.Refresh,
		map[string]string{"refresh_token": issued.Value}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("以 request body 攜帶有效憑證的刷新應被拒（401），實得 %d：%s\n"+
			"body fallback 存在＝憑證仍可經 script 可讀的通道傳遞，遷移形同未做",
			w.Code, w.Body.String())
	}
}

// TestRefreshWithoutCookieReturnsUnifiedFailure cookie 缺失走統一認證失敗回應。
//
// 不是 400：body 時代的 400 是「格式錯誤」語義，而 cookie 缺失語義上就是
// 「未提供憑證」。回應碼與「憑證無效」「已撤銷」相同，不給攻擊者區分的訊號
func TestRefreshWithoutCookieReturnsUnifiedFailure(t *testing.T) {
	e := setupRefreshCookieEnv(t)

	missing := e.post(t, "/api/v1/auth/refresh", e.h.Refresh, map[string]string{}, "")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("無 cookie 的刷新應回 401，實得 %d：%s", missing.Code, missing.Body.String())
	}
	invalid := e.post(t, "/api/v1/auth/refresh", e.h.Refresh, map[string]string{}, "",
		&http.Cookie{Name: RefreshCookieName, Value: "not-a-real-credential"})
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("無效憑證的刷新應回 401，實得 %d", invalid.Code)
	}
	if normalizeBody(missing) != normalizeBody(invalid) {
		t.Errorf("「未提供」與「無效」的回應可區分：%s vs %s——"+
			"攻擊者據此可判斷手上的值是否曾經是一枚憑證",
			missing.Body.String(), invalid.Body.String())
	}
}

func normalizeBody(w *httptest.ResponseRecorder) string {
	return strings.TrimSpace(w.Body.String())
}
