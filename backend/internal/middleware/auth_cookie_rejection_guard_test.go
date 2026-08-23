package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/pkg/crypto"
)

// 守衛 G2：
// **認證 middleware 不得自 cookie 接受 JWT**。
//
// # 為什麼這一格在本 change 才變成必要
//
// 本 change 引入了本專案**第一個**瀏覽器會自動附帶的憑證（refresh cookie）。
// 在此之前「middleware 不讀 cookie」是暗默事實——後端根本沒有 cookie 機制，
// 沒人會想到去讀。有了 cookie 之後，「順手支援 cookie 登入」會是一個看起來
// 很自然的好意改動，而它會讓 access token 事實上取得第二條傳輸通道，
// 使決策 6 的 CSRF 分析（「cookie 的射程只有 /api/v1/auth/ 端點群」）整個崩塌。
//
// spec 條款：auth-session
// 「JWT 僅經 Authorization header 接受」——SHALL NOT 自 cookie 接受 JWT，
// 任何 cookie（含 refresh cookie 本身）對認證 middleware SHALL NOT 構成憑證。
//
// # 判準取 AUTH_TOKEN_MISSING 而非「401 就好」
//
// 401 有兩種來路：middleware 根本沒去讀 cookie（`AUTH_TOKEN_MISSING`），
// 或讀了 cookie、拿去驗、判為無效（`AUTH_TOKEN_INVALID`）。
// 後者代表 cookie 已經是一條會被解析的輸入路徑，只是這次的值不合用——
// 那正是本守衛要擋的狀態，而只斷言狀態碼的測試看不出兩者的差別。
//
// # 突變自檢
//
// 在 auth.go 的取值處補上「header 為空時退回讀 cookie」，本檔兩格皆轉紅
// （回應碼由 AUTH_TOKEN_MISSING 變成 AUTH_TOKEN_INVALID 或 200）。

// refreshCookieNameForGuard refresh cookie 的名稱。
//
// **刻意在此重寫字面值而不 import internal/api**：middleware 是 api 的下游依賴，
// 反向 import 會成環。名稱若日後更動，本格仍然有效——它守的是
// 「任何名稱的 cookie 都不構成憑證」，具體名稱只是最貼近現實的一個樣本。
const refreshCookieNameForGuard = "custodexa_refresh"

// TestAuthMiddlewareDoesNotReadJWTFromCookie 有效 JWT 置於 cookie、無 Authorization
// header ⇒ 401 且原因為「未提供」，證明 middleware 未讀取 cookie
func TestAuthMiddlewareDoesNotReadJWTFromCookie(t *testing.T) {
	const jwtSecret = "test-secret"
	installEpochGateDB(t, 1)
	r := setupAuthTestRouter(jwtSecret)

	mgr := crypto.NewJWTManager(jwtSecret, time.Minute)
	token, err := mgr.GenerateToken(1, "cookieuser", "c@example.com", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// 兩個 cookie 名稱各一案：refresh cookie 本身，以及一個「看起來就是 token」的名稱。
	// 後者是真正會被誤加的那一個——「順手支援 cookie 登入」的人不會用 refresh 的名字
	for _, name := range []string{refreshCookieNameForGuard, "token"} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.AddCookie(&http.Cookie{Name: name, Value: token})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("cookie 內的有效 JWT 被接受了（狀態碼 %d）——access token 因此"+
					"取得第二條傳輸通道，CSRF 分析的「cookie 射程只有 auth 端點群」前提失效。body=%s",
					w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, string(apierror.CodeTokenMissing)) {
				t.Errorf("回應機器碼應為 %s（middleware 未讀 cookie），實得 body=%s\n"+
					"若是 %s，代表 cookie 已成為一條會被解析的憑證輸入路徑，只是這次的值不合用",
					apierror.CodeTokenMissing, body, apierror.CodeTokenInvalid)
			}
		})
	}
}

// TestAuthMiddlewareCookieDoesNotRescueMalformedHeader cookie 不得作為
// Authorization header 的補位。
//
// 與上一格互補：上一格是「完全沒有 header」，本格是「header 在但形狀不對」——
// 補位式的 fallback（`if tokenString == "" { 讀 cookie }`）正好會在這兩種情況下
// 都被觸發，而只測其中一種的守衛會被另一種形狀的實作繞過
func TestAuthMiddlewareCookieDoesNotRescueMalformedHeader(t *testing.T) {
	const jwtSecret = "test-secret"
	installEpochGateDB(t, 1)
	r := setupAuthTestRouter(jwtSecret)

	mgr := crypto.NewJWTManager(jwtSecret, time.Minute)
	token, err := mgr.GenerateToken(1, "cookieuser", "c@example.com", "user", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "NotBearer something")
	req.AddCookie(&http.Cookie{Name: refreshCookieNameForGuard, Value: token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cookie 補位了殘缺的 Authorization header（狀態碼 %d）", w.Code)
	}
	if !strings.Contains(w.Body.String(), string(apierror.CodeTokenMissing)) {
		t.Errorf("回應機器碼應為 %s，實得 body=%s", apierror.CodeTokenMissing, w.Body.String())
	}
}
