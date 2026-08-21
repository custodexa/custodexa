package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// HTTP 行為守衛（route-registration spec Requirement 4）。
//
// 鏈比對（TestRoutesMatchGolden）保證「掛了哪些中間件、順序為何」，屬結構面。
// 本檔補的是結構面看不到的**行為**：中間件是否真的攔截、全域鏈是否真的生效。
//
// 兩者互補而非重複：
//   - 鏈比對能抓到「中間件被拿掉」，但抓不到「中間件在但邏輯壞了」
//   - 行為測試能抓到後者，但無法窮舉所有路由（故不取代鏈比對）
//
// 不連 DB：未認證請求在 AuthMiddleware 的第一道（缺 Authorization header）即 401，
// 不會進入 ValidateToken 之後的路徑，故 zero-value deps 足夠。
// 需要真 JWT／真 DB 的情境（權限常數是否正確、audit 是否落列）留待後續 change。

// newTestRouter 以指定組態建 router，回傳可直接發請求的 engine。
func newTestRouter(t *testing.T, isRelease, auditLogEnabled bool) *gin.Engine {
	t.Helper()
	prev := gin.Mode()
	if isRelease {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.TestMode)
	}
	t.Cleanup(func() { gin.SetMode(prev) })

	r := gin.New() // 不用 Default()：本測試不需 Logger/Recovery，避免污染輸出
	registerRoutes(r, testDeps(isRelease, auditLogEnabled))
	return r
}

// TestProtectedRoutesRejectUnauthenticated 受保護端點必須攔截未認證請求。
//
// 這是鏈比對看不到的一層：即使 AuthMiddleware 出現在鏈上，若其邏輯失效
// （例如誤放行缺 token 的請求），鏈指紋依然完全相同。
func TestProtectedRoutesRejectUnauthenticated(t *testing.T) {
	r := newTestRouter(t, false, true)

	protected := []struct{ method, path string }{
		{"GET", "/api/v1/assets"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/sessions"},
		{"GET", "/api/v1/security-policies"},
		{"GET", "/api/v1/audit-logs"},
		{"POST", "/api/v1/connect-tokens"},
	}
	for _, p := range protected {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			req := httptest.NewRequest(p.method, p.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("未帶認證竟回 %d（應為 401）——認證中間件未生效，"+
					"鏈比對對此類邏輯失效完全無感", w.Code)
			}
		})
	}
}

// TestPublicRoutesAccessibleWithoutAuth 公開端點不得被認證中間件誤擋。
//
// 反向保護：若有人為了修某個問題而把 AuthMiddleware 掛到全域，
// 鏈比對會紅，但這裡會更早、更明確地指出是哪些端點被誤擋。
func TestPublicRoutesAccessibleWithoutAuth(t *testing.T) {
	r := newTestRouter(t, false, true)

	for _, p := range []struct{ method, path string }{
		{"GET", "/health"},
		{"POST", "/health"},
		{"GET", "/api/v1/ping"},
	} {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			req := httptest.NewRequest(p.method, p.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			// 斷言預期成功而非僅「不是 401」——後者會讓 403/500 靜默通過
			if w.Code != http.StatusOK {
				t.Errorf("公開端點回 %d（應為 200）——認證中間件掛載範圍過大，或該端點已損壞", w.Code)
			}
		})
	}
}

// TestGlobalMiddlewareEffective 全域中間件確實作用於路由。
//
// 驗 CORS 標頭與 Metrics 計數之外，最重要的是確認 dev 組態下 CORS 真的放行——
// 若 buildCORSConfig 的分支判斷寫反，鏈比對仍全綠（cors.New.func1 名稱不變）。
func TestGlobalMiddlewareEffective(t *testing.T) {
	r := newTestRouter(t, false, true)

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Error("dev 組態下跨源請求未取得 Access-Control-Allow-Origin——" +
			"CORS 中間件未生效或分支判斷有誤")
	}
	if w.Code != http.StatusOK {
		t.Errorf("/health 回 %d（應為 200）", w.Code)
	}
}

// TestAuditRoutesFollowFlag 審計查詢端點的存在與否須跟隨旗標。
func TestAuditRoutesFollowFlag(t *testing.T) {
	on := newTestRouter(t, false, true)
	w := httptest.NewRecorder()
	on.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/audit-logs", nil))
	if w.Code == http.StatusNotFound {
		t.Error("audit 啟用時 /audit-logs 竟 404")
	}

	off := newTestRouter(t, false, false)
	w2 := httptest.NewRecorder()
	off.ServeHTTP(w2, httptest.NewRequest("GET", "/api/v1/audit-logs", nil))
	if w2.Code != http.StatusNotFound {
		t.Errorf("audit 關閉時 /audit-logs 回 %d（應為 404）——條件註冊未生效", w2.Code)
	}
}
