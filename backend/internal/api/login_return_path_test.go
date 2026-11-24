package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 登入後回到原本頁面（auth-session「登入後回到原本的頁面」）。
//
// 判準只收通知連結會指到的七個頁面與三個查詢鍵；會在進入時建立連線的頁面一律退回預設路徑。
// 帳號密碼登入與單一登入發起共用同一個判準；目的地只附加在成功與中間狀態的回應上，
// 不改變任何失敗回應、限流或審計。

// TestSanitizeLoginReturnPathAccepts (a) 七個樣式的合法值原樣回傳。
func TestSanitizeLoginReturnPathAccepts(t *testing.T) {
	for _, in := range []string{
		"/approvals",
		"/approvals?tab=pending",
		"/approvals?request=42",
		"/approvals?tab=pending&request=42",
		"/approvals?tab=history&request=42",
		"/approvals?tab=reviews&request=1",
		"/audit-logs",
		"/audit-logs?tab=reviews",
		"/audit/agent-tasks/42",
		"/audit/agent-tasks/1234567890",
		"/agent-breakers",
		"/agent-breakers?user_id=9",
		"/alerts",
		"/sessions/42",
		"/notification-channels",
		"/approvals?tab=pending&request=42&user_id=x_y-Z",
	} {
		if got := sanitizeLoginReturnPath(in); got != in {
			t.Errorf("sanitizeLoginReturnPath(%q) = %q，want 原樣", in, got)
		}
	}
}

// TestSanitizeLoginReturnPathRejects (b) 回預設路徑的輸入。
func TestSanitizeLoginReturnPathRejects(t *testing.T) {
	cases := map[string]string{
		"空字串":             "",
		"外部絕對網址":          "https://evil.example.com/approvals",
		"scheme-relative": "//evil.example.com/approvals",
		"反斜線":             "/\\evil.example.com",
		"反斜線在路徑內":         "/approvals\\..\\users",
		"dot-segment":     "/approvals/../users",
		"編碼的斜線":           "/approvals%2F..",
		"編碼的字母":           "/%61pprovals",
		"即時監看":            "/sessions/7/monitor",
		"按鍵紀錄":            "/sessions/7/keystrokes",
		"連線頁":             "/terminal/7",
		"工作區帶資產":          "/workspace?asset=3",
		"分享頁":             "/share/abc",
		"會話識別碼非數字":        "/sessions/abc",
		"任務識別碼非數字":        "/audit/agent-tasks/01a",
		"任務識別碼超過十位":       "/audit/agent-tasks/12345678901",
		"不在清單的頁面":         "/users",
		"登入頁":             "/login",
		"根路徑以外的預設頁":       "/dashboard",
		"結尾斜線":            "/approvals/",
		"相對路徑":            "approvals",
		"javascript":      "javascript:alert(1)",
		"使用者資訊":           "https://user:pw@evil.example.com/approvals",
		"控制字元":            "/approvals\n",
		"超過 255 字":        "/approvals?tab=pending&zz=" + strings.Repeat("a", 260),
	}
	for name, in := range cases {
		if got := sanitizeLoginReturnPath(in); got != "/" {
			t.Errorf("%s: sanitizeLoginReturnPath(%q) = %q，want \"/\"", name, in, got)
		}
	}
}

// TestSanitizeLoginReturnPathQuery (c) 查詢字串：只保留三個鍵、依固定順序重組；多重編碼與保留鍵不合格整個退回。
func TestSanitizeLoginReturnPathQuery(t *testing.T) {
	keep := map[string]string{
		"/approvals?request=42&note=x#frag":         "/approvals?request=42",
		"/approvals?request=42&tab=pending":         "/approvals?tab=pending&request=42",
		"/agent-breakers?user_id=9&utm_source=mail": "/agent-breakers?user_id=9",
		"/alerts#top": "/alerts",
		"/approvals?": "/approvals",
		"/audit-logs?tab=reviews&date=2026-11-20":     "/audit-logs?tab=reviews",
		"/approvals?note=hello%20world&request=42":    "/approvals?request=42",
		"/sessions/42?t=10&at=2026-11-20T00:00:00Z":   "/sessions/42",
		"/approvals?user_id=7&request=8&tab=history":  "/approvals?tab=history&request=8&user_id=7",
		"/approvals?request=12345678901234567890abcd": "/approvals?request=12345678901234567890abcd",
	}
	for in, want := range keep {
		if got := sanitizeLoginReturnPath(in); got != want {
			t.Errorf("sanitizeLoginReturnPath(%q) = %q，want %q", in, got, want)
		}
	}
	reject := map[string]string{
		"保留鍵重複":         "/approvals?request=42&request=43",
		"值含空白":          "/approvals?request=4%202",
		"值以加號表示空白":      "/approvals?request=4+2",
		"值超過 32 字":      "/approvals?request=" + strings.Repeat("1", 33),
		"值為空":           "/approvals?request=",
		"只有鍵沒有值":        "/approvals?request",
		"保留鍵的值多重編碼":     "/approvals?request=%2542",
		"不認得的鍵的值多重編碼":   "/approvals?note=%252F",
		"值含斜線":          "/approvals?tab=..%2Fusers",
		"值含點":           "/approvals?tab=a.b",
		"分號分隔":          "/approvals?request=42;tab=pending",
		"保留鍵大小寫不同仍視為未知": "/approvals?Request=%2541",
	}
	for name, in := range reject {
		if got := sanitizeLoginReturnPath(in); got != "/" {
			t.Errorf("%s: sanitizeLoginReturnPath(%q) = %q，want \"/\"", name, in, got)
		}
	}
}

// loginReturnSampleRe 擷取前端清單的 `{ name: '…', sample: '…' }` 項目。
var loginReturnSampleRe = regexp.MustCompile(`name:\s*'([A-Za-z]+)',\s*sample:\s*'([^']*)'`)

// TestLoginReturnRoutesNoDrift 前端「登入後可回到的路由」清單與後端判準一致：
// 每個樣本都被判準原樣接受、七個路徑樣式都有樣本、清單的路由名稱都存在於前端路由表。
func TestLoginReturnRoutesNoDrift(t *testing.T) {
	raw, err := readLoginReturnRoutes()
	if err != nil {
		t.Fatalf("讀取前端清單失敗——容器內需 testdata/router 唯讀掛載，host 直跑需 frontend/ 在相對位置: %v", err)
	}
	entries := loginReturnSampleRe.FindAllStringSubmatch(string(raw), -1)
	if len(entries) == 0 {
		t.Fatal("前端清單解析不到任何項目（格式改了而本測試的解析未更新）")
	}
	covered := make([]bool, len(loginReturnPathPatterns))
	router, err := readRouterSources("testdata/router")
	if err != nil {
		router, err = readRouterSources("../../../frontend/src/router")
	}
	if err != nil {
		t.Fatalf("讀取前端路由表失敗: %v", err)
	}
	for _, m := range entries {
		name, sample := m[1], m[2]
		if got := sanitizeLoginReturnPath(sample); got != sample {
			t.Errorf("前端清單的 %s 樣本 %q 不被伺服端判準原樣接受（得 %q）：兩邊的頁面清單已不一致", name, sample, got)
			continue
		}
		u, _ := url.Parse(sample)
		for i, re := range loginReturnPathPatterns {
			if re.MatchString(u.EscapedPath()) {
				covered[i] = true
			}
		}
		if !strings.Contains(string(router), "name: '"+name+"'") {
			t.Errorf("前端清單的路由名稱 %s 不在前端路由表內", name)
		}
	}
	for i, ok := range covered {
		if !ok {
			t.Errorf("伺服端的路徑樣式 %s 在前端清單沒有對應的路由", loginReturnPathPatterns[i])
		}
	}
}

func readLoginReturnRoutes() ([]byte, error) {
	b, err := os.ReadFile("testdata/router/loginReturnRoutes.js")
	if err != nil {
		b, err = os.ReadFile("../../../frontend/src/router/loginReturnRoutes.js")
	}
	return b, err
}

// ---- 帳號密碼登入的 next 與 redirect_next ----

func postLoginBody(t *testing.T, h *AuthHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.POST("/api/v1/auth/login", h.Login)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = authSrcRemoteAddr
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func loginBodyWithNext(username, password, nextJSON string) string {
	b, _ := json.Marshal(map[string]string{"username": username, "password": password})
	if nextJSON == "" {
		return string(b)
	}
	return strings.TrimSuffix(string(b), "}") + `,"next":` + nextJSON + `}`
}

func redirectNextOf(t *testing.T, w *httptest.ResponseRecorder) (string, bool) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("回應不是 JSON: %s", w.Body.String())
	}
	v, ok := m["redirect_next"].(string)
	return v, ok
}

// TestLoginRedirectNextOnAllBranches 6.3 (a) 完成、驗證碼、強制綁定、強制改密四種分支都帶 redirect_next，
// 值為判準結果；沒帶 next 回 "/"。
func TestLoginRedirectNextOnAllBranches(t *testing.T) {
	const want = "/approvals?tab=pending&request=42"
	next := `"/approvals?tab=pending&request=42&note=x#frag"`
	branches := []struct {
		name   string
		setup  func(t *testing.T, env *authSrcEnv)
		marker string
	}{
		{"完成登入", func(*testing.T, *authSrcEnv) {}, `"token"`},
		{"需要驗證碼", func(t *testing.T, env *authSrcEnv) { env.enableTOTP(t) }, `"mfa_required":true`},
		{"強制綁定驗證器", func(t *testing.T, env *authSrcEnv) {
			p := policy.NewSecurityPolicyService(env.db)
			if _, err := p.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin"); err != nil {
				t.Fatal(err)
			}
			env.auth.SetSecurityPolicies(p)
		}, `"mfa_enrollment_required":true`},
		{"強制改密", func(t *testing.T, env *authSrcEnv) {
			if err := env.db.Model(&model.User{}).Where("id = ?", env.uid).Update("must_change_password", true).Error; err != nil {
				t.Fatal(err)
			}
		}, `"password_change_required":true`},
	}
	for _, br := range branches {
		t.Run(br.name, func(t *testing.T) {
			env := setupAuthSourceEnv(t)
			br.setup(t, env)
			w := postLoginBody(t, env.h, loginBodyWithNext("source-subject", authSrcPassword, next))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), br.marker) {
				t.Fatalf("前提不成立：應回 200 且為「%s」分支，得 %d %s", br.name, w.Code, w.Body.String())
			}
			if got, ok := redirectNextOf(t, w); !ok || got != want {
				t.Errorf("redirect_next = %q（存在=%v），want %q", got, ok, want)
			}
		})
		t.Run(br.name+"：沒帶 next", func(t *testing.T) {
			env := setupAuthSourceEnv(t)
			br.setup(t, env)
			w := postLoginBody(t, env.h, loginBodyWithNext("source-subject", authSrcPassword, ""))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), br.marker) {
				t.Fatalf("前提不成立：得 %d %s", w.Code, w.Body.String())
			}
			if got, ok := redirectNextOf(t, w); !ok || got != "/" {
				t.Errorf("沒帶 next 時 redirect_next = %q（存在=%v），want \"/\"", got, ok)
			}
		})
	}
	// 不合格或不是字串的 next 在成功回應上一律為 "/"（含開放重導向與會建立連線的頁面）
	for _, bad := range []string{`"https://evil.example.com/"`, `"//evil.example.com"`, `"/terminal/7"`, `"/approvals/../users"`, `42`, `{"path":"/approvals"}`, `["/approvals"]`, `null`} {
		env := setupAuthSourceEnv(t)
		w := postLoginBody(t, env.h, loginBodyWithNext("source-subject", authSrcPassword, bad))
		if w.Code != http.StatusOK {
			t.Fatalf("next=%s 時登入應成功，得 %d %s", bad, w.Code, w.Body.String())
		}
		if got, _ := redirectNextOf(t, w); got != "/" {
			t.Errorf("next=%s 時 redirect_next = %q，want \"/\"", bad, got)
		}
	}
}

// auditFingerprint 審計列中與請求內容有關的欄位（去掉識別碼與時間）。
func auditFingerprint(rows []model.AuditLog) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprint(r.Action, "|", r.Resource, "|", r.Status, "|", r.Username, "|", r.Method, "|", r.Path, "|", r.ClientIP, "|", r.ErrorMsg, "|", r.Details, "|", r.RequestBody)+
			"|"+http.StatusText(r.StatusCode))
	}
	return out
}

// TestLoginNextDoesNotChangeFailures 6.3 (b) 不存在的帳號、密碼錯誤、停用、鎖定四種失敗，
// 帶合法、不合格、數字、物件、陣列、null 的 next 與不帶 next 時，HTTP 狀態、錯誤碼、回應本文與失敗審計列完全相同。
func TestLoginNextDoesNotChangeFailures(t *testing.T) {
	variants := []string{"", `"/approvals?tab=pending&request=42"`, `"/terminal/7"`, `"https://evil.example.com/"`, `42`, `{"a":1}`, `["/approvals"]`, `null`}
	failures := []struct {
		name     string
		setup    func(t *testing.T, env *authSrcEnv)
		username string
		password string
		status   int
	}{
		{"不存在的帳號", func(*testing.T, *authSrcEnv) {}, "no-such-user", "x", http.StatusUnauthorized},
		{"密碼錯誤", func(*testing.T, *authSrcEnv) {}, "source-subject", "wrong-password", http.StatusUnauthorized},
		{"停用", func(t *testing.T, env *authSrcEnv) {
			if err := env.db.Model(&model.User{}).Where("id = ?", env.uid).Update("active", false).Error; err != nil {
				t.Fatal(err)
			}
		}, "source-subject", authSrcPassword, http.StatusForbidden},
		{"鎖定", func(t *testing.T, env *authSrcEnv) {
			if err := env.db.Model(&model.User{}).Where("id = ?", env.uid).Update("locked_until", time.Now().Add(time.Hour)).Error; err != nil {
				t.Fatal(err)
			}
		}, "source-subject", authSrcPassword, http.StatusLocked},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			var baseBody string
			var baseAudit []string
			for i, v := range variants {
				env := setupAuthSourceEnv(t)
				f.setup(t, env)
				w := postLoginBody(t, env.h, loginBodyWithNext(f.username, f.password, v))
				if w.Code != f.status {
					t.Fatalf("next=%s: 狀態 %d，want %d（%s）", v, w.Code, f.status, w.Body.String())
				}
				if strings.Contains(w.Body.String(), "redirect_next") {
					t.Errorf("next=%s: 失敗回應帶了 redirect_next: %s", v, w.Body.String())
				}
				audit := auditFingerprint(env.rows(t))
				if i == 0 {
					baseBody, baseAudit = w.Body.String(), audit
					if len(audit) != 1 {
						t.Fatalf("前提不成立：失敗應留恰好一筆審計列，得 %d", len(audit))
					}
					continue
				}
				if w.Body.String() != baseBody {
					t.Errorf("next=%s: 回應本文與不帶 next 時不同：\n%s\n%s", v, baseBody, w.Body.String())
				}
				if strings.Join(audit, "\n") != strings.Join(baseAudit, "\n") {
					t.Errorf("next=%s: 失敗審計列與不帶 next 時不同：\n%v\n%v", v, baseAudit, audit)
				}
			}
		})
	}
	// 請求格式錯誤（缺帳號）不因多帶 next 而改變
	env := setupAuthSourceEnv(t)
	a := postLoginBody(t, env.h, `{"password":"x"}`)
	b := postLoginBody(t, env.h, `{"password":"x","next":"/approvals"}`)
	if a.Code != http.StatusBadRequest || a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Errorf("缺帳號時帶不帶 next 的回應不同: %d %s / %d %s", a.Code, a.Body.String(), b.Code, b.Body.String())
	}
}

// TestLoginNextDoesNotChangeRateLimit 6.3 (b) IP 限流在帶合法、不合格與不帶 next 時的計數相同。
func TestLoginNextDoesNotChangeRateLimit(t *testing.T) {
	for _, v := range []string{"", `"/approvals?request=42"`, `"/terminal/7"`, `42`} {
		params := defaultLoginGuardParams()
		params.PerIPBurst = 3
		r := newLoginGuardRouter(t, params, &recordingAggSink{})
		send := func() int {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
				bytes.NewBufferString(loginBodyWithNext("someone", "guess", v)))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "203.0.113.30:40000"
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			return w.Code
		}
		for i := 0; i < 3; i++ {
			if code := send(); code == http.StatusTooManyRequests {
				t.Fatalf("next=%s: 第 %d 次（額度內）被限流", v, i+1)
			}
		}
		if code := send(); code != http.StatusTooManyRequests {
			t.Errorf("next=%s: 第 4 次應被限流，得 %d", v, code)
		}
	}
}

// TestLoginAuditOmitsNext 6.3 (c) 成功登入的稽核列不含 next 的值。
func TestLoginAuditOmitsNext(t *testing.T) {
	env := setupAuthSourceEnv(t)
	w := postLoginBody(t, env.h, loginBodyWithNext("source-subject", authSrcPassword, `"/approvals?tab=pending&request=4242"`))
	if w.Code != http.StatusOK {
		t.Fatalf("登入應成功，得 %d %s", w.Code, w.Body.String())
	}
	rows := env.rows(t)
	if len(rows) == 0 {
		t.Fatal("前提不成立：成功登入沒有稽核列")
	}
	for _, line := range auditFingerprint(rows) {
		if strings.Contains(line, "approvals") || strings.Contains(line, "4242") {
			t.Errorf("稽核列含 next 的值: %s", line)
		}
	}
}

// TestOIDCBeginStoresNarrowReturnPath 單一登入發起時保存的目的地使用同一個較窄的判準：
// 帶會建立連線的頁面時保存 "/"，帶審核中心直達時保存判準後的值。
func TestOIDCBeginStoresNarrowReturnPath(t *testing.T) {
	cases := map[string]string{
		"/terminal/7":                         "/",
		"/workspace?asset=3":                  "/",
		"/sessions/7/monitor":                 "/",
		"/approvals?tab=pending&request=42":   "/approvals?tab=pending&request=42",
		"/approvals?request=42&note=x":        "/approvals?request=42",
		"https://evil.example.com/approvals":  "/",
		"/approvals?request=%2542&tab=review": "/",
	}
	for in, want := range cases {
		env := setupCallbackDeniedEnv(t)
		r := gin.New()
		r.GET("/api/v1/auth/oidc/:id/begin", env.h.Begin)
		q := url.Values{"binding": {strings.Repeat("ab", 32)}, "next": {in}}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/"+strconv.FormatUint(uint64(env.provider.ID), 10)+"/begin?"+q.Encode(), nil)
		req.RemoteAddr = oidcAuditRemoteAddr
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("next=%q: 發起應 302 導向身分提供者，得 %d %s", in, w.Code, w.Body.String())
		}
		var flow model.OIDCFlowState
		if err := env.db.Take(&flow).Error; err != nil {
			t.Fatalf("讀流程狀態: %v", err)
		}
		if flow.RedirectNext != want {
			t.Errorf("next=%q: 保存的目的地 = %q，want %q", in, flow.RedirectNext, want)
		}
	}
}
