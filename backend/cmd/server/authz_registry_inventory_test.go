package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestAuthzRegistryCoversRouteInventory 擋：路由漏登錄、method 混用、未登錄路由放行、欄位條件能力未生效。
//
// 同時承載 3.1 的目錄子測試（目錄無 scoped-enforced、無明文讀取類、保留名稱被拒）。
// 「每條非公開路由鏈上恰有一個執行點」子測試已於路由守衛換為登錄執行時加入。

func registrySet() map[string]bool {
	m := map[string]bool{}
	for _, k := range authz.RegistryKeys() {
		m[k] = true
	}
	return m
}

func principalOf(key string, kind string) *authz.Principal {
	return authz.NewPrincipal(1, authz.TokenFacts{SubjectKind: kind},
		[]authz.Assignment{{RoleName: key, BuiltinKey: key, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal}})
}

// serve 以指定主體對測試路由送一個請求，回傳狀態碼與回應 JSON。
func serve(t *testing.T, method, pattern string, p *authz.Principal) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if p != nil {
			middleware.SetPrincipal(c, p)
		}
		c.Next()
	})
	r.Handle(method, pattern, middleware.EnforceRegistry(), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"reached": true}) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, pattern, nil)
	r.ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

func TestAuthzRegistryCoversRouteInventory(t *testing.T) {
	t.Run("登錄鍵集合等於路由清冊", func(t *testing.T) {
		g := loadGolden(t, "release-auditon")
		routes, _ := buildRouter(t, gin.ReleaseMode, true)
		reg := registrySet()
		goldenKeys := map[string]bool{}
		for _, r := range g.Routes {
			goldenKeys[r.Method+" "+r.Path] = true
		}
		assert.Len(t, goldenKeys, len(g.Routes), "golden 無重複鍵")
		var missing, extra []string
		for k := range goldenKeys {
			if !reg[k] {
				missing = append(missing, k)
			}
		}
		for k := range reg {
			if !goldenKeys[k] {
				extra = append(extra, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		assert.Empty(t, missing, "路由清冊內有路由未登錄：%v", missing)
		assert.Empty(t, extra, "登錄表有路由清冊沒有的項目：%v", extra)
		assert.Len(t, reg, len(g.Routes))
		// 實際 router 與 golden 一致（TestRoutesMatchGolden 另守），這裡再以實際路由核對一次
		var unregistered []string
		for k := range routes {
			if !reg[k[0]+" "+k[1]] {
				unregistered = append(unregistered, k[0]+" "+k[1])
			}
		}
		sort.Strings(unregistered)
		assert.Empty(t, unregistered, "實際註冊的路由未登錄：%v", unregistered)
	})

	t.Run("其他組態下註冊的路由也都已登錄", func(t *testing.T) {
		reg := registrySet()
		for _, c := range []struct {
			mode  string
			audit bool
		}{{gin.DebugMode, true}, {gin.DebugMode, false}, {gin.ReleaseMode, false}} {
			routes, _ := buildRouter(t, c.mode, c.audit)
			for k := range routes {
				assert.True(t, reg[k[0]+" "+k[1]], "%s 組態下 %s %s 未登錄", c.mode, k[0], k[1])
			}
		}
	})

	t.Run("同路徑不同 method 各自登錄不混用", func(t *testing.T) {
		routes, _ := buildRouter(t, gin.ReleaseMode, true)
		actual := map[string][]string{}
		for k := range routes {
			actual[k[1]] = append(actual[k[1]], k[0])
		}
		inReg := map[string][]string{}
		for _, e := range authz.RegistryEntries() {
			inReg[e.Path] = append(inReg[e.Path], e.Method)
		}
		for path, ms := range actual {
			a, b := append([]string(nil), ms...), append([]string(nil), inReg[path]...)
			sort.Strings(a)
			sort.Strings(b)
			assert.Equal(t, a, b, "路徑 %s 的 method 集合", path)
		}
		// 實例：同一路徑 GET 與 DELETE 的權限點不同
		get, _ := authz.LookupRoute("GET", "/api/v1/assets/:id")
		del, _ := authz.LookupRoute("DELETE", "/api/v1/assets/:id")
		assert.NotEqual(t, get.Perm, del.Perm)
	})

	t.Run("每條非公開路由的鏈上恰有一個登錄執行點（實際 registerRoutes）", func(t *testing.T) {
		for _, c := range []struct {
			mode  string
			audit bool
		}{{gin.ReleaseMode, true}, {gin.DebugMode, true}, {gin.DebugMode, false}, {gin.ReleaseMode, false}} {
			_, chains := buildRouter(t, c.mode, c.audit)
			for _, e := range authz.RegistryEntries() {
				chain, ok := chains[[2]string{e.Method, e.Path}]
				if !ok {
					continue // 該組態下沒有這條路由（路由集合一致性由其他子測試守）
				}
				executors := 0
				for _, name := range chain {
					if strings.Contains(name, ".EnforceRegistry") {
						executors++
					}
				}
				switch e.Base {
				case authz.BasePublic, authz.BaseManual:
					assert.Equal(t, 0, executors, "%s 組態 %s：公開／手動認證入口的鏈上不得有執行點", c.mode, e.Key())
				default:
					assert.Equal(t, 1, executors, "%s 組態 %s：鏈上登錄執行點應恰為 1，實際 %d；鏈=%v", c.mode, e.Key(), executors, chain)
				}
			}
		}
	})

	t.Run("登錄項形狀完整：權限點在目錄內、拒絕依據對應登錄項", func(t *testing.T) {
		manual := map[string]bool{}
		none := customPrincipal()
		for _, e := range authz.RegistryEntries() {
			switch e.Base {
			case authz.BasePerm:
				_, ok := authz.LookupPermission(e.Perm)
				assert.True(t, ok, "%s 的權限點 %q 不在目錄", e.Key(), e.Perm)
				d := authz.DecideEntry(e, none)
				assert.False(t, d.Allowed || d.Unauthenticated, "%s：無任何能力者應被拒", e.Key())
				if len(e.AnyOf) == 0 {
					assert.Equal(t, authz.DenialAllOf, d.Basis, e.Key())
					assert.Equal(t, []authz.Permission{e.Perm}, d.Required, e.Key())
				} else {
					assert.Equal(t, authz.DenialAnyOf, d.Basis, e.Key())
					assert.Equal(t, append([]authz.Permission{e.Perm}, e.AnyOf...), d.Required, e.Key())
				}
			default:
				assert.Empty(t, e.Perm, e.Key())
			}
			if e.Base == authz.BaseManual {
				manual[e.Path] = true
			}
		}
		assert.Equal(t, map[string]bool{
			"/api/v1/connect": true, "/api/v1/db-console": true, "/api/v1/ssh": true,
			"/api/v1/sessions/:id/monitor": true, "/api/v1/sessions/share/:code/ws": true,
		}, manual, "手動認證入口只登錄標記")
	})

	t.Run("未登錄路由一律拒絕，任何主體皆然", func(t *testing.T) {
		for name, p := range map[string]*authz.Principal{
			"super_admin": principalOf(model.BuiltinSuperAdmin, ""), "auditor": principalOf(model.BuiltinAuditor, ""), "nil": nil,
		} {
			code, body := serve(t, "GET", "/api/v1/__not_in_registry", p)
			assert.Equal(t, http.StatusForbidden, code, name)
			assert.Equal(t, "AUTH_PERMISSION_DENIED", body["code"], name)
			assert.NotContains(t, body, "required_permission", "%s：預設拒絕不帶權限名", name)
			assert.Len(t, body, 2, "%s：預設拒絕本文只有 code、error", name)
			assert.NotEqual(t, true, body["reached"], name)
		}
		// 已登錄路徑但 method 未登錄 → 同樣拒絕
		code, _ := serve(t, "PATCH", "/api/v1/alert-rules/:id", principalOf(model.BuiltinSuperAdmin, ""))
		assert.Equal(t, http.StatusForbidden, code)
	})

	t.Run("執行中介層依登錄項判定，拒絕一律單一形狀", func(t *testing.T) {
		singleShape := func(body map[string]any, msg string) {
			t.Helper()
			assert.Len(t, body, 2, msg)
			assert.Contains(t, body, "error", msg)
			assert.Equal(t, "AUTH_PERMISSION_DENIED", body["code"], msg)
		}
		// 原 RequireRole(admin)：稽核員被拒，不再帶角色名
		code, body := serve(t, "DELETE", "/api/v1/alert-rules/:id", principalOf(model.BuiltinAuditor, ""))
		assert.Equal(t, 403, code)
		singleShape(body, "原角色閘")
		code, body = serve(t, "DELETE", "/api/v1/alert-rules/:id", principalOf(model.BuiltinSuperAdmin, ""))
		assert.Equal(t, 200, code)
		assert.Equal(t, true, body["reached"])
		// 原 RequirePermission：純審核者被拒，不再帶權限點
		code, body = serve(t, "GET", "/api/v1/assets", principalOf(model.BuiltinApprover, ""))
		assert.Equal(t, 403, code)
		singleShape(body, "原權限點閘")
		// 一般使用者可讀資產列表，不可寫
		code, _ = serve(t, "GET", "/api/v1/assets", principalOf(model.BuiltinUser, ""))
		assert.Equal(t, 200, code)
		code, _ = serve(t, "DELETE", "/api/v1/assets/:id", principalOf(model.BuiltinUser, ""))
		assert.Equal(t, 403, code)
		// 稽核員可讀稽核完整性（原 RequireAnyRole(admin, auditor)）
		code, _ = serve(t, "GET", "/api/v1/audit-checkpoints", principalOf(model.BuiltinAuditor, ""))
		assert.Equal(t, 200, code)
		// 需登入的路由：無主體回 401、有主體放行；公開路由無主體放行
		code, _ = serve(t, "GET", "/api/v1/access-requests/mine", nil)
		assert.Equal(t, 401, code)
		code, _ = serve(t, "GET", "/api/v1/access-requests/mine", principalOf(model.BuiltinApprover, ""))
		assert.Equal(t, 200, code)
		code, _ = serve(t, "GET", "/api/v1/auth/banner", nil)
		assert.Equal(t, 200, code)
	})

	t.Run("欄位條件：以合成能力集合驗正反向", func(t *testing.T) {
		const method, path, field = "GET", "/api/v1/assets/:id/accounts", "credential_identity_fields"
		assert.True(t, authz.FieldCapability(method, path, field, principalOf(model.BuiltinSuperAdmin, "")), "持有額外能力 → 准")
		assert.False(t, authz.FieldCapability(method, path, field, principalOf(model.BuiltinAuditor, "")), "稽核員無 credential:manage → 拒")
		assert.False(t, authz.FieldCapability(method, path, field, principalOf(model.BuiltinUser, "")), "一般使用者 → 拒")
		assert.False(t, authz.FieldCapability(method, path, field, principalOf(model.BuiltinApprover, "")), "純審核者 → 拒")
		assert.False(t, authz.FieldCapability(method, path, field, nil), "無主體 → 拒")
		assert.False(t, authz.FieldCapability(method, path, "undeclared_field", principalOf(model.BuiltinSuperAdmin, "")), "未宣告的欄位 → 拒（宣告缺漏不得放行）")
		assert.False(t, authz.FieldCapability("GET", "/api/v1/__nope", field, principalOf(model.BuiltinSuperAdmin, "")), "未登錄路由 → 拒")
		// 所有欄位條件能力在目前的內建範本下只有超管持有（宣告不改變任何既有結果）
		for _, e := range authz.RegistryEntries() {
			for _, f := range e.Fields {
				for _, key := range []string{model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover} {
					assert.False(t, principalOf(key, "").Has(f.Perm), "%s 的欄位條件能力 %s 不得為 %s 範本持有", e.Key(), f.Perm, key)
				}
			}
		}
	})

	// ---- 3.1 權限點目錄 ----

	t.Run("目錄：scoped-enforced 只有已逐鍵啟用者", func(t *testing.T) {
		// 與 TestScopedEnforcedRequiresTargetResolution/product_catalogue_zero 同一張啟用表：
		// 啟用一鍵須先宣告其目標解析或列表投影，這裡防止未宣告的鍵被改標
		enabled := map[authz.Permission]bool{authz.PermAssetGroupManage: true,
			authz.PermAssetUpdate: true, authz.PermAssetDelete: true, authz.PermAssetTest: true, authz.PermAssetView: true,
			authz.PermCredentialView: true, authz.PermCredentialCreate: true, authz.PermCredentialUpdate: true,
			authz.PermCredentialSetSecret: true, authz.PermCredentialRotate: true, authz.PermCredentialConvertScope: true,
			authz.PermCredentialDetach: true, authz.PermCredentialDelete: true, authz.PermCredentialBind: true,
			authz.PermAuthorizationManage: true, authz.PermApproverScopeManage: true, authz.PermAssetCreate: true,
			authz.PermChangeSecretManage: true, authz.PermAccountRotate: true, authz.PermAccessPolicyManage: true}
		got := map[authz.Permission]bool{}
		for _, d := range authz.Catalog() {
			if d.Scope == authz.ScopeEnforced {
				got[d.Key] = true
				assert.True(t, enabled[d.Key], "%s：未逐鍵啟用的權限點不得為 scoped-enforced", d.Key)
			}
		}
		for k := range enabled {
			assert.True(t, got[k], "%s：已啟用的權限點須為 scoped-enforced", k)
		}
	})

	t.Run("目錄：沒有查看明文類與保留能力為名的權限點", func(t *testing.T) {
		for _, d := range authz.Catalog() {
			k := strings.ToLower(string(d.Key))
			for _, w := range []string{"reveal", "plaintext", "cleartext", "super", "shortcut"} {
				assert.NotContains(t, k, w, string(d.Key))
			}
		}
		for _, bad := range []authz.Permission{"credential:reveal", "secret:plaintext_read", "role:define", "superadmin:grant", "connect:shortcut_all"} {
			defs := append(authz.Catalog(), authz.PermissionDef{Key: bad, Group: authz.GroupAsset, Category: authz.CategoryManage, Scope: authz.ScopeReserved})
			assert.Error(t, authz.ValidateCatalog(defs), "保留名稱 %q 必須被目錄拒絕", bad)
		}
		assert.NoError(t, authz.ValidateCatalog(authz.Catalog()))
	})

	t.Run("目錄：計數由程式產生，登錄與範本引用的權限點都在目錄內", func(t *testing.T) {
		cat := authz.Catalog()
		keys := map[authz.Permission]bool{}
		groups := map[authz.PermGroup]int{}
		for _, d := range cat {
			assert.False(t, keys[d.Key], "重複鍵 %s", d.Key)
			keys[d.Key] = true
			groups[d.Group]++
		}
		total := 0
		for _, n := range groups {
			total += n
		}
		assert.Equal(t, len(cat), total, "各群組計數加總等於目錄總數")
		for _, e := range authz.RegistryEntries() {
			if e.Base == authz.BasePerm {
				assert.True(t, keys[e.Perm], e.Key())
			}
		}
		for _, tpl := range []string{model.BuiltinSuperAdmin, model.BuiltinAuditor, model.BuiltinUser, model.BuiltinApprover} {
			for _, p := range authz.TemplatePermissions(tpl) {
				assert.True(t, keys[p], "範本 %s 的 %s 不在目錄", tpl, p)
			}
		}
	})
}
