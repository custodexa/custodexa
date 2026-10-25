package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestForbiddenSingleShape 能力拒絕的單一形狀守衛。
//
// 程式化列舉 authz.RegistryEntries()，每條非公開路由各打一發：
//   - 權限點路由：一般使用者與「無任何能力」主體各一發。被拒者本文的鍵恰為 code、error，
//     碼為 AUTH_PERMISSION_DENIED，原文不含任何目錄權限鍵、admin／auditor／approver 與三語角色譯名；
//     放行者計入放行數，不當作拒絕案例。
//   - 僅需登入、手動認證、資料面路由：登錄閘必放行（拒絕發生在 handler 內，不經登錄閘）。
//   - 欄位條件決定能力的路由：登錄閘放行後由 handler 的欄位閘判定，以 fieldGateProbes 實打 handler
//     並斷言同一形狀；出現沒有對應探針的這類路由即失敗，不得靜默跳過。
//   - 服務層子案例：handler 內的能力類寫出點（超管保留守衛、標籤治理與標籤列表、資產更新欄位閘、
//     會話強制終止、儀表板卡片、主機身分確認）以與正式組裝相同的守衛鏈實打，本文須與登錄閘拒絕
//     逐位元相同，依據存入脈絡。
//
// 新增路由只要進了登錄表就自動被涵蓋。

// serviceProbe 以指定主體跑一條與正式組裝相同的守衛鏈（mount 掛路由），回收回應與存入脈絡的拒絕依據。
func serviceProbe(p *authz.Principal, method, path, body string, mount func(r gin.IRoutes)) shapeProbe {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var out shapeProbe
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "shape-probe")
		middleware.SetPrincipal(c, p)
		c.Next()
		out.denial, out.hasDeny = middleware.CapabilityDenialFrom(c)
	})
	mount(r)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	out.code = w.Code
	out.raw = w.Body.String()
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

// fieldGateProbe 對資產更新（欄位閘）打一發：路由與正式組裝同為登錄閘＋handler。
func fieldGateProbe(t *testing.T, p *authz.Principal, id uint, body string) shapeProbe {
	env := newFieldCapEnv(t)
	h := api.NewAssetHandler(env.assets, nil, nil)
	return serviceProbe(p, "PUT", fmt.Sprintf("/api/v1/assets/%d", id), body, func(r gin.IRoutes) {
		r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Update)
	})
}

// fieldGateProbes 欄位條件決定能力的路由各一支探針（以一般使用者打不存在的 ID）。
// 登錄表新增這類路由而未補探針時，TestForbiddenSingleShape 失敗。
var fieldGateProbes = map[string]func(t *testing.T, p *authz.Principal) shapeProbe{
	"PUT /api/v1/assets/:id": func(t *testing.T, p *authz.Principal) shapeProbe {
		return fieldGateProbe(t, p, 99999, `{"description":"x"}`)
	},
}

// shapeProbe 一次請求的結果。
type shapeProbe struct {
	code    int
	raw     string
	body    map[string]any
	reached bool
	denial  middleware.CapabilityDenial
	hasDeny bool
}

// probeGate 以指定主體對單一路由跑登錄閘，閘後放一個標記 handler。
func probeGate(method, pattern string, p *authz.Principal) shapeProbe {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var out shapeProbe
	r.Use(func(c *gin.Context) {
		if p != nil {
			middleware.SetPrincipal(c, p)
		}
		c.Next()
		out.denial, out.hasDeny = middleware.CapabilityDenialFrom(c)
	})
	r.Handle(method, pattern, middleware.EnforceRegistry(), func(c *gin.Context) {
		out.reached = true
		c.JSON(http.StatusOK, gin.H{"reached": true})
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, pattern, nil))
	out.code = w.Code
	out.raw = w.Body.String()
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

// shapeLocaleDir 取 locale 目錄：環境覆寫、容器掛載點、往上找 repo 內路徑；都找不到即失敗。
func shapeLocaleDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("APIERROR_LOCALE_DIR"); d != "" {
		return d
	}
	if st, err := os.Stat("/app/testdata/locales"); err == nil && st.IsDir() {
		return "/app/testdata/locales"
	}
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "frontend", "src", "i18n", "locales")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("找不到 locale 目錄：讀不到角色譯名就等於沒有守衛，故失敗而非跳過")
	return ""
}

// shapeRoleNames 從三語 locale 讀出內建角色與管理角色的譯名（不寫死）。
func shapeRoleNames(t *testing.T) []string {
	t.Helper()
	dir := shapeLocaleDir(t)
	set := map[string]bool{}
	for _, lang := range []string{"zh-TW", "en-US", "ja-JP"} {
		raw, err := os.ReadFile(filepath.Join(dir, lang+".json"))
		require.NoError(t, err, lang)
		var doc struct {
			Enum struct {
				Role map[string]struct {
					Label string `json:"label"`
				} `json:"role"`
			} `json:"enum"`
			Roles map[string]json.RawMessage `json:"roles"`
		}
		require.NoError(t, json.Unmarshal(raw, &doc), lang)
		for _, key := range []string{"admin", "auditor", "approver"} {
			l := doc.Enum.Role[key].Label
			require.NotEmpty(t, l, "%s enum.role.%s.label", lang, key)
			set[l] = true
		}
		for _, key := range []string{"identityAdmin", "securityAdmin"} {
			var n struct {
				Name string `json:"name"`
			}
			require.NoError(t, json.Unmarshal(doc.Roles[key], &n), "%s roles.%s", lang, key)
			require.NotEmpty(t, n.Name, "%s roles.%s.name", lang, key)
			set[n.Name] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestForbiddenSingleShape(t *testing.T) {
	roleNames := shapeRoleNames(t)
	require.GreaterOrEqual(t, len(roleNames), 9, "三語譯名集合不得為空殼")
	var catalogKeys []string
	for _, d := range authz.Catalog() {
		catalogKeys = append(catalogKeys, string(d.Key))
	}
	require.NotEmpty(t, catalogKeys)

	user := principalOf(model.BuiltinUser, "")
	// 純審核者的能力集合為空（沒有任何指派時視為一般使用者，不能拿來當無能力主體）。
	none := principalOf(model.BuiltinApprover, "")

	// 單一形狀斷言：鍵恰為 code、error，碼固定，原文不含任何權限名、角色名。
	assertShape := func(t *testing.T, who string, e authz.RouteEntry, pr shapeProbe, wantBasis authz.DenialBasis) {
		t.Helper()
		msg := who + " " + e.Key()
		assert.Equal(t, http.StatusForbidden, pr.code, msg)
		require.Len(t, pr.body, 2, "%s：本文鍵須恰為 code、error，實得 %s", msg, pr.raw)
		assert.Contains(t, pr.body, "code", msg)
		assert.Contains(t, pr.body, "error", msg)
		assert.Equal(t, "AUTH_PERMISSION_DENIED", pr.body["code"], msg)
		lower := strings.ToLower(pr.raw)
		for _, k := range catalogKeys {
			assert.NotContains(t, lower, strings.ToLower(k), "%s：不得含權限鍵", msg)
		}
		for _, w := range []string{"admin", "auditor", "approver"} {
			assert.NotContains(t, lower, w, "%s：不得含角色詞", msg)
		}
		for _, n := range roleNames {
			assert.NotContains(t, pr.raw, n, "%s：不得含角色譯名", msg)
		}
		assert.False(t, pr.reached, msg)
		if assert.True(t, pr.hasDeny, "%s：依據須存入脈絡", msg) {
			assert.Equal(t, wantBasis, pr.denial.Basis, msg)
		}
	}

	var (
		total, publicN, manualN, authedN, dataPlaneN, fieldN int
		permAllOf, permAnyOf                                 int
		userDenied, userAllowed, noneDenied                  int
		anyOnlyUserDenied                                    int
		fieldProbed                                          []string
	)
	var sample string // 同一份本文的位元組基準，供未登錄路由與各案例逐位元比對

	entries := authz.RegistryEntries()
	require.Greater(t, len(entries), 200, "登錄表不得為空殼")
	for _, e := range entries {
		total++
		key := e.Key()
		hasWildcard := false
		for _, f := range e.Fields {
			if f.Field == authz.FieldWildcard {
				hasWildcard = true
			}
		}
		switch e.Base {
		case authz.BasePublic:
			publicN++
		case authz.BaseManual:
			manualN++
			pr := probeGate(e.Method, e.Path, user)
			assert.True(t, pr.reached, "%s：手動認證入口登錄閘必放行", key)
		case authz.BaseAuthenticated, authz.BaseSelf:
			pr := probeGate(e.Method, e.Path, user)
			assert.True(t, pr.reached, "%s：僅需登入的路由登錄閘必放行（拒絕在 handler 內）", key)
			assert.Empty(t, e.AnyOf, key)
			if e.DataPlane {
				dataPlaneN++
				assert.Empty(t, e.Perm, "%s：資料面路由不帶管理權限點", key)
				assert.False(t, pr.hasDeny, "%s：資料面拒絕不經能力拒絕函式", key)
				continue
			}
			authedN++
			if hasWildcard {
				fieldN++
				probe, ok := fieldGateProbes[key]
				if !ok {
					t.Errorf("%s：欄位條件路由沒有對應探針，須在 fieldGateProbes 補上，不得靜默跳過", key)
					continue
				}
				pr := probe(t, user)
				assertShape(t, "user", e, pr, authz.DenialAllOf)
				fieldProbed = append(fieldProbed, key)
			}
		case authz.BasePerm:
			if len(e.AnyOf) == 0 {
				permAllOf++
			} else {
				permAnyOf++
			}
			wantBasis := authz.DenialAllOf
			if len(e.AnyOf) > 0 {
				wantBasis = authz.DenialAnyOf
			}
			prU := probeGate(e.Method, e.Path, user)
			if prU.reached {
				userAllowed++
				assert.Equal(t, http.StatusOK, prU.code, key)
			} else {
				userDenied++
				if len(e.AnyOf) > 0 {
					anyOnlyUserDenied++
				}
				assertShape(t, "user", e, prU, wantBasis)
				if sample == "" {
					sample = prU.raw
				}
				assert.JSONEq(t, sample, prU.raw, "%s：各路由的能力拒絕本文須完全相同", key)
			}
			prN := probeGate(e.Method, e.Path, none)
			require.False(t, prN.reached, "%s：無任何能力的主體不得放行", key)
			noneDenied++
			assertShape(t, "none", e, prN, wantBasis)
			assert.JSONEq(t, sample, prN.raw, "%s：無能力主體的拒絕本文須與一般使用者相同", key)
		default:
			t.Errorf("%s：未知 Base %q，須歸類", key, e.Base)
		}
	}

	// 探針表的每一項都必須真的是登錄表上的欄位條件路由（不得留下打不到的殼）。
	assert.Equal(t, len(fieldGateProbes), len(fieldProbed), "探針表與列舉出的欄位條件路由須一一對應：%v", fieldProbed)
	assert.Equal(t, total, publicN+manualN+authedN+dataPlaneN+permAllOf+permAnyOf, "每條路由都要歸入一類，沒有靜默跳過")
	assert.Greater(t, userDenied, 0)
	assert.Greater(t, anyOnlyUserDenied, 0, "至少一條只有 AnyOf 可進入的路由被一般使用者實際打到拒絕")
	require.NotEmpty(t, sample)
	t.Logf("列舉 %d 條：公開 %d、手動認證 %d、僅需登入 %d（含欄位條件 %d）、資料面 %d、權限點 %d（單一 %d、AnyOf %d）",
		total, publicN, manualN, authedN, fieldN, dataPlaneN, permAllOf+permAnyOf, permAllOf, permAnyOf)
	t.Logf("權限點路由：一般使用者被拒 %d（其中 AnyOf %d）、放行 %d；無能力主體被拒 %d；欄位條件路由實打 %v", userDenied, anyOnlyUserDenied, userAllowed, noneDenied, fieldProbed)

	t.Run("測試注入的未登錄路由同形", func(t *testing.T) {
		for name, p := range map[string]*authz.Principal{"user": user, "none": none, "super_admin": principalOf(model.BuiltinSuperAdmin, "")} {
			pr := probeGate("GET", "/api/v1/__not_in_registry", p)
			assertShape(t, name, authz.RouteEntry{Method: "GET", Path: "/api/v1/__not_in_registry"}, pr, authz.DenialUnregistered)
			assert.Empty(t, pr.denial.Required, name)
			assert.JSONEq(t, sample, pr.raw, "%s：未登錄路由須與登錄路由的能力拒絕逐位元相同", name)
		}
		// 已登錄路徑但 method 未登錄
		pr := probeGate("PATCH", "/api/v1/alert-rules/:id", user)
		assertShape(t, "user", authz.RouteEntry{Method: "PATCH", Path: "/api/v1/alert-rules/:id"}, pr, authz.DenialUnregistered)
		assert.JSONEq(t, sample, pr.raw)
	})

	t.Run("服務層子案例", func(t *testing.T) {
		auditor := principalOf(model.BuiltinAuditor, "")
		viewOnly := customPrincipal(authz.PermAssetView)
		assetEditor := customPrincipal(authz.PermAssetUpdate, authz.PermAssetView)
		policyManager := customPrincipal(authz.PermAccessPolicyManage, authz.PermAssetView)
		authzManager := customPrincipal(authz.PermAuthorizationManage)
		terminator := customPrincipal(authz.PermSessionTerminate, authz.PermSessionView)

		type mountFn = func(t *testing.T) func(r gin.IRoutes)
		static := func(m func(r gin.IRoutes)) mountFn {
			return func(*testing.T) func(gin.IRoutes) { return m }
		}
		// 以下各組守衛鏈與對應 RegisterRoutes 相同（身分以測試注入取代 token 驗證）
		assetRoutes := func(t *testing.T) func(r gin.IRoutes) {
			env := newFieldCapEnv(t)
			ah := api.NewAssetHandler(env.assets, nil, nil)
			hh := api.NewHostKeyHandler(nil, nil)
			return func(r gin.IRoutes) {
				r.GET("/api/v1/assets/tags", middleware.EnforceRegistry(), ah.ListTags)
				r.POST("/api/v1/assets/tags/rename", middleware.EnforceRegistry(), ah.RenameTag)
				r.POST("/api/v1/assets/tags/delete", middleware.EnforceRegistry(), ah.DeleteTag)
				r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(), ah.Update)
				r.DELETE("/api/v1/assets/:id/host-key", middleware.EnforceRegistry(), api.RequireHostKeyResetSuperAdmin, hh.Reset)
				r.POST("/api/v1/assets/:id/host-key/adopt", middleware.EnforceRegistry(), api.RequireHostKeyResetSuperAdmin, hh.Adopt)
			}
		}
		auditFailureRoutes := static(func(r gin.IRoutes) {
			h := api.NewAuditFailureHandler(nil)
			r.POST("/api/v1/audit-failures/permission-state/accept", middleware.EnforceRegistry(), api.RequirePermissionAcceptSuperAdmin, h.AcceptPermissionState)
		})
		authorizationRoutes := func(t *testing.T) func(r gin.IRoutes) {
			env := newFieldCapEnv(t)
			require.NoError(t, env.db.AutoMigrate(&model.User{}))
			h := api.NewAuthorizationHandler(nil, nil)
			// 經正式 RegisterRoutes 注入角色現況事實源（掛在不使用的群組上）；現查查無此人＝非超管
			h.RegisterRoutes(gin.New().Group("/unused"), identity.NewAuthService("shape-probe-only", time.Hour))
			return func(r gin.IRoutes) {
				r.PUT("/api/v1/authorizations/:id/accounts", middleware.EnforceRegistry(), h.UpdateAccounts)
			}
		}
		sessionRoutes := static(func(r gin.IRoutes) {
			h := api.NewSessionHandler(nil)
			r.POST("/api/v1/sessions/:id/terminate", middleware.EnforceRegistry(), h.Terminate)
		})

		reservedSet := map[string]bool{
			authz.ReservedSuperAdmin: true, authz.ReservedSuperAdminOrAuditor: true,
			authz.ReservedApproverEligibility: true, authz.ReservedRevokeEligibility: true,
		}
		upd, ap := string(authz.PermAssetUpdate), string(authz.PermAccessPolicyManage)
		cases := []struct {
			name, method, path, body string
			who                      *authz.Principal
			mount                    mountFn
			basis                    authz.DenialBasis
			required                 []string
		}{
			{"標籤列表：非超管非稽核員", "GET", "/api/v1/assets/tags", "", viewOnly, assetRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdminOrAuditor}},
			{"標籤改名：缺資產編輯能力", "POST", "/api/v1/assets/tags/rename", `{"from":"a","to":"b"}`, user, assetRoutes, authz.DenialAllOf, []string{upd}},
			{"標籤改名：持資產編輯能力的非超管", "POST", "/api/v1/assets/tags/rename", `{"from":"a","to":"b"}`, assetEditor, assetRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"標籤刪除：缺資產編輯能力", "POST", "/api/v1/assets/tags/delete", `{"name":"a"}`, auditor, assetRoutes, authz.DenialAllOf, []string{upd}},
			{"標籤刪除：持資產編輯能力的非超管", "POST", "/api/v1/assets/tags/delete", `{"name":"a"}`, assetEditor, assetRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"主機金鑰重置：稽核員", "DELETE", "/api/v1/assets/1/host-key", "", auditor, assetRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"主機金鑰採用：持資產編輯能力的非超管", "POST", "/api/v1/assets/1/host-key/adopt", `{"fingerprint":"SHA256:x"}`, assetEditor, assetRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"失效事件確認：稽核員", "POST", "/api/v1/audit-failures/permission-state/accept", `{"reason":"r"}`, auditor, auditFailureRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"失效事件確認：一般使用者", "POST", "/api/v1/audit-failures/permission-state/accept", `{"reason":"r"}`, user, auditFailureRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"授權帳號範圍：持授權管理能力但現查非超管", "PUT", "/api/v1/authorizations/1/accounts", `{"accounts":["@ALL"]}`, authzManager, authorizationRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"會話強制終止：持終止能力的非超管", "POST", "/api/v1/sessions/1/terminate", "", terminator, sessionRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}},
			{"資產更新欄位閘：兩個權限點都沒有＋不存在 ID（只送 access_policy）", "PUT", "/api/v1/assets/99999", `{"access_policy":"approval"}`, viewOnly, assetRoutes, authz.DenialAllOf, []string{upd}},
			{"資產更新欄位閘：兩個權限點都沒有＋不存在 ID（其他欄位）", "PUT", "/api/v1/assets/99999", `{"description":"x"}`, viewOnly, assetRoutes, authz.DenialAllOf, []string{upd}},
			{"資產更新欄位閘：兩個權限點都沒有＋不存在 ID（空本文）", "PUT", "/api/v1/assets/99999", "", viewOnly, assetRoutes, authz.DenialAllOf, []string{upd}},
			{"資產更新欄位閘：只持資產編輯能力帶 access_policy", "PUT", "/api/v1/assets/99999", `{"access_policy":"approval"}`, assetEditor, assetRoutes, authz.DenialAllOf, []string{ap}},
			{"資產更新欄位閘：只持存取政策權限點夾帶其他欄位", "PUT", "/api/v1/assets/99999", `{"access_policy":"approval","name":"x"}`, policyManager, assetRoutes, authz.DenialAllOf, []string{upd}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				pr := serviceProbe(c.who, c.method, c.path, c.body, c.mount(t))
				assertShape(t, c.name, authz.RouteEntry{Method: c.method, Path: c.path}, pr, c.basis)
				assert.Equal(t, sample, pr.raw, "%s：須與登錄閘的能力拒絕逐位元相同", c.name)
				assert.Equal(t, c.required, pr.denial.Required, "%s：拒絕依據所列鍵", c.name)
				if c.basis == authz.DenialReserved {
					for _, v := range pr.denial.Required {
						assert.True(t, reservedSet[v], "%s：保留條件值 %q 不在受控清單", c.name, v)
					}
				}
			})
		}
		for key, probe := range fieldGateProbes {
			assert.Equal(t, sample, probe(t, user).raw, "%s：欄位閘探針須與登錄閘的能力拒絕逐位元相同", key)
		}
	})
	t.Run("服務層子案例（資格、監看、指派、預覽）", func(t *testing.T) { outletSubcases(t, sample, assertShape) })
	t.Run("服務層子案例（儀表板卡片、主機身分確認）", func(t *testing.T) { handlerCapabilitySubcases(t, sample, assertShape) })
	t.Run("規則拒絕子案例", testRuleDenialSubcases)

	t.Run("資料面路由登錄只要求已認證", func(t *testing.T) {
		n := 0
		for _, e := range entries {
			if !e.DataPlane {
				continue
			}
			n++
			assert.Equal(t, authz.BaseAuthenticated, e.Base, e.Key())
			pr := probeGate(e.Method, e.Path, nil)
			assert.Equal(t, http.StatusUnauthorized, pr.code, "%s：未認證回 401，不是能力拒絕", e.Key())
			assert.False(t, pr.hasDeny, e.Key())
		}
		assert.Equal(t, dataPlaneN, n)
		assert.Greater(t, n, 0)
	})
}
