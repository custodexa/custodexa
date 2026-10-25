package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestScopeDenialOutlet 範圍拒絕共用出口的守衛。
//
//   - 種類對照：對照表每列一案，以 authz.ErrScopeDenied 構造輸入交給出口（不經判定器），回應須與
//     「全域主體打不存在 ID」逐位元相同。基準取兩處且兩處須一致：改前寫法（apierror.Respond 404、該碼、
//     無參數）與真實 handler 的不存在分支（已改經同一張表）。對照表的列集合以本測試的期望表核對，
//     增刪列必須同步改這裡。
//
//   - 能力先於範圍：能力拒絕交出口時為 403 單一形狀，不查對照表。
//
//   - 未登記種類：403 單一形狀、伺服端日誌、標記原因 kind_unmapped；不放行。
//
//   - 批次：同筆數下混入範圍外、不存在、無權三種 ID 的回應逐位元相同，只帶 count。
//
//   - AST：生產碼傳給出口的種類常數皆已登記（含合成反例）。
//
//   - 登錄閘：宣告了目標的登錄項經判定器與出口寫出（scope_gate_http_test.go）。
//
//   - 交易內重判：服務在寫入交易內改掛載後判出範圍拒絕，回應與範圍外案例逐位元相同、整筆回滾
//     （SQLite 與 PostgreSQL；scope_tx_recheck_test.go）。
//
//   - AST：authz 以外的生產碼不建構、不改寫範圍拒絕值（scope_denied_construction_ast_test.go）。
func TestScopeDenialOutlet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	baselines := scopeNotFoundBaselines(t)

	t.Run("對照表列集合", func(t *testing.T) {
		var got []string
		for _, r := range middleware.ScopeNotFoundRegistrations() {
			got = append(got, string(r.Kind)+"/"+string(r.Layer)+"→"+string(r.Code))
		}
		var want []string
		for _, e := range expectedScopeNotFound() {
			want = append(want, string(e.kind)+"/"+string(e.layer)+"→"+string(e.code))
		}
		// 受控 params 也須與期望表一致（客體種類決定 entity）
		for _, r := range middleware.ScopeNotFoundRegistrations() {
			for _, e := range expectedScopeNotFound() {
				if r.Kind == e.kind && r.Layer == e.layer {
					assert.Equal(t, e.params, r.Params, "%s/%s 的 params", r.Kind, r.Layer)
				}
			}
		}
		sort.Strings(got)
		sort.Strings(want)
		assert.Equal(t, want, got)
	})

	for _, e := range expectedScopeNotFound() {
		e := e
		t.Run("種類對照/"+string(e.kind)+"/"+string(e.layer), func(t *testing.T) {
			legacy := legacyBody(t, http.StatusNotFound, e.code, e.params)
			real, ok := baselines[e.baseline]
			require.True(t, ok, "缺真實 handler 基準 %s", e.baseline)
			assert.Equal(t, http.StatusNotFound, real.code, "真實 handler 不存在分支：%s", real.raw)
			assert.Equal(t, legacy, real.raw, "真實 handler 不存在分支須與改前寫法逐位元相同")
			assert.False(t, real.hasScope, "真不存在分支不得留範圍拒絕標記")
			for _, reason := range []authz.ScopeReason{authz.ScopeReasonOutOfScope, authz.ScopeReasonResolverMissing, authz.ScopeReasonTopologyUnavailable} {
				pr := scopeOutletServe(t, func(c *gin.Context) {
					res := authz.ScopeResult{Outcome: authz.ScopeDenyScope, Reason: reason}
					if middleware.RespondAuthzDecision(c, res, authz.NewErrScopeDenied(e.kind, e.layer, reason), middleware.CapabilityDenial{}) {
						return
					}
					c.JSON(http.StatusOK, gin.H{"reached": true})
				})
				assert.Equal(t, http.StatusNotFound, pr.code, "%s：%s", reason, pr.raw)
				assert.Equal(t, legacy, pr.raw, "%s：範圍拒絕須與全域主體打不存在 ID 逐位元相同", reason)
				assert.Equal(t, real.raw, pr.raw, "%s：範圍拒絕須與真實 handler 不存在分支逐位元相同", reason)
				require.True(t, pr.hasScope, "%s：須留範圍拒絕標記", reason)
				assert.Equal(t, map[string]string{"denial": "scope", "scope_reason": string(reason)}, pr.scope.AuditDetails())
				assert.False(t, pr.hasCap, "範圍拒絕不得留能力拒絕依據")
			}
		})
	}

	t.Run("能力先於範圍", func(t *testing.T) {
		legacy := legacyPermissionDeniedBody(t)
		basis := middleware.AllOfCapabilityDenial(authz.PermAssetUpdate)
		pr := scopeOutletServe(t, func(c *gin.Context) {
			res := authz.ScopeResult{Outcome: authz.ScopeDenyCapability, Reason: authz.ScopeReasonNoEffectiveBinding}
			if middleware.RespondAuthzDecision(c, res, nil, basis) {
				return
			}
			c.JSON(http.StatusOK, gin.H{"reached": true})
		})
		assert.Equal(t, http.StatusForbidden, pr.code)
		assert.Equal(t, legacy, pr.raw)
		require.True(t, pr.hasCap)
		assert.Equal(t, basis, pr.cap)
		assert.False(t, pr.hasScope)
	})

	t.Run("放行", func(t *testing.T) {
		pr := scopeOutletServe(t, func(c *gin.Context) {
			if middleware.RespondAuthzDecision(c, authz.ScopeResult{Outcome: authz.ScopeAllow}, nil, middleware.CapabilityDenial{}) {
				return
			}
			c.JSON(http.StatusOK, gin.H{"reached": true})
		})
		assert.Equal(t, http.StatusOK, pr.code, pr.raw)
		assert.False(t, pr.hasScope)
		assert.False(t, pr.hasCap)
	})

	t.Run("不一致結果不放行", func(t *testing.T) {
		denied := authz.NewErrScopeDenied(authz.ScopeTargetAsset, authz.ScopeLayerAsset, authz.ScopeReasonOutOfScope)
		for name, in := range map[string]struct {
			res    authz.ScopeResult
			denied *authz.ErrScopeDenied
		}{
			"零值":       {authz.ScopeResult{}, nil},
			"範圍拒絕無拒絕值": {authz.ScopeResult{Outcome: authz.ScopeDenyScope, Reason: authz.ScopeReasonOutOfScope}, nil},
			"放行卻帶拒絕值":  {authz.ScopeResult{Outcome: authz.ScopeAllow}, denied},
			"能力拒絕帶拒絕值": {authz.ScopeResult{Outcome: authz.ScopeDenyCapability}, denied},
		} {
			pr := scopeOutletServe(t, func(c *gin.Context) {
				if middleware.RespondAuthzDecision(c, in.res, in.denied, middleware.CapabilityDenial{}) {
					return
				}
				c.JSON(http.StatusOK, gin.H{"reached": true})
			})
			assert.Equal(t, http.StatusInternalServerError, pr.code, "%s：%s", name, pr.raw)
			assert.NotContains(t, pr.raw, "reached", name)
			assert.Equal(t, string(apierror.CodeInternalPermissionCheck), pr.body["code"], "%s：通用權限檢查失敗碼", name)
			assert.NotContains(t, pr.raw, "NOTFOUND", "%s：不得偽裝成不存在", name)
			assert.False(t, pr.hasScope, "%s：不留範圍拒絕標記", name)
			assert.False(t, pr.hasCap, "%s：不留能力拒絕標記", name)
		}
		pr := scopeOutletServe(t, func(c *gin.Context) { middleware.RespondScopeDenied(c, nil) })
		assert.Equal(t, http.StatusInternalServerError, pr.code, pr.raw)
		assert.Equal(t, string(apierror.CodeInternalPermissionCheck), pr.body["code"])
		assert.False(t, pr.hasScope)
	})

	t.Run("未登記種類", func(t *testing.T) {
		legacy := legacyPermissionDeniedBody(t)
		cases := []struct {
			name  string
			kind  authz.ScopeTargetKind
			layer authz.ScopeDeniedLayer
		}{
			{"已登記種類配未登記層（節點種類配資產層）", authz.ScopeTargetNode, authz.ScopeLayerAsset},
			{"未登記的種類值", authz.ScopeTargetKind("unregistered"), authz.ScopeLayerTarget},
			{"已登記種類配未登記層", authz.ScopeTargetAsset, authz.ScopeLayerAccount},
		}
		for _, k := range cases {
			for _, path := range []string{"outlet", "not_found"} {
				var buf bytes.Buffer
				prev := log.Writer()
				log.SetOutput(&buf)
				pr := scopeOutletServe(t, func(c *gin.Context) {
					if path == "outlet" {
						res := authz.ScopeResult{Outcome: authz.ScopeDenyScope, Reason: authz.ScopeReasonOutOfScope}
						if middleware.RespondAuthzDecision(c, res, authz.NewErrScopeDenied(k.kind, k.layer, authz.ScopeReasonOutOfScope), middleware.CapabilityDenial{}) {
							return
						}
					} else {
						middleware.RespondTargetNotFound(c, k.kind, k.layer)
						if c.IsAborted() {
							return
						}
					}
					c.JSON(http.StatusOK, gin.H{"reached": true})
				})
				log.SetOutput(prev)
				assert.Equal(t, http.StatusForbidden, pr.code, "%s/%s：%s", k.name, path, pr.raw)
				assert.Equal(t, legacy, pr.raw, "%s/%s：須為能力拒絕的 403 單一形狀", k.name, path)
				require.True(t, pr.hasScope, "%s/%s", k.name, path)
				assert.Equal(t, middleware.ScopeReasonKindUnmapped, pr.scope.Reason)
				assert.Equal(t, "kind_unmapped", pr.scope.AuditDetails()["scope_reason"])
				assert.Contains(t, buf.String(), "not registered in not-found table", "%s/%s：須記伺服端日誌", k.name, path)
				assert.Contains(t, buf.String(), strconv.Quote(string(k.kind)))
			}
		}
	})

	t.Run("批次", func(t *testing.T) { runBatchOutletSubtests(t) })
	t.Run("AST 種類常數皆已登記", func(t *testing.T) { runScopeKindASTSubtests(t) })
	t.Run("登錄閘", func(t *testing.T) { runScopeGateHTTPSubtests(t, baselines) })
	t.Run("交易內重判", func(t *testing.T) { runScopeTxRecheckSubtests(t, baselines) })
	t.Run("AST 拒絕值只經判定器取得", func(t *testing.T) { runScopeDeniedConstructionSubtests(t) })
}

// scopeNotFoundExpectation 期望表的一列；baseline 指向 scopeNotFoundBaselines 的真實 handler 基準。
type scopeNotFoundExpectation struct {
	kind     authz.ScopeTargetKind
	layer    authz.ScopeDeniedLayer
	code     apierror.ErrCode
	baseline string
	params   map[string]any
}

func expectedScopeNotFound() []scopeNotFoundExpectation {
	return []scopeNotFoundExpectation{
		{authz.ScopeTargetAsset, authz.ScopeLayerAsset, apierror.CodeAssetNotFound, "asset_get", nil},
		{authz.ScopeTargetAssetAccount, authz.ScopeLayerAsset, apierror.CodeAssetNotFound, "account_missing_asset", nil},
		{authz.ScopeTargetAssetAccount, authz.ScopeLayerAccount, apierror.CodeAssetAccountNotFound, "account_missing_account", nil},
		{authz.ScopeTargetNode, authz.ScopeLayerNode, apierror.CodeAssetNodeNotFound, "node_update", nil},
		{authz.ScopeTargetAuthorizationRule, authz.ScopeLayerTarget, apierror.CodeAuthorizationNotFound, "authorization_update_accounts", nil},
		{authz.ScopeTargetAuthorizationObject, authz.ScopeLayerAsset, apierror.CodeGrantReferenceNotFound, "authorization_create_asset", map[string]any{"entity": "asset"}},
		{authz.ScopeTargetAuthorizationObject, authz.ScopeLayerNode, apierror.CodeGrantReferenceNotFound, "authorization_create_node", map[string]any{"entity": "asset_group"}},
		{authz.ScopeTargetApproverScope, authz.ScopeLayerTarget, apierror.CodeApproverScopeNotFound, "approver_scope_delete", nil},
		{authz.ScopeTargetCredential, authz.ScopeLayerTarget, apierror.CodeCredentialNotFound, "credential_get", nil},
		{authz.ScopeTargetChangeSecretCandidate, authz.ScopeLayerTarget, apierror.CodeCandidateNotFound, "candidate_retry", nil},
	}
}

// scopeNotFoundBaselines 全域主體（超管）經真實 handler 打不存在 ID 的回應；鍵為基準名。
// 另斷言同碼的各端點（資產詳情、刪除、更新）彼此逐位元相同。
func scopeNotFoundBaselines(t *testing.T) map[string]scopeOutletProbe {
	t.Helper()
	env := newMarkerEnv(t, "")
	global := principalOf(model.BuiltinSuperAdmin, "")
	// 節點寫入在交易內取拓撲序列化鎖並重解主體：補上授權表與一個真實的超管使用者，節點基準改用它
	require.NoError(t, env.db.AutoMigrate(&model.User{}, &model.Role{}, &model.RolePermission{}, &model.UserGroup{},
		&model.AuthzState{}, &model.AssetAuthorization{}, &model.ApproverScope{}))
	require.NoError(t, env.db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}))
	superUser := model.User{Username: "outlet-baseline-super", Password: "x", Active: true}
	require.NoError(t, env.db.Create(&superUser).Error)
	var adminRole model.Role
	if err := env.db.Where("name = ?", model.RoleAdmin).First(&adminRole).Error; err != nil {
		adminRole = model.Role{Name: model.RoleAdmin}
		require.NoError(t, env.db.Create(&adminRole).Error)
	}
	require.NoError(t, env.db.Create(&model.UserRole{UserID: superUser.ID, RoleID: adminRole.ID,
		Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
	nodeGlobal := authz.NewPrincipal(superUser.ID, authz.TokenFacts{},
		[]authz.Assignment{{RoleName: model.BuiltinSuperAdmin, BuiltinKey: model.BuiltinSuperAdmin, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal}})
	const missing = "/999901"
	require.NoError(t, env.db.AutoMigrate(&model.ChangeSecretCandidate{}))
	candidates, err := asset.NewChangeSecretCandidateService(env.db, env.codec, env.assets, audit.NewTxSink())
	require.NoError(t, err)
	authCat, err := authz.CatalogueWithScopedEnforcedForTest(authz.PermAuthorizationManage)
	require.NoError(t, err)
	authEval := authz.NewAuthorizationScopeEvaluator(authCat, asset.NewScopeTopologyReader())
	authSvc := authz.NewAssetAuthorizationService(env.db)
	authSvc.SetWriteScope(authz.NewAuthorizationWriteScope(authEval))
	require.NoError(t, authSvc.RequireWriteScope())
	// 審核範圍：組裝同產品，服務注入寫入範圍判定（移除時先取拓撲序列化鎖、交易內重解主體再查列）
	scopeSvc := authz.NewApproverScopeService(env.db)
	scopeSvc.SetWriteScope(authz.NewApproverScopeWriteScope(authEval), authEval)
	require.NoError(t, scopeSvc.RequireWriteScope())
	mount := func(r gin.IRoutes) {
		h := api.NewAssetHandler(env.assets, nil, nil)
		r.GET("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Get)
		r.DELETE("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Delete)
		r.PUT("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Update)
		mountAccounts(env, r)
		gh := api.NewAssetGroupHandler(newWiredAssetGroupService(env.db, nil), nil, nil)
		r.PUT("/api/v1/asset-groups/:id", middleware.EnforceRegistry(), gh.Update)
		ch := api.NewCredentialHandler(env.creds, nil, nil)
		r.GET("/api/v1/credentials/:id", middleware.EnforceRegistry(), ch.Get)
		sh := api.NewChangeSecretHandler(nil, nil, candidates, nil, nil, nil)
		r.POST("/api/v1/change-secret-candidates/:id/retry", middleware.EnforceRegistry(), sh.RetryCandidate)
		// 授權規則：全域主體經真實 handler 的不存在分支（建立時客體不存在、改帳號範圍時規則不存在），
		// 組裝同產品：服務注入寫入範圍判定、handler 開啟範圍化寫入
		ah := api.NewAuthorizationHandler(authSvc, authz.NewEffectiveAccessResolver(env.db).WithScope(authEval))
		ah.EnableScopedWrites(nil, authz.NewAuthorizationSelectors(env.db, authEval))
		// 授權者須與脈絡主體一致：這兩條路由以真實超管使用者為操作者
		asSuper := func(c *gin.Context) { c.Set("userID", superUser.ID) }
		r.POST("/api/v1/authorizations", asSuper, ah.Create)
		r.PUT("/api/v1/authorizations/:id/accounts", asSuper, ah.UpdateAccounts)
		arh := api.NewAccessRequestHandler(nil, scopeSvc, env.db)
		r.DELETE("/api/v1/approver-scopes/:id", middleware.EnforceRegistry(), asSuper, arh.DeleteScope)
	}
	grantSubject := model.User{Username: "outlet-baseline-subject", Password: "x", Active: true}
	require.NoError(t, env.db.Create(&grantSubject).Error)
	subj := strconv.Itoa(int(grantSubject.ID))
	probes := map[string]scopeOutletProbe{
		"node_update":     scopeOutletRealServe(t, nodeGlobal, "PUT", "/api/v1/asset-groups"+missing, `{"name":"renamed"}`, mount),
		"asset_get":       scopeOutletRealServe(t, global, "GET", "/api/v1/assets"+missing, "", mount),
		"credential_get":  scopeOutletRealServe(t, global, "GET", "/api/v1/credentials"+missing, "", mount),
		"candidate_retry": scopeOutletRealServe(t, global, "POST", "/api/v1/change-secret-candidates"+missing+"/retry", "", mount),
		"asset_delete":    scopeOutletRealServe(t, global, "DELETE", "/api/v1/assets"+missing, "", mount),
		"asset_update":    scopeOutletRealServe(t, global, "PUT", "/api/v1/assets"+missing, `{"name":"renamed"}`, mount),
		"account_missing_asset": scopeOutletRealServe(t, global, "PUT",
			"/api/v1/assets"+missing+"/accounts/"+strconv.Itoa(int(env.seed.accountID)), `{"note":"n"}`, mount),
		"account_missing_account": scopeOutletRealServe(t, global, "PUT",
			"/api/v1/assets/"+strconv.Itoa(int(env.seed.assetID))+"/accounts/999902", `{"note":"n"}`, mount),
		"authorization_create_asset": scopeOutletRealServe(t, nodeGlobal, "POST", "/api/v1/authorizations",
			`{"user_id":`+subj+`,"asset_id":999901,"permission":"view"}`, mount),
		"authorization_create_node": scopeOutletRealServe(t, nodeGlobal, "POST", "/api/v1/authorizations",
			`{"user_id":`+subj+`,"asset_group_id":999901,"permission":"view"}`, mount),
		"authorization_update_accounts": scopeOutletRealServe(t, nodeGlobal, "PUT", "/api/v1/authorizations/999903/accounts",
			`{"accounts":["root"]}`, mount),
		"approver_scope_delete": scopeOutletRealServe(t, nodeGlobal, "DELETE", "/api/v1/approver-scopes/999904", "", mount),
	}
	for _, other := range []string{"asset_delete", "asset_update"} {
		assert.Equal(t, probes["asset_get"].raw, probes[other].raw, "資產不存在：%s 與詳情須逐位元相同", other)
		assert.Equal(t, http.StatusNotFound, probes[other].code, "%s：%s", other, probes[other].raw)
	}
	return probes
}

// scopeOutletProbe 一次請求的回應與存入脈絡的標記。
type scopeOutletProbe struct {
	code     int
	raw      string
	body     map[string]any
	scope    middleware.ScopeDenial
	hasScope bool
	cap      middleware.CapabilityDenial
	hasCap   bool
}

func scopeOutletServe(t *testing.T, h gin.HandlerFunc) scopeOutletProbe {
	t.Helper()
	return scopeOutletRealServe(t, nil, "POST", "/outlet", "", func(r gin.IRoutes) { r.POST("/outlet", h) })
}

func scopeOutletRealServe(t *testing.T, p *authz.Principal, method, path, body string, mount func(r gin.IRoutes)) scopeOutletProbe {
	t.Helper()
	r := gin.New()
	var out scopeOutletProbe
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "outlet-probe")
		if p != nil {
			middleware.SetPrincipal(c, p)
		}
		c.Next()
		out.scope, out.hasScope = middleware.ScopeDenialFrom(c)
		out.cap, out.hasCap = middleware.CapabilityDenialFrom(c)
	})
	mount(r)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	out.code = w.Code
	out.raw = w.Body.String()
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

// legacyBody 改前寫法（apierror.Respond、無參數）的回應本文。
func legacyBody(t *testing.T, status int, code apierror.ErrCode, params map[string]any) string {
	t.Helper()
	pr := scopeOutletServe(t, func(c *gin.Context) { apierror.Respond(c, status, code, params) })
	require.Equal(t, status, pr.code)
	return pr.raw
}
