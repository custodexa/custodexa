package main

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestDenialAuditClassification 拒絕的審計分類與細節。
//
// 每案經真的審計中介層與真的審計服務寫入 audit_logs，讀回該列斷言：
//   - 狀態：有拒絕分類標記即 denied（範圍拒絕的 404 亦然）；無標記者依狀態碼（非範圍判定的 404 為 failure）。
//   - details 的本段新增鍵（denial、basis、required、scope_reason、count）逐值精確相等，值只在受控集合內，
//     不含 fixture 的名稱或識別碼；其餘既有鍵（deny_reason、查詢摘要等）逐值等於改動前的寫法。
//   - 同名鍵已存在時保留既有值。
//
// 規則拒絕（與能力拒絕同碼者）無 denial 鍵、details 與改動前相同。
func TestDenialAuditClassification(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("寫出函式與出口", func(t *testing.T) {
		db := installCoverageAuditDB(t)
		for _, c := range denialOutletCases() {
			c := c
			t.Run(c.name, func(t *testing.T) { runDenialAuditCase(t, db, c) })
		}
	})

	t.Run("登錄閘與保留守衛", func(t *testing.T) {
		db := installCoverageAuditDB(t)
		for _, c := range denialGateCases() {
			c := c
			t.Run(c.name, func(t *testing.T) { runDenialAuditCase(t, db, c) })
		}
	})

	t.Run("審核資格守衛", func(t *testing.T) {
		env := newOwnerTransferEnv(t)
		ensureDenialAuditTable(t, env.db)
		mount := func(r gin.IRoutes) {
			r.POST("/api/v1/access-requests/:id/approve", middleware.EnforceRegistry(), middleware.RequireApproverRole(env.db), denialAuditReached)
			r.POST("/api/v1/access-requests/:id/revoke", middleware.EnforceRegistry(), middleware.RequireRevokeEligibility(env.db), denialAuditReached)
		}
		plain := principalOf(model.BuiltinUser, "")
		for _, c := range []denialAuditCase{
			{name: "審核：非有效審核者", method: "POST", path: "/api/v1/access-requests/1/approve", body: `{}`, uid: otUserU, who: plain, mount: mount,
				wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialReserved, authz.ReservedApproverEligibility)},
			{name: "撤銷：非超管且非有效審核者", method: "POST", path: "/api/v1/access-requests/1/revoke", body: `{}`, uid: otUserU, who: plain, mount: mount,
				wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialReserved, authz.ReservedRevokeEligibility)},
		} {
			c := c
			t.Run(c.name, func(t *testing.T) { runDenialAuditCase(t, env.db, c) })
		}
	})

	t.Run("全域主體打不存在目標", func(t *testing.T) {
		env := newMarkerEnv(t, "")
		ensureDenialAuditTable(t, env.db)
		global := principalOf(model.BuiltinSuperAdmin, "")
		mount := func(r gin.IRoutes) {
			h := api.NewAssetHandler(env.assets, nil, nil)
			r.GET("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Get)
			r.DELETE("/api/v1/assets/:id", middleware.EnforceRegistry(), h.Delete)
			mountAccounts(env, r)
		}
		fixtures := []string{"marker-host", "marker-shared", strconv.Itoa(int(env.seed.assetID)), strconv.Itoa(int(env.seed.accountID))}
		for _, c := range []denialAuditCase{
			{name: "資產詳情：不存在", method: "GET", path: "/api/v1/assets/999901", uid: 7, who: global, mount: mount,
				wantCode: http.StatusNotFound, wantStatus: model.StatusFailure},
			{name: "資產刪除：不存在", method: "DELETE", path: "/api/v1/assets/999901", uid: 7, who: global, mount: mount,
				wantCode: http.StatusNotFound, wantStatus: model.StatusFailure},
			{name: "資產帳號：帳號不存在", method: "PUT", path: "/api/v1/assets/" + strconv.Itoa(int(env.seed.assetID)) + "/accounts/999902",
				body: `{"note":"n"}`, uid: 7, who: global, mount: mount, wantCode: http.StatusNotFound, wantStatus: model.StatusFailure},
		} {
			c := c
			c.fixtures = fixtures
			t.Run(c.name, func(t *testing.T) { runDenialAuditCase(t, env.db, c) })
		}
	})

	t.Run("原因分類形狀", func(t *testing.T) {
		for _, c := range []struct{ name, details, want string }{
			{"能力拒絕/all_of", `{"denial":"capability","basis":"all_of","required":"assets.view"}`, "authz_capability_denied"},
			{"能力拒絕/保留依據", `{"denial":"capability","basis":"reserved","required":"superadmin"}`, "authz_capability_denied"},
			{"能力拒絕/與指派關卡並存", `{"denial":"capability","basis":"all_of","required":"x","deny_reason":"r"}`, "authz_capability_denied"},
			{"範圍拒絕/out_of_scope", `{"denial":"scope","scope_reason":"out_of_scope"}`, "authz_scope_denied"},
			{"範圍拒絕/kind_unmapped(403)", `{"denial":"scope","scope_reason":"kind_unmapped"}`, "authz_scope_denied"},
			{"範圍拒絕/批次", `{"denial":"scope","scope_reason":"batch_items_unavailable","count":"2"}`, "authz_scope_denied"},
		} {
			c := c
			t.Run(c.name, func(t *testing.T) {
				code, _ := audit.ClassifyAuditReason(audit.AuditReasonInput{
					Action: "update", Resource: "asset", Status: string(model.StatusDenied), Details: c.details,
				})
				assert.Equal(t, c.want, code)
			})
		}
		code, _ := audit.ClassifyAuditReason(audit.AuditReasonInput{
			Action: "update", Resource: "asset", Status: string(model.StatusDenied), Details: `{"deny_reason":"r"}`,
		})
		assert.NotContains(t, []string{"authz_capability_denied", "authz_scope_denied"}, code, "規則拒絕無 denial 鍵")
	})

	t.Run("新鍵與既有寫入點的鍵不重疊", func(t *testing.T) { assertDenialKeysDisjoint(t) })
	t.Run("新鍵與間接寫入點的鍵不重疊", func(t *testing.T) { TestDenialIndirectWritersDisjoint(t) })
	t.Run("間接掃描對反例有反應", func(t *testing.T) { TestDenialIndirectScanCatchesOverlap(t) })
}

// denialOutletCases 直接呼叫寫出函式與共用出口的案例（範圍拒絕各層與三原因、批次、未登記種類、
// 能力拒絕各依據、既有鍵並存與同名鍵）。
func denialOutletCases() []denialAuditCase {
	var cases []denialAuditCase
	layers := []struct {
		label string
		kind  authz.ScopeTargetKind
		layer authz.ScopeDeniedLayer
		path  string
	}{
		{"資產", authz.ScopeTargetAsset, authz.ScopeLayerAsset, "/api/v1/assets/31"},
		{"資產帳號的資產層", authz.ScopeTargetAssetAccount, authz.ScopeLayerAsset, "/api/v1/assets/31/accounts/32"},
		{"資產帳號的帳號層", authz.ScopeTargetAssetAccount, authz.ScopeLayerAccount, "/api/v1/assets/31/accounts/32"},
	}
	reasons := []authz.ScopeReason{authz.ScopeReasonOutOfScope, authz.ScopeReasonResolverMissing, authz.ScopeReasonTopologyUnavailable}
	for _, l := range layers {
		for _, reason := range reasons {
			l, reason := l, reason
			cases = append(cases, denialAuditCase{
				name: "範圍拒絕/" + l.label + "/" + string(reason), method: "PUT", path: l.path, body: `{"name":"x"}`, uid: 7,
				mount: denialHandler(l.path, func(c *gin.Context) bool {
					res := authz.ScopeResult{Outcome: authz.ScopeDenyScope, Reason: reason}
					return middleware.RespondAuthzDecision(c, res, authz.NewErrScopeDenied(l.kind, l.layer, reason), middleware.CapabilityDenial{})
				}),
				wantCode: http.StatusNotFound, wantStatus: model.StatusDenied, wantNew: scopeDetails(string(reason), ""),
			})
		}
	}
	return append(cases,
		denialAuditCase{
			name: "範圍拒絕/服務回傳拒絕值", method: "DELETE", path: "/api/v1/assets/31", uid: 7,
			mount: denialHandler("/api/v1/assets/31", func(c *gin.Context) bool {
				middleware.RespondScopeDenied(c, authz.NewErrScopeDenied(authz.ScopeTargetAsset, authz.ScopeLayerAsset, authz.ScopeReasonOutOfScope))
				return true
			}),
			wantCode: http.StatusNotFound, wantStatus: model.StatusDenied, wantNew: scopeDetails(string(authz.ScopeReasonOutOfScope), ""),
		},
		denialAuditCase{
			name: "批次出口", method: "POST", path: "/api/v1/denial-audit/batch", body: `{"ids":[31,32,999903]}`, uid: 7,
			mount:    denialHandler("/api/v1/denial-audit/batch", func(c *gin.Context) bool { middleware.RespondBatchUnavailable(c, 2); return true }),
			wantCode: http.StatusNotFound, wantStatus: model.StatusDenied, wantNew: scopeDetails(middleware.ScopeReasonBatchItemsUnavailable, "2"),
		},
		denialAuditCase{
			name: "未登記種類/範圍出口", method: "PUT", path: "/api/v1/denial-audit/node", uid: 7,
			mount: denialHandler("/api/v1/denial-audit/node", func(c *gin.Context) bool {
				middleware.RespondScopeDenied(c, authz.NewErrScopeDenied(authz.ScopeTargetNode, authz.ScopeLayerAsset, authz.ScopeReasonOutOfScope))
				return true
			}),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: scopeDetails(middleware.ScopeReasonKindUnmapped, ""),
		},
		denialAuditCase{
			name: "未登記種類/真不存在分支", method: "PUT", path: "/api/v1/denial-audit/node", uid: 7,
			mount: denialHandler("/api/v1/denial-audit/node", func(c *gin.Context) bool {
				middleware.RespondTargetNotFound(c, authz.ScopeTargetNode, authz.ScopeLayerAsset)
				return true
			}),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: scopeDetails(middleware.ScopeReasonKindUnmapped, ""),
		},
		denialAuditCase{
			name: "真不存在分支：已登記種類為 failure 且無 denial 鍵", method: "PUT", path: "/api/v1/assets/31", uid: 7,
			mount: denialHandler("/api/v1/assets/31", func(c *gin.Context) bool {
				middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
				return true
			}),
			wantCode: http.StatusNotFound, wantStatus: model.StatusFailure,
		},
		denialAuditCase{
			name: "共用出口：能力拒絕", method: "PUT", path: "/api/v1/assets/31", uid: 7,
			mount: denialHandler("/api/v1/assets/31", func(c *gin.Context) bool {
				res := authz.ScopeResult{Outcome: authz.ScopeDenyCapability, Reason: authz.ScopeReasonNoEffectiveBinding}
				return middleware.RespondAuthzDecision(c, res, nil, middleware.AllOfCapabilityDenial(authz.PermAssetUpdate))
			}),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialAllOf, string(authz.PermAssetUpdate)),
		},
		denialAuditCase{
			name: "既有 deny_reason 與拒絕細節並存", method: "POST", path: "/api/v1/denial-audit/preset", uid: 7,
			preset: map[string]string{"deny_reason": "preset_reason", "query": "preset-query"},
			mount: denialHandler("/api/v1/denial-audit/preset", func(c *gin.Context) bool {
				middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermRoleAssign))
				return true
			}),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialAllOf, string(authz.PermRoleAssign)),
			wantExisting: map[string]string{"deny_reason": "preset_reason", "query": "preset-query"},
		},
		denialAuditCase{
			name: "同名鍵已存在時保留既有值", method: "POST", path: "/api/v1/denial-audit/collide", uid: 7,
			preset: map[string]string{"denial": "preset-denial", "basis": "preset-basis", "deny_reason": "preset_reason"},
			mount: denialHandler("/api/v1/denial-audit/collide", func(c *gin.Context) bool {
				middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermRoleAssign))
				return true
			}),
			collision: true,
			wantCode:  http.StatusForbidden, wantStatus: model.StatusDenied,
			wantNew:      map[string]string{"denial": "preset-denial", "basis": "preset-basis", "required": string(authz.PermRoleAssign)},
			wantExisting: map[string]string{"deny_reason": "preset_reason"},
		},
		denialAuditCase{
			name: "同名鍵已存在時保留既有值（範圍拒絕）", method: "POST", path: "/api/v1/denial-audit/collide", uid: 7,
			preset:    map[string]string{"count": "preset-count"},
			mount:     denialHandler("/api/v1/denial-audit/collide", func(c *gin.Context) bool { middleware.RespondBatchUnavailable(c, 3); return true }),
			collision: true,
			wantCode:  http.StatusNotFound, wantStatus: model.StatusDenied,
			wantNew: map[string]string{"denial": "scope", "scope_reason": middleware.ScopeReasonBatchItemsUnavailable, "count": "preset-count"},
		},
	)
}

// denialGateCases 登錄閘（all_of、any_of、unregistered）、超管保留守衛、指派關卡、
// 與能力拒絕同碼的規則拒絕、審計列表的缺能力 GET（查詢摘要原樣保留）。
func denialGateCases() []denialAuditCase {
	plain := principalOf(model.BuiltinUser, "")
	auditor := principalOf(model.BuiltinAuditor, "")
	userManager := customPrincipal(authz.PermUserManage)
	gate := func(method, path string) func(r gin.IRoutes) {
		return func(r gin.IRoutes) { r.Handle(method, path, middleware.EnforceRegistry(), denialAuditReached) }
	}
	userRoutes := func(err error) func(r gin.IRoutes) {
		h := api.NewUserHandler(addRoleStub{err: err})
		return func(r gin.IRoutes) { r.POST("/api/v1/users/:id/roles/:role", middleware.EnforceRegistry(), h.AddRole) }
	}
	acceptRoute := func(r gin.IRoutes) {
		h := api.NewAuditFailureHandler(nil)
		r.POST("/api/v1/audit-failures/permission-state/accept", middleware.EnforceRegistry(), api.RequirePermissionAcceptSuperAdmin, h.AcceptPermissionState)
	}
	anyOf := []string{string(authz.PermCredentialManage), string(authz.PermCredentialCreate), string(authz.PermCredentialUpdate),
		string(authz.PermCredentialSetSecret), string(authz.PermCredentialRotate), string(authz.PermCredentialConvertScope),
		string(authz.PermCredentialDetach), string(authz.PermCredentialDelete), string(authz.PermCredentialBind)}
	const fixtureUser, fixtureQ = "4242", "alpha-host"
	auditQuery := url.Values{"user_id": {fixtureUser}, "q": {fixtureQ}, "token": {"tok-secret-1"}}.Encode()
	assignDenied := &identity.AssignmentDenial{Reason: identity.DenyReasonCapabilityMissing, Err: identity.ErrRoleAssignmentForbidden}
	agentRole := &identity.AssignmentDenial{Reason: identity.DenyReasonAgentRole, Err: identity.ErrAgentRoleForbidden}
	return []denialAuditCase{
		{name: "登錄閘：all_of", method: "POST", path: "/api/v1/assets", body: `{"name":"x"}`, uid: 7, who: plain, mount: gate("POST", "/api/v1/assets"),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialAllOf, string(authz.PermAssetCreate))},
		{name: "登錄閘：any_of 列出全部進入鍵", method: "PUT", path: "/api/v1/credentials/31", body: `{"name":"x"}`, uid: 7, who: plain,
			mount:    gate("PUT", "/api/v1/credentials/:id"),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialAnyOf, anyOf...)},
		{name: "登錄閘：未登錄路由", method: "POST", path: "/api/v1/denial-audit/unregistered", uid: 7, who: plain,
			mount:    gate("POST", "/api/v1/denial-audit/unregistered"),
			wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialUnregistered)},
		{name: "超管保留守衛：稽核員", method: "POST", path: "/api/v1/audit-failures/permission-state/accept", body: `{"reason":"r"}`, uid: 7, who: auditor,
			mount: acceptRoute, wantCode: http.StatusForbidden, wantStatus: model.StatusDenied, wantNew: capDetails(authz.DenialReserved, authz.ReservedSuperAdmin)},
		{name: "指派關卡：缺指派能力（deny_reason 並存）", method: "POST", path: "/api/v1/users/9/roles/auditor", uid: 7, who: userManager,
			mount: userRoutes(assignDenied), wantCode: http.StatusForbidden, wantStatus: model.StatusDenied,
			wantNew:      capDetails(authz.DenialAllOf, string(authz.PermRoleAssign)),
			wantExisting: map[string]string{"deny_reason": identity.DenyReasonCapabilityMissing}},
		{name: "規則拒絕：agent 不得持有的角色", method: "POST", path: "/api/v1/users/9/roles/auditor", uid: 7, who: userManager,
			mount: userRoutes(agentRole), wantCode: http.StatusForbidden, wantStatus: model.StatusDenied,
			wantExisting: map[string]string{"deny_reason": identity.DenyReasonAgentRole}},
		{name: "規則拒絕：限人類帳號的操作", method: "POST", path: "/api/v1/users/9/roles/auditor", uid: 7, who: userManager,
			mount: userRoutes(identity.ErrAgentHumanOnly), wantCode: http.StatusForbidden, wantStatus: model.StatusDenied},
		{name: "審計列表：缺能力 GET 的查詢摘要原樣保留", method: "GET", path: "/api/v1/audit-logs?" + auditQuery, uid: 7, who: plain,
			mount: gate("GET", "/api/v1/audit-logs"), wantCode: http.StatusForbidden, wantStatus: model.StatusDenied,
			wantNew:      capDetails(authz.DenialAllOf, string(authz.PermAuditView)),
			wantExisting: map[string]string{"query": middleware.MaskCredentialQuery(auditQuery)},
			wantQuery:    []string{"user_id=" + fixtureUser, "q=" + fixtureQ},
			fixtures:     []string{fixtureUser, fixtureQ}},
	}
}
