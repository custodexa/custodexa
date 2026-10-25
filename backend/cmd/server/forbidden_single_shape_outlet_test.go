package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/sshproxy"
)

// 服務層能力拒絕的後半寫出點：審核與撤銷資格守衛、監看票簽發、指派關卡的指派能力拒絕、
// 角色指派預覽。由 TestForbiddenSingleShape 呼叫，與登錄閘拒絕的本文逐位元比對。

// shapeAsserter TestForbiddenSingleShape 的單一形狀斷言。
type shapeAsserter = func(t *testing.T, who string, e authz.RouteEntry, pr shapeProbe, wantBasis authz.DenialBasis)

// outletProbe 以指定使用者編號與主體跑一條守衛鏈，回收回應、能力拒絕依據與審計 details。
func outletProbe(uid uint, p *authz.Principal, method, path, body string, mount func(r gin.IRoutes)) (shapeProbe, map[string]string) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var out shapeProbe
	var details map[string]string
	r.Use(func(c *gin.Context) {
		c.Set("userID", uid)
		c.Set("username", "shape-outlet")
		middleware.SetPrincipal(c, p)
		c.Next()
		out.denial, out.hasDeny = middleware.CapabilityDenialFrom(c)
		if v, ok := c.Get("audit_details"); ok {
			details, _ = v.(map[string]string)
		}
	})
	mount(r)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	out.code = w.Code
	out.raw = w.Body.String()
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out, details
}

// addRoleStub 只覆寫 AddRole 的使用者服務替身：回傳指定的指派關卡錯誤。
type addRoleStub struct {
	api.UserServiceInterface
	err error
}

func (s addRoleStub) AddRole(uint, string) error { return s.err }

func outletSubcases(t *testing.T, sample string, assertShape shapeAsserter) {
	require.NotEmpty(t, sample)
	plain := principalOf(model.BuiltinUser, "")

	// 審核與撤銷資格、監看票的職能現查都讀 DB（users 1–5，無審核方群組、無稽核職能）。
	env := newOwnerTransferEnv(t)
	require.NoError(t, env.db.Model(&model.User{}).Where("id = ?", otUserV).Update("active", false).Error)
	auth := identity.NewAuthService("shape-outlet-only", time.Hour)
	ssh := sshproxy.NewHandler(nil, auth, nil, session.NewSessionService(nil), nil, "", nil)
	marker := func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"reached": true}) }
	accessRoutes := func(r gin.IRoutes) {
		r.POST("/api/v1/access-requests/:id/approve", middleware.EnforceRegistry(), middleware.RequireApproverRole(env.db), marker)
		r.GET("/api/v1/access-requests/pending", middleware.EnforceRegistry(), middleware.RequireApproverRole(env.db), marker)
		r.POST("/api/v1/access-requests/:id/revoke", middleware.EnforceRegistry(), middleware.RequireRevokeEligibility(env.db), marker)
		r.POST("/api/v1/sessions/:id/monitor-token", middleware.EnforceRegistry(), ssh.HandleCreateMonitorTicket)
	}

	userRoutes := func(err error) func(r gin.IRoutes) {
		h := api.NewUserHandler(addRoleStub{err: err})
		return func(r gin.IRoutes) {
			r.POST("/api/v1/users/:id/roles/:role", middleware.EnforceRegistry(), h.AddRole)
		}
	}
	previewRoutes := func(r gin.IRoutes) {
		h := api.NewRoleAssignmentPreviewHandler(nil)
		r.POST("/api/v1/role-assignment-previews", middleware.EnforceRegistry(), h.Preview)
	}
	assignOnly := customPrincipal(authz.PermRoleAssign)
	userManager := customPrincipal(authz.PermUserManage)
	assignDenied := func(reason string) error {
		return &identity.AssignmentDenial{Reason: reason, Err: identity.ErrRoleAssignmentForbidden}
	}

	reservedSet := map[string]bool{
		authz.ReservedSuperAdmin: true, authz.ReservedSuperAdminOrAuditor: true,
		authz.ReservedApproverEligibility: true, authz.ReservedRevokeEligibility: true,
	}
	roleAssign := string(authz.PermRoleAssign)
	cases := []struct {
		name, method, path, body string
		uid                      uint
		who                      *authz.Principal
		mount                    func(r gin.IRoutes)
		basis                    authz.DenialBasis
		required                 []string
		denyReason               string
	}{
		{"審核：非有效審核者", "POST", "/api/v1/access-requests/1/approve", `{}`, otUserU, plain, accessRoutes, authz.DenialReserved, []string{authz.ReservedApproverEligibility}, ""},
		{"審核待辦列表：非有效審核者", "GET", "/api/v1/access-requests/pending", "", otUserU, plain, accessRoutes, authz.DenialReserved, []string{authz.ReservedApproverEligibility}, ""},
		{"撤銷：非超管且非有效審核者", "POST", "/api/v1/access-requests/1/revoke", `{}`, otUserU, plain, accessRoutes, authz.DenialReserved, []string{authz.ReservedRevokeEligibility}, ""},
		{"監看票：現查無監看職能", "POST", "/api/v1/sessions/1/monitor-token", "", otUserU, plain, accessRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdminOrAuditor}, ""},
		{"指派關卡：缺指派能力", "POST", "/api/v1/users/9/roles/auditor", "", 7, userManager, userRoutes(assignDenied(identity.DenyReasonCapabilityMissing)), authz.DenialAllOf, []string{roleAssign}, identity.DenyReasonCapabilityMissing},
		{"指派關卡：無操作者主體", "POST", "/api/v1/users/9/roles/auditor", "", 7, userManager, userRoutes(assignDenied(identity.DenyReasonOperatorMissing)), authz.DenialAllOf, []string{roleAssign}, identity.DenyReasonOperatorMissing},
		{"角色預覽：直接角色缺使用者管理能力", "POST", "/api/v1/role-assignment-previews", `{"kind":"direct_roles","user_id":9}`, 7, assignOnly, previewRoutes, authz.DenialAllOf, []string{string(authz.PermUserManage)}, ""},
		{"角色預覽：群組角色缺群組管理能力", "POST", "/api/v1/role-assignment-previews", `{"kind":"group_roles","group_id":9}`, 7, assignOnly, previewRoutes, authz.DenialAllOf, []string{string(authz.PermUserGroupManage)}, ""},
		{"角色預覽：群組成員缺群組管理能力", "POST", "/api/v1/role-assignment-previews", `{"kind":"group_members","group_id":9}`, 7, assignOnly, previewRoutes, authz.DenialAllOf, []string{string(authz.PermUserGroupManage)}, ""},
		{"角色預覽：映射規則缺身分來源管理能力", "POST", "/api/v1/role-assignment-previews", `{"kind":"mapping_rule_change"}`, 7, assignOnly, previewRoutes, authz.DenialAllOf, []string{string(authz.PermIdentitySourceManage)}, ""},
		{"角色預覽：角色定義的非超管", "POST", "/api/v1/role-assignment-previews", `{"kind":"role_definition","role_id":9}`, 7, customPrincipal(authz.PermRoleAssign, authz.PermUserManage, authz.PermUserGroupManage), previewRoutes, authz.DenialReserved, []string{authz.ReservedSuperAdmin}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pr, details := outletProbe(c.uid, c.who, c.method, c.path, c.body, c.mount)
			assertShape(t, c.name, authz.RouteEntry{Method: c.method, Path: c.path}, pr, c.basis)
			assert.Equal(t, sample, pr.raw, "%s：須與登錄閘的能力拒絕逐位元相同", c.name)
			assert.Equal(t, c.required, pr.denial.Required, "%s：拒絕依據所列鍵", c.name)
			if c.basis == authz.DenialReserved {
				for _, v := range pr.denial.Required {
					assert.True(t, reservedSet[v], "%s：保留條件值 %q 不在受控清單", c.name, v)
				}
			}
			if c.denyReason != "" {
				assert.Equal(t, c.denyReason, details["deny_reason"], "%s：審計 deny_reason 須保留", c.name)
			}
		})
	}

	// 與能力拒絕同碼的規則拒絕、G-M1 的連線認證分支：回應照原樣，不留能力拒絕依據。
	agentRole := &identity.AssignmentDenial{Reason: identity.DenyReasonAgentRole, Err: identity.ErrAgentRoleForbidden}
	rules := []struct {
		name, method, path string
		uid                uint
		who                *authz.Principal
		mount              func(r gin.IRoutes)
		code, denyReason   string
	}{
		{"規則拒絕：agent 不得持有的角色", "POST", "/api/v1/users/9/roles/auditor", 7, userManager, userRoutes(agentRole), "AUTH_PERMISSION_DENIED", identity.DenyReasonAgentRole},
		{"規則拒絕：限人類帳號的操作", "POST", "/api/v1/users/9/roles/auditor", 7, userManager, userRoutes(identity.ErrAgentHumanOnly), "AUTH_PERMISSION_DENIED", ""},
		{"監看票：帳號停用屬連線認證錯誤", "POST", "/api/v1/sessions/1/monitor-token", otUserV, plain, accessRoutes, "AUTH_USER_INACTIVE", ""},
	}
	for _, c := range rules {
		t.Run(c.name, func(t *testing.T) {
			pr, details := outletProbe(c.uid, c.who, c.method, c.path, "", c.mount)
			assert.Equal(t, http.StatusForbidden, pr.code, pr.raw)
			assert.Equal(t, c.code, pr.body["code"], pr.raw)
			assert.False(t, pr.hasDeny, "%s：規則拒絕不得留能力拒絕依據", c.name)
			if c.denyReason != "" {
				assert.Equal(t, c.denyReason, details["deny_reason"], c.name)
			}
		})
	}
	require.False(t, errors.Is(agentRole, identity.ErrRoleAssignmentForbidden), "規則拒絕的哨兵不得與指派能力拒絕相同")
}
