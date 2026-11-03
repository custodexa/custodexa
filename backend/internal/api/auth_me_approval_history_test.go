package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestApprovalHistoryPointMatchesHistoryRoute 審核歷史呈現點與審核歷史端點同源：
// 對每一類主體，「目前使用者回應含 ui:approval-history 或 ui:approvals」⇔「歷史端點 200」。
// 同一個路由器同時掛目前使用者與審核歷史兩條真路由（真 AuthMiddleware、真 JWT、真守衛）。
func TestApprovalHistoryPointMatchesHistoryRoute(t *testing.T) {
	env := setupCapabilityMeEnv(t)
	reqSvc := new(MockAccessRequestService)
	reqSvc.On("ListHistory", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return([]*model.AccessRequest{}, int64(0), nil).Maybe()
	NewAccessRequestHandler(reqSvc, new(MockApproverScopeService), env.db).
		RegisterRoutes(env.r.Group("/api/v1"), env.auth)

	_, directAuditorTok := env.seedUser(t, "aud-direct", model.RoleAuditor, model.BuiltinAuditor)
	_, superTok := env.seedUser(t, "super", model.RoleAdmin, model.BuiltinSuperAdmin)
	approver, approverTok := env.seedUser(t, "appr", model.RoleApprover, model.BuiltinApprover)
	_, plainTok := env.seedUser(t, "plain", model.RoleUser, model.BuiltinUser)
	groupAuditor, groupAuditorTok := env.seedUser(t, "aud-group", "", "")

	asset := &model.Asset{Name: "srv", Protocol: model.ProtocolSSH, Host: "h", Port: 22}
	require.NoError(t, env.db.Create(asset).Error)
	require.NoError(t, env.db.Create(&model.ApproverScope{ApproverID: &approver.ID, AssetID: &asset.ID, GrantedBy: 1}).Error)

	var auditorRole model.Role
	require.NoError(t, env.db.Where("name = ?", model.RoleAuditor).First(&auditorRole).Error)
	group := &model.UserGroup{Name: "auditors"}
	require.NoError(t, env.db.Create(group).Error)
	require.NoError(t, env.db.Create(&model.UserGroupMember{UserGroupID: group.ID, UserID: groupAuditor.ID, Manual: true}).Error)
	require.NoError(t, env.db.Create(&model.UserGroupRole{UserGroupID: group.ID, RoleID: auditorRole.ID, ScopeKind: model.ScopeKindGlobal}).Error)

	history := func(tok string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/access-requests/history", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		env.r.ServeHTTP(w, req)
		return w.Code
	}

	cases := []struct {
		name        string
		tok         string
		wantHistory bool
	}{
		{"全域直接稽核員", directAuditorTok, true},
		{"經群組稽核員", groupAuditorTok, false},
		{"超級管理者", superTok, false},
		{"審核者", approverTok, false},
		{"一般使用者", plainTok, false},
	}
	for _, c := range cases {
		w := env.do(http.MethodGet, "", c.tok)
		require.Equal(t, http.StatusOK, w.Code, c.name+w.Body.String())
		perms := permissionsOf(t, w.Body.Bytes())
		hasHistory := perms[authz.UIApprovalHistory]
		require.Equal(t, c.wantHistory, hasHistory, c.name)
		visible := hasHistory || perms[authz.UIApprovals]
		code := history(c.tok)
		require.Equal(t, visible, code == http.StatusOK, "%s: 入口可見=%v 端點=%d", c.name, visible, code)
	}

	// 本文鍵集合與舊形狀相同：只多 permissions、scope_summary，不因新判定多鍵。
	w := env.do(http.MethodGet, "", directAuditorTok)
	keys := sortedKeys(decodeMap(t, w.Body.Bytes()))
	require.NotContains(t, keys, "is_history_auditor")
	for _, k := range keys {
		require.False(t, strings.Contains(strings.ToLower(k), "history"), k)
	}

	// 角色預覽不含此點（依個人資格產生）。
	require.NotContains(t, authz.PreviewRole(model.BuiltinAuditor, 0, nil).Permissions, authz.UIApprovalHistory)
}

// TestApprovalHistoryPointQueryFailure 判定查詢失敗時當否、目前使用者回應照常 200。
func TestApprovalHistoryPointQueryFailure(t *testing.T) {
	env := setupCapabilityMeEnv(t)
	_, tok := env.seedUser(t, "aud-fail", model.RoleAuditor, model.BuiltinAuditor)
	w := env.do(http.MethodGet, "", tok)
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, permissionsOf(t, w.Body.Bytes())[authz.UIApprovalHistory], "前提：未注入失敗時應含此點")

	// 只讓「審核歷史讀取資格」那一支計數查詢失敗。
	require.NoError(t, env.db.Callback().Query().After("gorm:query").Register("fail-history-auditor", func(tx *gorm.DB) {
		sql := tx.Statement.SQL.String()
		if strings.Contains(strings.ToLower(sql), "count(") && strings.Contains(sql, "user_roles.scope_kind") &&
			strings.Contains(sql, "roles.builtin_key") {
			_ = tx.AddError(errInjectedHistoryAuditor)
		}
	}))
	t.Cleanup(func() { _ = env.db.Callback().Query().Remove("fail-history-auditor") })
	_, err := authz.IsAccessRequestHistoryAuditor(env.db, 1)
	require.ErrorIs(t, err, errInjectedHistoryAuditor, "注入須命中判定查詢")

	w = env.do(http.MethodGet, "", tok)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.False(t, permissionsOf(t, w.Body.Bytes())[authz.UIApprovalHistory])
}

var errInjectedHistoryAuditor = errInjected("injected history auditor failure")

type errInjected string

func (e errInjected) Error() string { return string(e) }

func permissionsOf(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	m := decodeMap(t, body)
	raw, ok := m["permissions"].([]any)
	require.True(t, ok, string(body))
	out := map[string]bool{}
	for _, p := range raw {
		out[p.(string)] = true
	}
	return out
}
