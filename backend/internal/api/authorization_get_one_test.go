package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 授權規則單筆讀取：同一個請求主體，單筆回應等於它在授權列表中看到的那一列（含範圍投影下的列級旗標）；
// 客體在其管理範圍外的規則，單筆回應與不存在的規則逐位元組相同。

const authorizationGetOneMissingID = 999999

type authzGetOneEnv struct {
	*nodeScopeEnv
	h *AuthorizationHandler
}

func newAuthzGetOneEnv(t *testing.T) *authzGetOneEnv {
	t.Helper()
	e := newNodeScopeEnv(t, authz.PermAuthorizationManage)
	require.NoError(t, e.db.AutoMigrate(&model.AccessRequest{}, &model.AccessRequestItem{},
		&model.AccessRequestApproval{}, &model.SecurityPolicy{}))
	aeval := authz.NewAuthorizationScopeEvaluator(e.cat, asset.NewScopeTopologyReader())
	svc := authz.NewAssetAuthorizationService(e.db)
	svc.SetWriteScope(authz.NewAuthorizationWriteScope(aeval))
	requests := authz.NewAccessRequestService(e.db, policy.NewSecurityPolicyService(e.db), nil, nil, nil)
	requests.SetRevokeScope(authz.NewAuthorizationWriteScope(aeval))
	h := NewAuthorizationHandler(svc, authz.NewEffectiveAccessResolver(e.db).WithScope(aeval))
	h.EnableScopedWrites(authz.NewAuthorizationRowActions(e.db, requests), nil)
	return &authzGetOneEnv{nodeScopeEnv: e, h: h}
}

func (e *authzGetOneEnv) get(uid uint, path string) (int, []byte) {
	e.t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	r.GET("/api/v1/authorizations", e.h.List)
	r.GET("/api/v1/authorizations/:id", e.h.Get)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code, w.Body.Bytes()
}

func (e *authzGetOneEnv) ruleOnAsset(subject, assetID uint) uint {
	e.t.Helper()
	a := model.AssetAuthorization{UserID: &subject, AssetID: &assetID, Permission: model.PermissionConnect,
		Source: model.AuthorizationSourceManual, GrantedBy: 1, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(e.t, e.db.Create(&a).Error)
	return a.ID
}

func (e *authzGetOneEnv) ruleOnNode(subject uint, path string) uint {
	e.t.Helper()
	node := e.id(path)
	a := model.AssetAuthorization{UserID: &subject, AssetGroupID: &node, Permission: model.PermissionConnect,
		Source: model.AuthorizationSourceManual, GrantedBy: 1, Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(e.t, e.db.Create(&a).Error)
	return a.ID
}

// temporaryRule 已核准申請單產生的臨時授權列（有效期內），申請單與項目接回授權。
func (e *authzGetOneEnv) temporaryRule(requester, assetID uint) uint {
	e.t.Helper()
	now := time.Now()
	dur := 60
	start, expire := now.Add(-time.Minute), now.Add(time.Hour)
	req := model.AccessRequest{RequesterID: requester, AssetID: assetID, Reason: "single read", Kind: "normal",
		RequestedDurationMinutes: dur, Status: model.AccessRequestPending, PendingExpiresAt: now.Add(time.Hour)}
	require.NoError(e.t, e.db.Create(&req).Error)
	require.NoError(e.t, e.db.Model(&req).Update("status", model.AccessRequestApproved).Error)
	a := model.AssetAuthorization{UserID: &requester, AssetID: &assetID, Permission: model.PermissionConnect,
		GrantedBy: 1, Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &expire,
		Accounts: model.AccountScope{model.AccountScopeAll}}
	require.NoError(e.t, e.db.Create(&a).Error)
	item := model.AccessRequestItem{RequestID: req.ID, RequesterID: requester, AssetID: assetID,
		Accounts: model.AccountScope{model.AccountScopeAll}, Status: model.AccessRequestPending, PolicySnapshot: "{}",
		AuthorizationID: &a.ID, ApprovedDurationMinutes: &dur, ApprovedDateStart: &start}
	require.NoError(e.t, e.db.Create(&item).Error)
	require.NoError(e.t, e.db.Model(&item).Update("status", model.AccessRequestApproved).Error)
	require.NoError(e.t, e.db.Model(&req).Update("authorization_id", a.ID).Error)
	return a.ID
}

// assertRuleSingleMatchesList 每一條規則：列表有者單筆逐欄相同，列表沒有者與不存在的規則同一回應。
// 回列表中的規則識別。
func (e *authzGetOneEnv) assertRuleSingleMatchesList(t *testing.T, uid uint, ruleIDs []uint) map[uint]map[string]any {
	t.Helper()
	code, body := e.get(uid, "/api/v1/authorizations?page_size=100")
	require.Equal(t, http.StatusOK, code, string(body))
	var list struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	rows := map[uint]map[string]any{}
	for _, r := range list.Data {
		rows[uint(r["id"].(float64))] = r
	}
	missCode, missBody := e.get(uid, fmt.Sprintf("/api/v1/authorizations/%d", authorizationGetOneMissingID))
	require.Equal(t, http.StatusNotFound, missCode, string(missBody))
	for _, id := range ruleIDs {
		code, raw := e.get(uid, fmt.Sprintf("/api/v1/authorizations/%d", id))
		if row, ok := rows[id]; ok {
			require.Equal(t, http.StatusOK, code, "規則 %d：%s", id, raw)
			var got map[string]any
			require.NoError(t, json.Unmarshal(raw, &got))
			assert.Equal(t, row, got, "規則 %d：單筆與列表中那一列逐欄相同", id)
			continue
		}
		assert.Equal(t, missCode, code, "規則 %d：列表看不到時與不存在同狀態碼", id)
		assert.Equal(t, string(missBody), string(raw), "規則 %d：列表看不到時與不存在同本文", id)
	}
	return rows
}

func TestAuthorizationHandler_GetOne(t *testing.T) {
	e := newAuthzGetOneEnv(t)
	subject := e.user("subject")
	inScopeAsset := e.asset("in-scope", "prod/db/a")
	outScopeAsset := e.asset("out-of-scope", "sit/web")

	onInAsset := e.ruleOnAsset(subject, inScopeAsset)
	onOutAsset := e.ruleOnAsset(subject, outScopeAsset)
	onScopeRoot := e.ruleOnNode(subject, "prod/db")
	onAncestor := e.ruleOnNode(subject, "prod") // 規則掛在範圍根的祖先上：客體不在範圍內
	onSibling := e.ruleOnNode(subject, "prod/web")
	temporary := e.temporaryRule(subject, inScopeAsset)
	all := []uint{onInAsset, onOutAsset, onScopeRoot, onAncestor, onSibling, temporary}

	manage := e.role(authz.PermAuthorizationManage)
	admin := e.superAdmin()

	t.Run("super_admin_reads_every_rule_as_listed", func(t *testing.T) {
		rows := e.assertRuleSingleMatchesList(t, admin, all)
		assert.Len(t, rows, len(all))
	})

	t.Run("global_holder_reads_every_rule_with_actions", func(t *testing.T) {
		g := e.user("global-holder")
		e.grantGlobal(g, manage)
		rows := e.assertRuleSingleMatchesList(t, g, all)
		assert.Len(t, rows, len(all))
		_, hasActions := rows[onInAsset]["actions"]
		assert.True(t, hasActions, "非超級管理者的列帶列級旗標（前提）")
	})

	t.Run("node_scope_holder_reads_only_rules_whose_object_is_in_scope", func(t *testing.T) {
		n := e.user("node-holder")
		e.grantNodes(n, manage, "prod/db")
		rows := e.assertRuleSingleMatchesList(t, n, all)
		got := map[uint]bool{}
		for id := range rows {
			got[id] = true
		}
		assert.Equal(t, map[uint]bool{onInAsset: true, onScopeRoot: true, temporary: true}, got,
			"範圍內資產、範圍根與範圍內的臨時授權可讀；範圍外資產、範圍根的祖先、兄弟節點不可讀")
		tmp := rows[temporary]
		require.NotNil(t, tmp)
		assert.Equal(t, model.AuthorizationSourceTicket, tmp["source"])
		actions, _ := tmp["actions"].(map[string]any)
		_, hasRevoke := actions["revoke"]
		assert.True(t, hasRevoke, "臨時授權列的列級旗標含撤銷（與列表同）")
	})

	t.Run("global_and_node_assignments_together_read_everything", func(t *testing.T) {
		m := e.user("mixed-holder")
		e.grantNodes(m, manage, "prod/db")
		e.grantGlobal(m, e.role(authz.PermAuthorizationManage))
		rows := e.assertRuleSingleMatchesList(t, m, all)
		assert.Len(t, rows, len(all), "全域指派使範圍為不限")
	})

	t.Run("deleted_rule_answers_like_missing", func(t *testing.T) {
		gone := e.ruleOnAsset(e.user("subject-2"), inScopeAsset)
		require.NoError(t, e.db.Delete(&model.AssetAuthorization{}, gone).Error)
		code, raw := e.get(admin, fmt.Sprintf("/api/v1/authorizations/%d", gone))
		_, missRaw := e.get(admin, fmt.Sprintf("/api/v1/authorizations/%d", authorizationGetOneMissingID))
		assert.Equal(t, http.StatusNotFound, code)
		assert.Equal(t, string(missRaw), string(raw))
	})

	t.Run("invalid_id_is_bad_request", func(t *testing.T) {
		code, body := e.get(admin, "/api/v1/authorizations/abc")
		assert.Equal(t, http.StatusBadRequest, code, string(body))
	})

	t.Run("id_boundaries_depend_only_on_input", func(t *testing.T) {
		n := e.user("boundary-node-holder")
		e.grantNodes(n, manage, "prod/db")
		get := func(uid uint) func(string) (int, []byte) {
			return func(raw string) (int, []byte) { return e.get(uid, "/api/v1/authorizations/"+raw) }
		}
		gone := e.ruleOnAsset(e.user("boundary-subject"), inScopeAsset)
		require.NoError(t, e.db.Delete(&model.AssetAuthorization{}, gone).Error)
		assertIDBoundaries(t, get(admin), onInAsset, gone, false)
		// 節點範圍持有者：範圍外資產上的規則看不到
		assertIDBoundaries(t, get(n), onInAsset, onOutAsset, false)
	})
}
