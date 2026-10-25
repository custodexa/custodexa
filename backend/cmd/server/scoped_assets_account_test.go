package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sshproxy"
)

// 資產帳號隨資產：列表依來源（管理可視回全部帳號、只連線可視維持連線帳號範圍過濾），
// 寫入在交易內隨所屬資產判定（範圍外與不存在同形）。

// saSeedAccounts 以系統呼叫者在資產上建帳號（名稱 → 帳號 ID）。
func (e *saEnv) saSeedAccounts(assetID uint, names ...string) map[string]uint {
	e.t.Helper()
	seed := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(fieldCapSeedAuthorizer{}).WithSystemAlertSink(noopAlertSink{})
	out := map[string]uint{}
	for _, n := range names {
		dto, err := seed.Create(asset.WithSystemCaller(operatorCtx()), assetID,
			&asset.CreateAssetAccountRequest{Username: n, Password: "zz-sa-secret-" + n})
		require.NoError(e.t, err)
		out[n] = dto.ID
	}
	return out
}

// accountRouter 帳號路由：scoped＝注入管理可視與帳號寫入範圍判定（正式組裝）；否則為現行列表路徑的對照。
func (e *saEnv) accountRouter(uid uint, scoped bool) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		e.current = p
		c.Next()
	})
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(fieldCapManagementAuthorizer{env: e.fieldCapEnv}).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	h := api.NewAssetAccountHandler(svc, e.authzSvc)
	var visible gin.HandlerFunc = middleware.RequireAssetVisible(e.authzSvc)
	if scoped {
		src := authz.NewAssetScopeReader(e.eval, e.db)
		h.SetAssetManagementVisibility(src)
		visible = middleware.RequireAssetVisibleOrManaged(e.authzSvc, src)
	}
	g := r.Group("/api/v1/assets/:id/accounts")
	g.GET("", middleware.EnforceRegistry(), visible, h.List)
	g.POST("", middleware.EnforceRegistry(), h.Create)
	g.PUT("/:accountId", middleware.EnforceRegistry(), h.Update)
	g.DELETE("/:accountId", middleware.EnforceRegistry(), h.Delete)
	g.POST("/:accountId/set-default", middleware.EnforceRegistry(), h.SetDefault)
	return r
}

func (e *saEnv) doAccount(uid uint, scoped bool, method, path, body string) (int, string) {
	e.t.Helper()
	defer func() { e.current = nil }()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	e.accountRouter(uid, scoped).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// issueConnectToken 以正式的連線票證簽發 handler 對資產發出簽發請求（主體每次自資料庫重解）。
// 簽發只做授權與政策判定、不撥號，不需要連線靶機。
func (e *saEnv) issueConnectToken(uid, assetID uint) (int, string) {
	e.t.Helper()
	authSvc := identity.NewAuthService("zz-sa-connect-secret", time.Hour)
	auditService := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true, AsyncAuditEnabled: false})
	ssh := sshproxy.NewHandler(e.assets, authSvc, e.authzSvc, nil, nil, e.t.TempDir(), auditService)
	policies := policy.NewSecurityPolicyService(e.db)
	ssh.AccessPolicy = policy.NewAccessPolicyService(e.db, policies, e.authzSvc)
	ssh.TransmissionConsent = policy.NewTransmissionConsentService(e.db,
		policy.NewTransmissionPolicyService(policies, func() policy.LDAPRiskResult { return policy.LDAPRiskResult{} }))
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	r.POST("/api/v1/connect-tokens", middleware.EnforceRegistry(), ssh.HandleCreateConnectToken)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/connect-tokens", strings.NewReader(fmt.Sprintf(`{"asset_id":%d}`, assetID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func accountsPath(assetID uint) string { return fmt.Sprintf("/api/v1/assets/%d/accounts", assetID) }

// saAccountRows 列表回應的列（鍵值保留）。
func saAccountRows(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var out struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	return out.Data
}

func (e *saEnv) accountSnapshot(assetID uint) []string {
	e.t.Helper()
	var rows []model.AssetAccount
	require.NoError(e.t, e.db.Unscoped().Where("asset_id = ?", assetID).Order("id").Find(&rows).Error)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%d:%s:default=%t:deleted=%t", r.ID, r.Username, r.IsDefault, r.DeletedAt.Valid))
	}
	return out
}

// accountAuditCount 資產上某種帳號操作的審計列數。
func (e *saEnv) accountAuditCount(assetID uint, op string) int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.AuditLog{}).Where("resource_id = ?", assetID).
		Where("details LIKE ?", `%"resource":"asset_account"%`).
		Where("details LIKE ?", `%"operation":"`+op+`"%`).Count(&n).Error)
	return n
}

func TestScopedAssetAccountScope(t *testing.T) {
	t.Run("list_by_source", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		mgr := e.user("zz-sa-acct-mgr")
		e.grantNodes(mgr, e.role(authz.PermAssetView, authz.PermAssetUpdate), "zz-sa-a")
		y := e.asset("zz-sa-acct-y", "zz-sa-a")
		e.saSeedAccounts(y, "zz-u1", "zz-u2", "zz-u3")
		z := e.asset("zz-sa-acct-z", "zz-sa-c")
		e.saSeedAccounts(z, "zz-u1", "zz-u2", "zz-u3")
		zid, uid := z, mgr
		require.NoError(t, e.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &zid,
			Permission: model.PermissionConnect, GrantedBy: e.super, Accounts: model.AccountScope{"zz-u2"}}).Error)
		w := e.asset("zz-sa-acct-w", "zz-sa-c")

		code, raw := e.doAccount(mgr, true, "GET", accountsPath(y), "")
		require.Equal(t, http.StatusOK, code, raw)
		rows := saAccountRows(t, raw)
		assert.Len(t, rows, 3, "管理可視且無連線授權：回全部帳號")
		for _, r := range rows {
			for _, k := range []string{"credential_id", "credential_name", "credential_scope", "shared_credential"} {
				_, ok := r[k]
				assert.False(t, ok, "不持憑證管理能力者的列不含憑證身分欄位 %s", k)
			}
		}
		assert.NotContains(t, raw, "zz-sa-secret-", "全回應不含秘密")

		code, raw = e.doAccount(mgr, true, "GET", accountsPath(z), "")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Len(t, saAccountRows(t, raw), 1, "範圍外只經連線可視：維持連線帳號範圍過濾")
		cPlain, rPlain := e.doAccount(mgr, false, "GET", accountsPath(z), "")
		assert.Equal(t, cPlain, code)
		assert.JSONEq(t, rPlain, raw, "與一般使用者既有結果相同")

		cW, rW := e.doAccount(mgr, true, "GET", accountsPath(w), "")
		cM, rM := e.doAccount(mgr, true, "GET", "/api/v1/assets/"+saMissing+"/accounts", "")
		assert.Equal(t, http.StatusNotFound, cW, rW)
		assert.Equal(t, cM, cW)
		assert.JSONEq(t, rM, rW, "範圍外無授權與不存在同形")
	})

	t.Run("writes_follow_asset", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		mgr := e.user("zz-sa-acct-mgr")
		e.grantNodes(mgr, e.role(authz.PermAssetView, authz.PermAssetUpdate), "zz-sa-a")
		cred := e.user("zz-sa-acct-cred")
		e.grantNodes(cred, e.role(authz.PermAssetView, authz.PermAssetUpdate), "zz-sa-a")
		// 帳號名稱欄位能力（credential:manage）＋內嵌秘密新建專用憑證的能力（credential:create）
		e.grantGlobal(cred, e.role(authz.PermCredentialManage, authz.PermCredentialCreate))
		in := e.asset("zz-sa-acct-in", "zz-sa-a")
		inAcc := e.saSeedAccounts(in, "zz-in-1", "zz-in-2")
		out := e.asset("zz-sa-acct-out", "zz-sa-c")
		outAcc := e.saSeedAccounts(out, "zz-out-1", "zz-out-2")

		before := e.accountSnapshot(out)
		writes := []struct{ method, suffix, body string }{
			{"POST", "", `{"auth_method":"password","password":"zz-pw"}`},
			{"PUT", "/%d", `{"note":"zz-note"}`},
			{"DELETE", "/%d", ""},
			{"POST", "/%d/set-default", ""},
		}
		for _, w := range writes {
			suffix := w.suffix
			if strings.Contains(suffix, "%d") {
				suffix = fmt.Sprintf(suffix, outAcc["zz-out-2"])
			}
			cOut, rOut := e.doAccount(mgr, true, w.method, accountsPath(out)+suffix, w.body)
			cMiss, rMiss := e.doAccount(mgr, true, w.method, "/api/v1/assets/"+saMissing+"/accounts"+suffix, w.body)
			assert.Equal(t, http.StatusNotFound, cOut, "%s %s：%s", w.method, w.suffix, rOut)
			assert.Equal(t, cMiss, cOut, "%s %s：狀態", w.method, w.suffix)
			assert.JSONEq(t, rMiss, rOut, "%s %s：本文", w.method, w.suffix)
		}
		assert.Equal(t, before, e.accountSnapshot(out), "範圍外資產的帳號不變")

		// 範圍內資產搭配其他資產的帳號
		code, raw := e.doAccount(mgr, true, "POST", fmt.Sprintf("%s/%d/set-default", accountsPath(in), outAcc["zz-out-1"]), "")
		assert.Equal(t, http.StatusNotFound, code, raw)

		// 持 username 欄位能力者：範圍內新增並設預設成功、帳號審計各一列
		creates, defaults := e.accountAuditCount(in, model.AccountOpCreate), e.accountAuditCount(in, model.AccountOpSetDefault)
		code, raw = e.doAccount(cred, true, "POST", accountsPath(in), `{"username":"zz-in-new","password":"zz-pw"}`)
		require.Equal(t, http.StatusCreated, code, raw)
		var created map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &created))
		newID := uint(created["id"].(float64))
		code, raw = e.doAccount(cred, true, "POST", fmt.Sprintf("%s/%d/set-default", accountsPath(in), newID), "")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, creates+1, e.accountAuditCount(in, model.AccountOpCreate), "新增一列帳號審計")
		assert.Equal(t, defaults+1, e.accountAuditCount(in, model.AccountOpSetDefault), "設預設一列帳號審計")

		// 不持該能力者：新增帶名稱帳號被拒、設預設成功
		code, raw = e.doAccount(mgr, true, "POST", accountsPath(in), `{"username":"zz-in-denied","password":"zz-pw"}`)
		assert.Equal(t, http.StatusForbidden, code, raw)
		code, raw = e.doAccount(mgr, true, "POST", fmt.Sprintf("%s/%d/set-default", accountsPath(in), inAcc["zz-in-2"]), "")
		require.Equal(t, http.StatusOK, code, raw)

		// 管理範圍不擴大連線：範圍內無連線授權的資產，連線判定與簽發連線都與無管理指派時相同
		conn := e.user("zz-sa-acct-conn")
		e.connGrant(conn, in)
		cOK, rOK := e.issueConnectToken(conn, in)
		require.Equal(t, http.StatusOK, cOK, "對照：有連線授權者在同一夾具簽發成功：%s", rOK)
		assert.Contains(t, rOK, "connect_token")

		ctx := authz.ContextWithPrincipal(operatorCtx(), &authz.Principal{UserID: mgr})
		withMgmt, err := e.authzSvc.CheckPermission(ctx, mgr, in, model.PermissionConnect)
		require.NoError(t, err)
		cWith, rWith := e.issueConnectToken(mgr, in)
		e.dropNodeAssignments(mgr)
		withoutMgmt, err := e.authzSvc.CheckPermission(ctx, mgr, in, model.PermissionConnect)
		require.NoError(t, err)
		cWithout, rWithout := e.issueConnectToken(mgr, in)
		assert.False(t, withMgmt, "管理指派不授予連線")
		assert.Equal(t, withoutMgmt, withMgmt)
		assert.NotEqual(t, http.StatusOK, cWith, "管理指派不使簽發連線成功：%s", rWith)
		assert.Equal(t, cWithout, cWith, "簽發連線被拒：狀態與無管理指派時相同")
		assert.JSONEq(t, rWithout, rWith, "簽發連線被拒：本文與無管理指派時相同")
	})
}
