package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 掛載來源檢查接上建帳號、單台脫離與專用轉共用：能力由入口傳入，不被追加 bind；
// 範圍化主體的範圍外來源與不存在同形。

// scAccountRouter 帳號建立路由：服務層關卡為正式的管理授權轉接頭，帳號寫入範圍判定為正式實作。
func (e *scEnv) scAccountRouter(uid uint) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	svc := asset.NewAssetAccountService(e.assets, e.codec, audit.NewTxSink()).
		WithManagementAuthorizer(e.adapter).WithSystemAlertSink(noopAlertSink{}).
		WithAccountWriteScope(authz.NewAssetWriteScope(e.eval))
	h := api.NewAssetAccountHandler(svc, e.authzSvc)
	r.POST("/api/v1/assets/:id/accounts", middleware.EnforceRegistry(), h.Create)
	return r
}

// scDetachRouter 單台脫離路由：輪替引擎為真實作（遠端依賴不注入：被拒的請求不得走到遠端）。
func (e *scEnv) scDetachRouter(uid uint, rot *asset.CredentialRotationService) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(e.scPrincipal(uid))
	h := api.NewCredentialHandler(e.creds, rot, scStatus{})
	r.POST("/api/v1/credentials/:id/bindings/:accountId/detach", middleware.EnforceRegistry(), h.Detach)
	return r
}

func (e *scEnv) scPrincipal(uid uint) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	}
}

func scServe(r *gin.Engine, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (m *scMount) rotationCount() int64 {
	m.t.Helper()
	var n int64
	require.NoError(m.t, m.db.Model(&model.CredentialRotation{}).Count(&n).Error)
	return n
}

func runMountEntryCases(t *testing.T) {
	t.Run("建帳號帶 credential_id 的三種不可用來源同形且帳號表筆數不變", func(t *testing.T) {
		m := newSCMount(t)
		creator := m.user("zz-sc-account-creator")
		m.grant(creator, []string{"zz-sc-in"}, authz.PermAssetView, authz.PermAssetUpdate,
			authz.PermCredentialView, authz.PermCredentialBind)
		r := m.scAccountRouter(creator)
		create := func(credID uint) (int, string) {
			return scServe(r, "POST", fmt.Sprintf("/api/v1/assets/%d/accounts", m.aIn), fmt.Sprintf(`{"credential_id":%d}`, credID))
		}
		before := m.accountCount()
		wantCode, wantBody := create(m.ghost)
		require.GreaterOrEqual(t, wantCode, 400, wantBody)
		for _, src := range []uint{m.outCred, m.globalCred} {
			code, body := create(src)
			require.Equal(t, wantCode, code)
			require.Equal(t, wantBody, body)
			require.Zero(t, m.mountCount(src))
		}
		require.Equal(t, before, m.accountCount(), "帳號表筆數不變")

		code, body := create(m.inCred)
		require.Less(t, code, 300, body)
		require.EqualValues(t, 1, m.mountCount(m.inCred), "範圍內來源成功")
	})

	t.Run("脫離歸屬範圍外的共用憑證與不存在憑證同形且零遠端", func(t *testing.T) {
		m := newSCMount(t)
		detacher := m.user("zz-sc-detacher")
		m.grant(detacher, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialDetach)
		acc := m.mount(m.outCred, m.aIn)
		rot := asset.NewCredentialRotationService(m.db, m.assets, nil, nil, m.codec, audit.NewTxSink(), m.adapter)
		r := m.scDetachRouter(detacher, rot)
		body := `{"source":"random"}`
		wantCode, wantBody := scServe(r, "POST", fmt.Sprintf("%s/bindings/%d/detach", credPath(m.ghost), acc), body)
		require.GreaterOrEqual(t, wantCode, 400, wantBody)
		code, got := scServe(r, "POST", fmt.Sprintf("%s/bindings/%d/detach", credPath(m.outCred), acc), body)
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, got)
		require.Zero(t, m.rotationCount(), "未建立輪替：遠端零呼叫")
		var a model.AssetAccount
		require.NoError(t, m.db.First(&a, acc).Error)
		require.Equal(t, m.outCred, a.CredentialID, "掛載不動")
	})

	t.Run("只持脫離或轉換範圍的範圍化主體：來源歸屬範圍外與不存在同形", func(t *testing.T) {
		m := newSCMount(t)
		detacher := m.user("zz-sc-only-detach")
		m.grant(detacher, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialDetach)
		converter := m.user("zz-sc-only-convert")
		m.grant(converter, []string{"zz-sc-in"}, authz.PermCredentialView, authz.PermCredentialConvertScope)

		// 脫離：只持 detach，不因缺 bind 被拒，而是以來源歸屬判定
		acc := m.mount(m.outCred, m.aIn)
		rot := asset.NewCredentialRotationService(m.db, m.assets, nil, nil, m.codec, audit.NewTxSink(), m.adapter)
		r := m.scDetachRouter(detacher, rot)
		wantCode, wantBody := scServe(r, "POST", fmt.Sprintf("%s/bindings/%d/detach", credPath(m.ghost), acc), `{"source":"random"}`)
		code, body := scServe(r, "POST", fmt.Sprintf("%s/bindings/%d/detach", credPath(m.outCred), acc), `{"source":"random"}`)
		require.NotEqual(t, http.StatusForbidden, wantCode, "能力不被追加 bind：不是能力拒絕")
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, body)

		// 轉共用：只持 convert-scope；專用憑證隨資產，資產在範圍外即與不存在同形
		dedOut := m.dedicated(m.aOut)
		wantCode, wantBody = m.call(converter, "POST", credPath(m.ghost)+"/scope", `{"scope":"shared","name":"zz-sc-conv-ghost"}`)
		code, body = m.call(converter, "POST", credPath(dedOut)+"/scope", `{"scope":"shared","name":"zz-sc-conv-out"}`)
		require.NotEqual(t, http.StatusForbidden, wantCode, "能力不被追加 bind：不是能力拒絕")
		require.Equal(t, wantCode, code)
		require.Equal(t, wantBody, body)
		var c model.Credential
		require.NoError(t, m.db.First(&c, dedOut).Error)
		require.Equal(t, model.CredentialScopeDedicated, c.Scope, "範圍不變")
	})

	t.Run("全域主體只持轉換範圍（無 bind）轉共用成功", func(t *testing.T) {
		m := newSCMount(t)
		conv := m.user("zz-sc-global-convert")
		m.grantGlobal(conv, m.role(authz.PermCredentialView, authz.PermCredentialConvertScope))
		ded := m.dedicated(m.aIn)
		code, body := m.call(conv, "POST", credPath(ded)+"/scope", `{"scope":"shared","name":"zz-sc-conv-global"}`)
		require.Equal(t, http.StatusOK, code, body)
		var c model.Credential
		require.NoError(t, m.db.First(&c, ded).Error)
		require.Equal(t, model.CredentialScopeShared, c.Scope)
	})
}
