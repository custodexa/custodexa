package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 超管保留種類的登錄項經登錄閘拒絕時：脈絡內的依據與 handler 現用的保留條件依據相同，
// 回應本文與既有能力拒絕樣本逐位元相同。
func TestEnforceRegistrySuperAdminDenialMatchesReservedSample(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const method, path = "POST", "/api/v1/role-definitions"
	e, ok := authz.LookupRoute(method, path)
	require.True(t, ok)
	require.Equal(t, authz.BaseSuperAdmin, e.Base)

	// 樣本：handler 直接以保留條件寫出的拒絕
	sample := func() string {
		r := gin.New()
		r.POST(path, func(c *gin.Context) {
			WriteCapabilityDenial(c, ReservedCapabilityDenial(authz.ReservedSuperAdmin))
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		require.Equal(t, http.StatusForbidden, w.Code)
		return w.Body.String()
	}()

	type result struct {
		code    int
		raw     string
		denial  CapabilityDenial
		hasDeny bool
		reached bool
	}
	run := func(p *authz.Principal) result {
		var out result
		r := gin.New()
		r.Use(func(c *gin.Context) {
			if p != nil {
				SetPrincipal(c, p)
			}
			c.Next()
			out.denial, out.hasDeny = CapabilityDenialFrom(c)
		})
		r.POST(path, EnforceRegistry(), func(c *gin.Context) {
			out.reached = true
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		out.code = w.Code
		out.raw = w.Body.String()
		return out
	}
	builtin := func(key string) *authz.Principal {
		return authz.NewPrincipal(1, authz.TokenFacts{}, []authz.Assignment{{RoleName: key, BuiltinKey: key, Via: authz.ViaDirect, Scope: model.ScopeKindGlobal}})
	}

	for name, p := range map[string]*authz.Principal{
		"一般使用者": builtin(model.BuiltinUser),
		"稽核員":   builtin(model.BuiltinAuditor),
	} {
		got := run(p)
		assert.False(t, got.reached, "%s：不得到達 handler", name)
		assert.Equal(t, http.StatusForbidden, got.code, name)
		require.True(t, got.hasDeny, "%s：依據須存入脈絡", name)
		assert.Equal(t, ReservedCapabilityDenial(authz.ReservedSuperAdmin), got.denial, "%s：依據須與保留條件寫法相同", name)
		assert.Equal(t, sample, got.raw, "%s：回應本文須與既有能力拒絕樣本逐位元相同", name)
	}

	super := run(builtin(model.BuiltinSuperAdmin))
	assert.True(t, super.reached, "超管放行")
	assert.False(t, super.hasDeny)

	anon := run(nil)
	assert.False(t, anon.reached)
	assert.Equal(t, http.StatusUnauthorized, anon.code, "未登入為 401")
	assert.False(t, anon.hasDeny)
}
