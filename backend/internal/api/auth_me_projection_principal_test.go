package api

import (
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProjectionPrincipalMissingOnAuthenticatedRequestDenied 目前使用者投影：認證入口已標示請求憑證種類卻缺
// 主體時回錯誤，不以帳號完整身分重解；有主體時沿用請求主體（人類工作階段與修改前相同）。
func TestProjectionPrincipalMissingOnAuthenticatedRequestDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, kind := range []model.RequestCredential{model.RequestCredentialAPIToken, model.RequestCredentialHumanSession} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/api/v1/auth/me/capabilities", nil)
		middleware.BindRequestPrincipal(c, nil, kind)
		p, err := resolveProjectionPrincipal(c, 7)
		assert.ErrorIs(t, err, errProjectionPrincipalMissing, string(kind))
		assert.Nil(t, p)
	}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/api/v1/auth/me/capabilities", nil)
	want := testSessionPrincipal(7)
	middleware.BindRequestPrincipal(c, want, model.RequestCredentialHumanSession)
	got, err := resolveProjectionPrincipal(c, 7)
	require.NoError(t, err)
	assert.Same(t, want, got)
}
