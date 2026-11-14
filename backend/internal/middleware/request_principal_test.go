package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestBindRequestPrincipalSetsRequestContext 認證入口把請求主體與請求憑證種類同時放進 gin 脈絡與
// c.Request 的 context，服務層取得同一個主體；未經入口的請求沒有種類（不推定為人類工作階段）。
func TestBindRequestPrincipalSetsRequestContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil)
	_, ok := GetRequestCredential(c)
	assert.False(t, ok)
	_, ok = model.RequestCredentialFrom(c.Request.Context())
	assert.False(t, ok)

	p := authz.NewPrincipal(7, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)
	BindRequestPrincipal(c, p, model.RequestCredentialHumanSession)
	assert.Same(t, p, PrincipalFrom(c))
	assert.Same(t, p, authz.PrincipalFromContext(c.Request.Context()))
	kind, ok := GetRequestCredential(c)
	assert.True(t, ok)
	assert.Equal(t, model.RequestCredentialHumanSession, kind)
	kind, ok = model.RequestCredentialFrom(c.Request.Context())
	assert.True(t, ok)
	assert.Equal(t, model.RequestCredentialHumanSession, kind)
	_, bg := model.BackgroundInitiatorFrom(model.WithBackgroundInitiator(c.Request.Context(), 7, "u"))
	assert.False(t, bg, "請求脈絡上不產生背景標示")
}
