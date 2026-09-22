package middleware

import (
	"net/http"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// AgentRouteAllowlist is global so public/scoped routes and WebSocket handshakes
// cannot bypass it. Human requests are unchanged; agent facts are read once.
func AgentRouteAllowlist(auth *identity.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		kind, _ := GetPrincipalKind(c)
		bearer := c.GetHeader("Authorization")
		if kind != "agent" && strings.HasPrefix(bearer, "Bearer "+identity.AgentTokenPrefix) {
			if !authenticateAgent(c, auth, strings.TrimPrefix(bearer, "Bearer ")) {
				return
			}
			kind = model.KindAgent
		}
		if kind != model.KindAgent {
			c.Next()
			return
		}
		allowed, _ := AgentRouteDecision(c.Request.Method, c.FullPath())
		if !allowed {
			apierror.Respond(c, http.StatusForbidden, apierror.CodeAuthAgentForbiddenRoute, nil)
			c.Abort()
			return
		}
		c.Next()
	}
}
