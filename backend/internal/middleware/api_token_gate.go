package middleware

import (
	"net/http"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// APITokenRouteDecider 以 API token 認證的請求能否呼叫某條路由：(是否開放, 是否已登錄)。
// path 為 gin 的樣板路徑（c.FullPath()），查無路由時為空字串。
type APITokenRouteDecider func(method, path string) (allowed, registered bool)

// APITokenGate API token 的全域閘門：註冊在所有路由之前、緊接 agent 閘門之後，公開路由、WebSocket 入口
// 與查無的路徑因此都繞不過。
//
// 帶 API token 前綴的請求在此認證一次（之後的認證中介層沿用已建立的主體），失敗走唯一的未認證出口
// （401）；認證通過而路由不開放、未登錄或查無路由時回 403。其他請求（人類工作階段、agent 鑰匙、
// 不帶憑證）原樣放行，行為不變。路由範圍以 APITokenRouteDecision 判定。
func APITokenGate(auth *identity.AuthService) gin.HandlerFunc {
	return (&apiTokenGate{auth: auth, decide: APITokenRouteDecision}).Handle
}

// apiTokenGate 閘門的具名承載體：中介層鏈以 runtime 函式名記錄，具名方法的名稱不隨內聯與呼叫位置改變。
type apiTokenGate struct {
	auth   *identity.AuthService
	decide APITokenRouteDecider
}

// Handle 閘門本體。
func (g *apiTokenGate) Handle(c *gin.Context) {
	if kind, ok := GetRequestCredential(c); ok && kind != model.RequestCredentialAPIToken {
		c.Next() // 前面的閘門已以其他憑證認證（agent 鑰匙）
		return
	}
	bearer := c.GetHeader("Authorization")
	if !strings.HasPrefix(bearer, "Bearer "+identity.APITokenPrefix) {
		c.Next()
		return
	}
	if kind, ok := GetRequestCredential(c); !ok || kind != model.RequestCredentialAPIToken {
		if !authenticateAPIToken(c, g.auth, strings.TrimPrefix(bearer, "Bearer ")) {
			return
		}
	}
	decide := g.decide
	if decide == nil {
		decide = denyAllAPITokenRoutes
	}
	if allowed, _ := decide(c.Request.Method, c.FullPath()); !allowed {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeAuthAPITokenForbiddenRoute, nil)
		c.Abort()
		return
	}
	c.Next()
}

// denyAllAPITokenRoutes 沒有可用的判定時一律不開放。
func denyAllAPITokenRoutes(string, string) (bool, bool) { return false, false }
