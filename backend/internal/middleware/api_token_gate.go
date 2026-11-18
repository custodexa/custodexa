package middleware

import (
	"net/http"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// APITokenRouteDecider 以 API token 認證的請求查路由登錄。path 為 gin 的樣板路徑（c.FullPath()），
// 查無路由時為空字串。正式組裝為 LookupAPITokenRoute。
type APITokenRouteDecider func(method, path string) APITokenRouteVerdict

// APITokenGate API token 的全域閘門：註冊在所有路由之前、緊接 agent 閘門之後，公開路由、WebSocket 入口
// 與查無的路徑因此都繞不過。
//
// 帶 API token 前綴的請求在此認證一次（之後的認證中介層沿用已建立的主體），失敗走唯一的未認證出口
// （401）；認證時依這次路由的性質決定計入哪些授權角色（性質恰為讀計入全部，其他只計入層級為讀寫者）。
// 認證通過而路由不開放、未登錄或查無路由時回 403 AUTH_API_TOKEN_FORBIDDEN_ROUTE；路由開放且性質不是讀、
// 而這把 token 沒有任何層級為讀寫的授權角色時回 403 AUTH_API_TOKEN_READ_ONLY，不進處理函式。
// 兩種拒絕都在稽核列的 details 留下 denial＝api_token 與 basis＝forbidden_route／read_only（見 denial_audit.go）。
// 順序固定為認證、開放判定、全唯讀判定。其他請求（人類工作階段、agent 鑰匙、不帶憑證）原樣放行，行為不變。
// 認證選角色與開放判定用同一次查登錄的結果。
func APITokenGate(auth *identity.AuthService) gin.HandlerFunc {
	return (&apiTokenGate{auth: auth, decide: LookupAPITokenRoute}).Handle
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
	decide := g.decide
	if decide == nil {
		decide = denyAllAPITokenRoutes
	}
	verdict := decide(c.Request.Method, c.FullPath())
	if kind, ok := GetRequestCredential(c); !ok || kind != model.RequestCredentialAPIToken {
		if !authenticateAPIToken(c, g.auth, strings.TrimPrefix(bearer, "Bearer "), verdict) {
			return
		}
	}
	if !verdict.Open {
		rejectAPIToken(c, apierror.CodeAuthAPITokenForbiddenRoute, apiTokenDenialForbiddenRoute)
		return
	}
	if !verdict.CountsAllGrantedRoles() && !apiTokenHasReadWriteRole(c) {
		rejectAPIToken(c, apierror.CodeAuthAPITokenReadOnly, apiTokenDenialReadOnly)
		return
	}
	c.Next()
}

// rejectAPIToken 閘門拒絕的唯一寫出點：留下稽核用的拒絕標記與依據，回 403 並中止後續處理。
func rejectAPIToken(c *gin.Context, code apierror.ErrCode, basis string) {
	markAPITokenDenial(c, basis)
	apierror.Respond(c, http.StatusForbidden, code, nil)
	c.Abort()
}

// denyAllAPITokenRoutes 沒有可用的判定時一律不開放。
func denyAllAPITokenRoutes(string, string) APITokenRouteVerdict { return APITokenRouteVerdict{} }
