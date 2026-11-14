package middleware

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// requestCredentialContextKey gin 脈絡中的請求憑證種類鍵。
const requestCredentialContextKey = "request_credential"

// BindRequestPrincipal 認證成功後把請求主體與請求憑證種類放進請求脈絡：gin 脈絡（handler 用）與
// c.Request 的 context.Context（服務層用）兩處同時設定，所有 HTTP 路徑都取得到同一個主體，
// 不再依賴各 handler 自行放入。人類工作階段、AI agent 鑰匙與 API token 的認證入口都經此設定。
func BindRequestPrincipal(c *gin.Context, p *authz.Principal, kind model.RequestCredential) {
	c.Set(requestCredentialContextKey, kind)
	if c.Request != nil {
		c.Request = c.Request.WithContext(model.WithRequestCredential(c.Request.Context(), kind))
	}
	SetPrincipal(c, p)
}

// GetRequestCredential 這次請求的憑證種類；未經認證入口設定時回 ("", false)。
// 判定處不得以「沒有值」推定為人類工作階段。
func GetRequestCredential(c *gin.Context) (model.RequestCredential, bool) {
	v, ok := c.Get(requestCredentialContextKey)
	kind, typed := v.(model.RequestCredential)
	return kind, ok && typed && kind.Valid()
}
