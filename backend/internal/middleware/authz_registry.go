package middleware

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// 路由登錄執行中介層。
//
// 掛在原守衛所在的位置；判定本體在 authz.DecideRoute（手動認證入口不經此函式，改以現查主體加資產授權判定），
// 這裡只保留 HTTP 關注點：取主體、回 401，拒絕一律交能力拒絕的單一寫出函式。
// 未登錄的路由一律拒絕（預設拒絕），回應與其他能力拒絕同形。

const principalContextKey = "authz_principal"

// SetPrincipal 把解析後的主體放入請求脈絡（由 AuthMiddleware 呼叫）。
func SetPrincipal(c *gin.Context, p *authz.Principal) { c.Set(principalContextKey, p) }

// PrincipalFrom 取請求脈絡中的主體；未設定回傳 nil。
func PrincipalFrom(c *gin.Context) *authz.Principal {
	v, ok := c.Get(principalContextKey)
	if !ok {
		return nil
	}
	p, _ := v.(*authz.Principal)
	return p
}

// EnforceRegistry 依 (method, c.FullPath()) 查登錄表並判定；登錄項宣告了目標解析時，
// 能力判定通過後再以 gate 的判定器做範圍判定（scope_gate.go）。gate 至多一個，由組裝端經
// handler 建構參數傳入；未傳入時，宣告了目標的登錄項一律不放行。
//
// 本函式只回傳小閉包、判定邏輯在 enforceRegistry：路由快照記錄的中介層名稱取決於本函式是否被內聯。
func EnforceRegistry(gate ...*ScopeGate) gin.HandlerFunc {
	var g *ScopeGate
	if len(gate) > 0 {
		g = gate[0]
	}
	return func(c *gin.Context) { enforceRegistry(c, g) }
}
