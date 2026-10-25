package middleware

import (
	"net/http"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// 能力拒絕的單一寫出點。
//
// 凡「主體不具該操作所需能力」的拒絕，回應一律是 403 與只含 code、error 兩鍵的本文
// （code＝AUTH_PERMISSION_DENIED），不帶權限點、角色或內建身分名稱。拒絕依據（種類與所列鍵）
// 只存進請求脈絡，由審計中介層取用；回應本身不因依據不同而有任何差異。

// capabilityDenialContextKey 能力拒絕依據在請求脈絡中的鍵。
const capabilityDenialContextKey = "authz_capability_denial"

// CapabilityDenial 能力拒絕的依據。Basis 為 all_of／any_of／reserved／unregistered；
// Required 在 all_of、any_of 為權限點鍵，在 reserved 為受控條件值，在 unregistered 為空。
type CapabilityDenial struct {
	Basis    authz.DenialBasis
	Required []string
}

// WriteCapabilityDenial 能力拒絕的唯一寫出函式：存依據、回單一形狀、中止後續處理。
func WriteCapabilityDenial(c *gin.Context, d CapabilityDenial) {
	c.Set(capabilityDenialContextKey, CapabilityDenial{Basis: d.Basis, Required: append([]string(nil), d.Required...)})
	markAuthzDenial(c, denialKindCapability)
	writeCapabilityShape(c)
	c.Abort()
}

// writeCapabilityShape 能力拒絕的 403 本文；本函式與範圍出口的未登記種類分支共用，回應不得分岔。
func writeCapabilityShape(c *gin.Context) {
	apierror.Write(c, http.StatusForbidden, apierror.ErrorResponse{Code: apierror.CodePermissionDenied})
}

// CapabilityDenialFrom 取本請求經 WriteCapabilityDenial 存下的拒絕依據；未經它拒絕回 false。
func CapabilityDenialFrom(c *gin.Context) (CapabilityDenial, bool) {
	v, ok := c.Get(capabilityDenialContextKey)
	if !ok {
		return CapabilityDenial{}, false
	}
	d, ok := v.(CapabilityDenial)
	return d, ok
}

// ReservedCapabilityDenial 保留條件的拒絕依據；cond 須為 authz.Reserved* 常數之一。
func ReservedCapabilityDenial(cond string) CapabilityDenial {
	return CapabilityDenial{Basis: authz.DenialReserved, Required: []string{cond}}
}

// AllOfCapabilityDenial 所列權限點皆須持有的拒絕依據（handler 內以權限點判定者）。
func AllOfCapabilityDenial(perms ...authz.Permission) CapabilityDenial {
	req := make([]string, len(perms))
	for i, p := range perms {
		req[i] = string(p)
	}
	return CapabilityDenial{Basis: authz.DenialAllOf, Required: req}
}

// RouteCapabilityDenial 把路由判定的拒絕依據轉成能力拒絕依據（登錄閘、預設拒絕，
// 以及 handler 以同一登錄項重新判定被拒時共用）。
func RouteCapabilityDenial(d authz.Decision) CapabilityDenial {
	req := make([]string, len(d.Required))
	for i, p := range d.Required {
		req[i] = string(p)
	}
	return CapabilityDenial{Basis: d.Basis, Required: req}
}
