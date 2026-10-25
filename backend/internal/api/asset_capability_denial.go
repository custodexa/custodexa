package api

import (
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// respondAssetCapabilityDenial 資產與憑證服務能力拒絕的出口：回應與其他能力拒絕同形，
// 依據（all_of）取自錯誤值所附的權限點鍵；錯誤值未附鍵者（如未綁欄位判定）記本路由登錄項的
// 操作層級要求。
func respondAssetCapabilityDenial(c *gin.Context, err error) {
	keys := asset.DeniedCapabilities(err)
	if len(keys) == 0 {
		keys = routeRequiredKeys(c)
	}
	perms := make([]authz.Permission, len(keys))
	for i, k := range keys {
		perms[i] = authz.Permission(k)
	}
	middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(perms...))
}

// routeRequiredKeys 本路由登錄項的操作層級要求：權限點路由取其權限點；僅需登入、由欄位條件
// 承擔者取萬用條件的權限點。查無登錄項回 nil。
func routeRequiredKeys(c *gin.Context) []string {
	e, ok := authz.LookupRoute(c.Request.Method, c.FullPath())
	if !ok {
		return nil
	}
	if e.Perm != "" {
		return []string{string(e.Perm)}
	}
	for _, f := range e.Fields {
		if f.Field == authz.FieldWildcard {
			return []string{string(f.Perm)}
		}
	}
	return nil
}

// fieldPermissionKey 本路由登錄項上該欄位條件的權限點鍵；未宣告回空字串。
func fieldPermissionKey(method, fullPath, field string) string {
	e, ok := authz.LookupRoute(method, fullPath)
	if !ok {
		return ""
	}
	for _, f := range e.Fields {
		if f.Field == field {
			return string(f.Perm)
		}
	}
	return ""
}
