package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
)

// Permission 權限常數
//
// **SD-4 第一步（modular-architecture W7 7.2）**：型別與角色→權限表已搬入
// `internal/modules/authz`（`authz.Permission`／`authz.RoutePermissions`）。
// 此處保留的是**型別別名與常數轉出**，不是第二份定義——別名使既有 46 條路由的
// `middleware.PermXxx` 呼叫點逐字不動（路由鏈位元相同），而唯一的權限真相在 authz。
type Permission = authz.Permission

const (
	// Asset 權限
	PermAssetView   = authz.PermAssetView
	PermAssetCreate = authz.PermAssetCreate
	PermAssetUpdate = authz.PermAssetUpdate
	PermAssetDelete = authz.PermAssetDelete
	PermAssetTest   = authz.PermAssetTest

	// Session 權限
	PermSessionView      = authz.PermSessionView
	PermSessionTerminate = authz.PermSessionTerminate

	// Audit 權限
	PermAuditView = authz.PermAuditView

	// Alert 權限
	PermAlertView   = authz.PermAlertView
	PermAlertManage = authz.PermAlertManage
)

// RequirePermission 要求特定權限的中間件
// 判定本體在 `authz.RoutePermissions`；此處只保留 HTTP 關注點
// （取 context 身分、取角色、回 401／403）
func RequirePermission(perm Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 從 context 獲取用戶資訊
		_, exists := c.Get("userID")
		if !exists {
			abortUnauthenticated(c, apierror.CodeUnauthenticated)
			return
		}

		// 2. 獲取用戶角色（從 JWT context 設定）
		var role string
		if roleVal, exists := c.Get("role"); exists {
			role = roleVal.(string)
		} else {
			// 如果沒有角色資訊，預設為 user（低權限）
			role = "user"
		}

		// 3. 檢查權限
		if !authz.RoutePermissions(role, perm) {
			apierror.Write(c, http.StatusForbidden, apierror.ErrorResponse{Code: apierror.CodePermissionDenied, Meta: map[string]any{"required_permission": string(perm)}})
			c.Abort()
			return
		}

		c.Next()
	}
}
