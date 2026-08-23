package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// RevokeAdminKey context key：RequireRevokeEligibility 放行時寫入 admin 身分，
// 撤銷 handler 據此讓 service 走「admin 兜底」資格分支
//
// 舊的 `ApproverAdminKey`（審核端點的 admin 兜底旗標）已隨審核資格收斂
// 移除——admin 不再是有效審核者，審核端點不存在 admin 兜底身分。
const RevokeAdminKey = "revokeIsAdmin"

// RequireApproverRole 審核端點守門（審核方群組成員即資格）：即時查 DB，
// approver 角色 OR 屬任一審核方群組 放行——不讀 JWT claims
// （approver 為可疊加職能角色，不進 JWT、不參與 primaryRoleOf 三階排序），
// 撤 approver/離組即刻生效、無 token 殘窗。低頻管理端點，索引查詢可接受
//
// **行為變更（BREAKING）**：移除 `isAdmin` 放行分支——
// 僅具 `admin` 角色者對審核端點一律 403。判定改由
// `authz.EvaluateApproverRouteEligibility` 委派給 `IsEffectiveApprover` 的述詞，
// 守衛與入口／badge 判定成為單一真相（收斂前 admin 看不到審核中心入口卻能呼叫審核 API）。
// **脫困路徑**：`PUT /users/:id/roles` 與 `/approver-scopes` 皆不經本守衛（admin only），
// 故零有效審核者時 admin 仍能指派 approver 使系統復原（收斂的硬性附帶條件）。
func RequireApproverRole(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := GetCurrentUserID(c)
		if !exists {
			abortUnauthenticated(c, apierror.CodeUnauthenticated)
			return
		}

		verdict, err := authz.EvaluateApproverRouteEligibility(db, userID)
		if err != nil {
			code := apierror.CodeInternalApproverQuery
			if verdict.RoleQueryFailed {
				code = apierror.CodeInternalRoleQuery
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, code, err)
			c.Abort()
			return
		}
		if !verdict.Allowed {
			apierror.Respond(c, http.StatusForbidden, apierror.CodeApproverRequired, nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRevokeEligibility 撤銷端點守門（與審核端點分離）：
// admin OR 有效審核者放行，判準與收斂前的 `RequireApproverRole` 相同。
//
// **為何不與審核端點一起收斂**：撤銷是**遏制動作不是審核**，既有 spec 明定資格＝
// admin OR 原核准人；一併收斂會使 admin 無法撤銷已核出的票證＝安全倒退。
// 細緻資格由 service 的 `eligibleToRevoke` 裁決。
func RequireRevokeEligibility(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := GetCurrentUserID(c)
		if !exists {
			abortUnauthenticated(c, apierror.CodeUnauthenticated)
			return
		}

		verdict, err := authz.EvaluateRevokeRouteEligibility(db, userID)
		if err != nil {
			code := apierror.CodeInternalApproverQuery
			if verdict.RoleQueryFailed {
				code = apierror.CodeInternalRoleQuery
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, code, err)
			c.Abort()
			return
		}
		if !verdict.Allowed {
			apierror.Respond(c, http.StatusForbidden, apierror.CodeApproverRequired, nil)
			c.Abort()
			return
		}

		c.Set(RevokeAdminKey, verdict.IsAdmin)
		c.Next()
	}
}
