package middleware

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
)

// AssetPermissionChecker 逐資產授權檢查（由 service 層實作，middleware 只依賴介面避免循環引用）
type AssetPermissionChecker interface {
	CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error)
}

// RequireAssetVisible 逐資產可視性守門（asset-access-scoping）：所有 /assets/:id/*
// 讀取端點統一掛此中介層，非 admin/auditor 須對該資產有 view（含 connect/manage 推導）
// 授權，否則回 404「資產不存在」——不洩漏資產存在性。admin/auditor 直通。
//
// 抽為中介層而非各 handler 自檢：資產子端點（詳情/host-key/k8s pods/未來擴充）
// 共用同一道守門，避免逐一漏網（codex 審查揪出 host-key 端點漏守門）。
func RequireAssetVisible(checker AssetPermissionChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		// admin/auditor 直通（管理角色不做逐資產授權）
		if role, ok := c.Get("role"); ok {
			if r, ok := role.(string); ok && (r == model.RoleAdmin || r == model.RoleAuditor) {
				c.Next()
				return
			}
		}

		id, err := strconv.ParseUint(c.Param("id"), 10, 32)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
			c.Abort()
			return
		}

		userID, exists := GetCurrentUserID(c)
		if !exists {
			abortUnauthenticated(c, apierror.CodeUnauthenticated)
			return
		}

		ctx := c.Request.Context()
		if role, ok := c.Get("role"); ok {
			ctx = context.WithValue(ctx, "role", role) //nolint:staticcheck // 沿用既有 CheckPermission 慣例
		}
		hasPermission, err := checker.CheckPermission(ctx, userID, uint(id), model.PermissionView)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			c.Abort()
			return
		}
		if !hasPermission {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			c.Abort()
			return
		}

		c.Next()
	}
}
