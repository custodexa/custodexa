package middleware

import (
	"context"
	"github.com/custodexa/backend/internal/modules/authz"
	"log"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/gin-gonic/gin"
)

// AssetPermissionChecker 逐資產授權檢查（由 service 層實作，middleware 只依賴介面避免循環引用）
type AssetPermissionChecker interface {
	CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error)
}

// RequireAssetVisible 逐資產可視性守門：所有 /assets/:id/*
// 讀取端點統一掛此中介層，非 admin/auditor 須對該資產有 view（含 connect/manage 推導）
// 授權，否則回 404「資產不存在」——不洩漏資產存在性。admin/auditor 直通。
//
// 抽為中介層而非各 handler 自檢：資產子端點（詳情/host-key/k8s pods/未來擴充）
// 共用同一道守門，避免逐一漏網（安全審查揪出 host-key 端點漏守門）。
func RequireAssetVisible(checker AssetPermissionChecker) gin.HandlerFunc {
	return requireAssetVisible(checker, nil)
}

// RequireAssetVisibleOrManaged 同 RequireAssetVisible，另在連線可視不成立時接受管理可視
// （範圍化檢視者的資產檢視範圍涵蓋該資產）。兩者皆否與不存在同形。mgmt 為 nil 時與
// RequireAssetVisible 完全相同（未注入不放寬）。經管理可視放行的請求以
// AssetVisibleViaManagement 標記，供 handler 套管理面的額外條件。
func RequireAssetVisibleOrManaged(checker AssetPermissionChecker, mgmt AssetManagementVisibility) gin.HandlerFunc {
	return requireAssetVisible(checker, mgmt)
}

// AssetManagementVisibility 單一資產的管理可視判定（authz.AssetScopeReader 實作）。
// AssetViewScopeDenial 只供範圍化檢視者的拒絕分流：判定器以資產檢視權限點判出範圍拒絕值時經共用出口
// （與不存在同形，另留範圍拒絕原因）；判不出（回 nil）即走現行「不存在」。拒絕值不在本層組出。
type AssetManagementVisibility interface {
	ManagementVisibleAsset(ctx context.Context, assetID uint) (bool, *authz.AssetScopeView, error)
	AssetViewScopeDenial(ctx context.Context, assetID uint) (*authz.ErrScopeDenied, error)
}

const ctxKeyAssetViaManagement = "asset_visible_via_management"

// AssetVisibleViaManagement 本請求是否只經管理可視通過逐資產守門（連線可視不成立）。
func AssetVisibleViaManagement(c *gin.Context) bool {
	v, ok := c.Get(ctxKeyAssetViaManagement)
	b, _ := v.(bool)
	return ok && b
}

func requireAssetVisible(checker AssetPermissionChecker, mgmt AssetManagementVisibility) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 超管／稽核員身分直通（管理視圖不做逐資產授權）
		if PrincipalFrom(c).ViewShortcut() {
			c.Next()
			return
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

		ctx := authz.ContextWithPrincipal(c.Request.Context(), PrincipalFrom(c))
		hasPermission, err := checker.CheckPermission(ctx, userID, uint(id), model.PermissionView)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			c.Abort()
			return
		}
		if !hasPermission && mgmt != nil {
			managed, view, err := mgmt.ManagementVisibleAsset(ctx, uint(id))
			if err != nil {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
				c.Abort()
				return
			}
			if managed {
				c.Set(ctxKeyAssetViaManagement, true)
				c.Next()
				return
			}
			// 持節點範圍管理指派的主體：判定器判出範圍拒絕值時經共用出口（與不存在同形，另留範圍拒絕原因）。
			// 判不出（資產檢視權限點仍為保留或主體不持有）與不持範圍化管理路徑的主體（view 為 nil）
			// 都走下方現行 404，回應與審計不變。
			if view != nil {
				denied, err := mgmt.AssetViewScopeDenial(ctx, uint(id))
				if err != nil {
					apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
					c.Abort()
					return
				}
				if denied != nil {
					RespondScopeDenied(c, denied)
					return
				}
			}
		}
		if !hasPermission {
			if kind, _ := GetPrincipalKind(c); kind == model.KindAgent {
				if tokenID, ok := GetAgentTokenID(c); ok {
					if recorder, ok := checker.(interface {
						RecordDeniedAgentProbe(context.Context, uint, uint, uint, string) error
					}); ok {
						if err := recorder.RecordDeniedAgentProbe(ctx, userID, tokenID, uint(id), c.Request.Method+" "+c.FullPath()); err != nil {
							log.Printf("[AgentProbe] denied event failed user_id=%d asset_ref=%d: %v", userID, id, err)
						}
					}
				}
			}
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			c.Abort()
			return
		}

		c.Next()
	}
}
