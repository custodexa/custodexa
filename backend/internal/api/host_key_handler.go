package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// hostKeyMismatchViewLimit 檢視最多列出的待確認指紋數（最近出現者在前）
const hostKeyMismatchViewLimit = 5

// HostKeyServiceInterface host key 服務接口（用於測試注入）
type HostKeyServiceInterface interface {
	Get(assetID uint) (*model.AssetHostKey, error)
	Observations(assetID uint, limit int) ([]model.AssetHostKeyMismatch, error)
	Reset(assetID uint, actor asset.HostKeyActor) (bool, error)
	Adopt(assetID uint, fingerprint string, actor asset.HostKeyActor) (*model.AssetHostKey, error)
}

// HostKeyHandler 資產 host key 管理 API（host-key-verification）
type HostKeyHandler struct {
	hostKeys HostKeyServiceInterface
	authz    middleware.AssetPermissionChecker
	// managed 範圍化檢視者的管理可視（只開讀取入口）；nil＝守門與現行相同
	managed middleware.AssetManagementVisibility
}

// SetAssetManagementVisibility 注入讀取入口的管理可視來源（組裝端呼叫，須早於 RegisterRoutes）。
// 只影響檢視；重置與採用的超管資格不變。
func (h *HostKeyHandler) SetAssetManagementVisibility(m middleware.AssetManagementVisibility) {
	h.managed = m
}

// NewHostKeyHandler 建立 host key handler。authz 用於逐資產可視性守門
// （host-key 揭露資產指紋與存在性，須與 /assets/:id 同級授權）
func NewHostKeyHandler(hostKeys HostKeyServiceInterface, authz middleware.AssetPermissionChecker) *HostKeyHandler {
	return &HostKeyHandler{hostKeys: hostKeys, authz: authz}
}

// hostKeyMismatchView 檢視內的待確認指紋（公鑰本體不外露）
type hostKeyMismatchView struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`
	SeenCount   int    `json:"seen_count"`
}

// hostKeyActor 由請求脈絡取執行採用或重置的操作者
func hostKeyActor(c *gin.Context) asset.HostKeyActor {
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	return asset.HostKeyActor{UserID: userID, Username: username, ClientIP: sourceip.Of(c)}
}

// Get 檢視資產的 host key 指紋。有觀察紀錄時多回 mismatches（最多 5 筆、最近出現者在前）；
// 沒有觀察紀錄時回應與既有逐位元組相同（不帶該欄）。
func (h *HostKeyHandler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	rec, err := h.hostKeys.Get(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeHostKeyNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalHostKeyQuery, err)
		return
	}
	observations, err := h.hostKeys.Observations(uint(id), hostKeyMismatchViewLimit)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalHostKeyQuery, err)
		return
	}
	var body gin.H
	if rec.Inherited {
		// 本資產尚無自身記錄，回傳沿用的同位址記錄：標 inherited，asset_id 為被查資產，
		// 不回傳來源記錄的識別與時間戳（不揭露來源資產的存在與其建立、更新時間）
		body = gin.H{
			"asset_id": rec.AssetID, "algorithm": rec.Algorithm, "fingerprint": rec.Fingerprint,
			"inherited": true,
		}
	} else {
		body = gin.H{
			"id": rec.ID, "asset_id": rec.AssetID, "algorithm": rec.Algorithm, "fingerprint": rec.Fingerprint,
			"created_at": rec.CreatedAt, "updated_at": rec.UpdatedAt,
		}
	}
	if len(observations) > 0 {
		views := make([]hostKeyMismatchView, 0, len(observations))
		for _, o := range observations {
			views = append(views, hostKeyMismatchView{
				Algorithm: o.ObservedAlgorithm, Fingerprint: o.ObservedFingerprint,
				FirstSeenAt: o.FirstSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
				LastSeenAt:  o.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
				SeenCount:   o.SeenCount,
			})
		}
		body["mismatches"] = views
	}
	c.JSON(http.StatusOK, body)
}

// Reset 重置資產 host key（超管保留；主機重灌場景）。生效的重置連同一則系統告警同交易寫入。
func (h *HostKeyHandler) Reset(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	existed, err := h.hostKeys.Reset(uint(id), hostKeyActor(c))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalHostKeyReset, err)
		return
	}
	if !existed {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeHostKeyNoRecordToReset, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// hostKeyAdoptRequest 採用請求：只接受該資產觀察紀錄中存在的指紋
type hostKeyAdoptRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// Adopt 把觀察紀錄中的一個指紋採用為資產的主機金鑰記錄（超管保留）。
// 成功回 200 與新的檢視內容（與 GET 的自身記錄同形，沒有 mismatches）。
func (h *HostKeyHandler) Adopt(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	var req hostKeyAdoptRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Fingerprint) == "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	rec, err := h.hostKeys.Adopt(uint(id), strings.TrimSpace(req.Fingerprint), hostKeyActor(c))
	if err != nil {
		if errors.Is(err, asset.ErrHostKeyObservationNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeHostKeyObservationNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalHostKeyAdopt, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": rec.ID, "asset_id": rec.AssetID, "algorithm": rec.Algorithm, "fingerprint": rec.Fingerprint,
		"created_at": rec.CreatedAt, "updated_at": rec.UpdatedAt,
	})
}

// RequireHostKeyResetSuperAdmin 重置與採用端點（匯出供路由測試掛同一條守衛鏈）的保留資格守衛：
// 登錄項為 BaseAuthenticated，超管身分屬保留能力（不是可指派的權限），由此判定；
// 非超管回能力拒絕單一形狀（依據為保留條件），服務不被呼叫。
func RequireHostKeyResetSuperAdmin(c *gin.Context) {
	if p := middleware.PrincipalFrom(c); p == nil || !p.IsSuperAdmin() {
		middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedSuperAdmin))
		return
	}
	c.Next()
}

// RegisterRoutes 註冊路由：檢視需對該資產有可視授權（非 admin/auditor 逐資產守門），
// 重置與採用 admin only。逐資產守門無條件生效（權限旗標已退場）。
func (h *HostKeyHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/assets/:id/host-key")
	g.Use(middleware.AuthMiddleware(authService))
	{
		g.GET("", middleware.EnforceRegistry(), middleware.RequireAssetVisibleOrManaged(h.authz, h.managed), h.Get)
		g.DELETE("", middleware.EnforceRegistry(), RequireHostKeyResetSuperAdmin, h.Reset)
		g.POST("/adopt", middleware.EnforceRegistry(), RequireHostKeyResetSuperAdmin, h.Adopt)
	}
}
