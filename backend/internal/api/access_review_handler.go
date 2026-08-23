package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// AccessReviewHandler 週期性存取複審（audit-workflows v1，PCI 7.2.4）
type AccessReviewHandler struct {
	reviewService *authz.AccessReviewService
	auditService  *audit.AuditLogService
}

// NewAccessReviewHandler 建立存取複審 handler
func NewAccessReviewHandler(reviewService *authz.AccessReviewService, auditService *audit.AuditLogService) *AccessReviewHandler {
	return &AccessReviewHandler{reviewService: reviewService, auditService: auditService}
}

// GetMatrix 取當下完整存取矩陣
func (h *AccessReviewHandler) GetMatrix(c *gin.Context) {
	matrix, err := h.reviewService.GetMatrix()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessMatrixQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": matrix, "total": len(matrix)})
}

// List 複審歷史 + 上次複審距今天數
func (h *AccessReviewHandler) List(c *gin.Context) {
	reviews, err := h.reviewService.ListReviews(50)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessReviewQuery, err)
		return
	}
	daysAgo, err := h.reviewService.LastReviewDaysAgo()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessReviewLastQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":                 reviews,
		"last_review_days_ago": daysAgo, // -1 = 從未複審
		// 週期與逾期由伺服端單源回傳（前端不硬編碼）
		"review_period_days": authz.ReviewPeriodDays,
		"overdue":            daysAgo < 0 || daysAgo > authz.ReviewPeriodDays,
	})
}

// Detail 單筆複審檢視
func (h *AccessReviewHandler) Detail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessReviewID, nil)
		return
	}
	detail, err := h.reviewService.GetReviewDetail(uint(id))
	if err != nil {
		if errors.Is(err, authz.ErrReviewNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAccessReviewNotFound, nil)
			return
		}
		// 快照損壞是策劃過的 sentinel（可安全回顯）；其餘（如 wrapped DB 錯誤）泛化不外洩
		if errors.Is(err, authz.ErrReviewSnapshotCorrupted) {
			apierror.Respond(c, http.StatusInternalServerError, apierror.CodeAccessReviewSnapshotCorrupted, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessReviewDetailQuery, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// Create 提交一筆複審簽核（管理層確認，7.2.4）
func (h *AccessReviewHandler) Create(c *gin.Context) {
	var req struct {
		Note string `json:"note"`
	}
	_ = c.ShouldBindJSON(&req)

	reviewerID, _ := middleware.GetCurrentUserID(c)
	reviewerName, _ := middleware.GetCurrentUsername(c)

	review, err := h.reviewService.CreateReview(reviewerID, reviewerName, req.Note)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAccessReviewCreate, err)
		return
	}

	// 複審簽核入審計（管理層確認的可稽核留痕，7.2.4）
	if h.auditService != nil {
		rid := review.ID
		h.auditService.Log(&audit.AuditLogEntry{
			UserID:     reviewerID,
			Username:   reviewerName,
			Action:     model.ActionCreate,
			Resource:   model.ResourceAccessReview,
			ResourceID: &rid,
			Status:     model.StatusSuccess,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusCreated,
		})
	}

	c.JSON(http.StatusCreated, review)
}

// RegisterRoutes 註冊存取複審路由：讀取限 audit:view、簽核限 admin——
// 全部端點**無條件**強制權限
// （矩陣快照為全庫授權展開、簽核為管理層
// 確認語意，比照敏感端點先例。本 handler 從未有過
// 條件式註冊分支——同期其他 handler 的該類分支已全面移除，
// 旗標本身退場）。
// 路由順序：/matrix 必須先於 /:id
func (h *AccessReviewHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	grp := r.Group("/access-reviews")
	grp.Use(middleware.AuthMiddleware(authService))

	grp.GET("/matrix", middleware.RequirePermission(middleware.PermAuditView), h.GetMatrix)
	grp.GET("", middleware.RequirePermission(middleware.PermAuditView), h.List)
	grp.GET("/:id", middleware.RequirePermission(middleware.PermAuditView), h.Detail)
	// 簽核＝管理層確認（7.2.4），限 admin
	grp.POST("", middleware.RequireRole("admin"), h.Create)
}
