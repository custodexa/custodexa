package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
)

// DailyReviewHandler 每日審閱簽核 API（audit-log-compliance，PCI 10.4.1）
type DailyReviewHandler struct {
	reviewService *audit.DailyReviewService
}

// NewDailyReviewHandler 建立每日審閱 handler
func NewDailyReviewHandler(reviewService *audit.DailyReviewService) *DailyReviewHandler {
	return &DailyReviewHandler{reviewService: reviewService}
}

// Status 今日簽核狀態與事件計數快照（儀表板卡片）
func (h *DailyReviewHandler) Status(c *gin.Context) {
	status, err := h.reviewService.Status(time.Now())
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewStatusQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": status})
}

type dailyReviewSignRequest struct {
	Note string `json:"note"`
}

// Sign 簽核今日審閱
func (h *DailyReviewHandler) Sign(c *gin.Context) {
	if !h.reviewService.Enabled() {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDisabled, nil)
		return
	}
	var req dailyReviewSignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	username, _ := middleware.GetCurrentUsername(c)
	userID, _ := middleware.GetCurrentUserID(c)

	row, err := h.reviewService.Sign(time.Now(), userID, username, req.Note)
	if err != nil {
		// 「幾點由誰簽的」進 params：使用者據此判斷不是自己漏簽、無須再追
		var signed *audit.AlreadySignedError
		if errors.As(err, &signed) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeDailyReviewAlreadySigned,
				map[string]any{"time": signed.SignedAt, "signer": signed.Signer})
			return
		}
		if errors.Is(err, audit.ErrAlreadySigned) {
			// 裸 sentinel 保底（同上：僅保住狀態碼，訊息缺時刻與簽核者）
			apierror.Respond(c, http.StatusConflict, apierror.CodeDailyReviewAlreadySigned, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewSign, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// List 簽核歷史
func (h *DailyReviewHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	rows, total, err := h.reviewService.List(page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewListQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"items": rows, "total": total}})
}

// RegisterRoutes 註冊每日審閱路由：查詢掛 audit:view、簽核掛 alert:manage
// （auditor/admin 有；design D5——每日審閱是日常審閱操作，非管理層確認語義）
func (h *DailyReviewHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	reviews := r.Group("/daily-reviews")
	reviews.Use(middleware.AuthMiddleware(authService))
	reviews.GET("/status", middleware.RequirePermission(middleware.PermAuditView), h.Status)
	reviews.GET("", middleware.RequirePermission(middleware.PermAuditView), h.List)
	reviews.POST("", middleware.RequirePermission(middleware.PermAlertManage), h.Sign)
}
