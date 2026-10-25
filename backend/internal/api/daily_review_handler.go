package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/reviewcal"
	"github.com/gin-gonic/gin"
)

// DailyReviewHandler 每日審閱簽核 API（PCI 10.4.1）
type DailyReviewHandler struct {
	reviewService *audit.DailyReviewService
	// namer 事件列原因參數的讀取期換名；nil 時維持識別碼
	namer *AuditReasonNamer
}

// NewDailyReviewHandler 建立每日審閱 handler；namer 為原因參數的名稱換算器（可為 nil）
func NewDailyReviewHandler(reviewService *audit.DailyReviewService, namer *AuditReasonNamer) *DailyReviewHandler {
	return &DailyReviewHandler{reviewService: reviewService, namer: namer}
}

// Status 卡片摘要：啟用狀態、業務時區分界、昨日、待簽與逾期日數、近 30 天統計
func (h *DailyReviewHandler) Status(c *gin.Context) {
	status, err := h.reviewService.Status()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewStatusQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": status})
}

// Pending 待簽日清單（由最早排起，每頁至多 31 天）
func (h *DailyReviewHandler) Pending(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", strconv.Itoa(audit.DailyReviewPendingPageMax)))
	items, total, err := h.reviewService.Pending(page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewPendingQuery, err)
		return
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > audit.DailyReviewPendingPageMax {
		pageSize = audit.DailyReviewPendingPageMax
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"items": items, "total": total, "page": page, "page_size": pageSize}})
}

// PendingCount 待簽日數與已逾期數（側欄徽章輪詢）
func (h *DailyReviewHandler) PendingCount(c *gin.Context) {
	count, overdue, err := h.reviewService.PendingCount()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewPendingQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"count": count, "overdue_count": overdue}})
}

// Day 單日明細
func (h *DailyReviewHandler) Day(c *gin.Context) {
	detail, err := h.reviewService.Day(c.Param("date"))
	if err != nil {
		if errors.Is(err, audit.ErrDailyReviewDateInvalid) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDateInvalid, nil)
			return
		}
		if errors.Is(err, audit.ErrDailyReviewDayNotEnded) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDayNotEnded, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewDayQuery, err)
		return
	}
	h.namer.RenameEventItems(detail.LoginFailures.Items)
	h.namer.RenameEventItems(detail.HighRiskOps.Items)
	c.JSON(http.StatusOK, gin.H{"data": detail})
}

// Stats 期間統計：period=30d|90d，或 from／to（業務時區日期，含頭尾）
func (h *DailyReviewHandler) Stats(c *gin.Context) {
	stats, err := h.reviewService.Stats(audit.StatsPeriod{
		Period: c.Query("period"), From: c.Query("from"), To: c.Query("to"),
	})
	if err != nil {
		if errors.Is(err, audit.ErrDailyReviewPeriodInvalid) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewPeriodInvalid, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewStatsQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": stats})
}

// dailyReviewSignRequest 簽核請求。**沒有簽核時刻欄位**：簽核時刻一律由伺服器
// 於受理時寫入，body 夾帶的任何時刻欄位都被忽略
type dailyReviewSignRequest struct {
	ReviewDate  string `json:"review_date"`
	Note        string `json:"note"`
	DelayReason string `json:"delay_reason"`
}

// Sign 簽核指定所屬日
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

	row, err := h.reviewService.Sign(audit.SignRequest{
		ReviewDate: req.ReviewDate, Note: req.Note, DelayReason: req.DelayReason,
		ReviewerID: userID, ReviewerName: username,
	})
	if err != nil {
		respondDailyReviewSignError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// respondDailyReviewSignError 簽核規則錯誤 → 錯誤碼
func respondDailyReviewSignError(c *gin.Context, err error) {
	var signed *audit.AlreadySignedError
	var settling *audit.DailyReviewSettlingError
	var pending *audit.DailyReviewAlertsPendingError
	var tooLong *audit.DailyReviewTextTooLongError
	switch {
	case errors.As(err, &signed):
		// 「誰、在什麼時刻簽的」進 params：使用者據此判斷不是自己漏簽、無須再追
		// 簽核時刻以該列的切日時區呈現（RFC3339 帶位移），與畫面上的所屬日同一個時區
		signedAt := ""
		if !signed.SignedAt.IsZero() {
			at := signed.SignedAt
			if loc, ok := reviewcal.LoadTimezone(signed.Timezone); ok {
				at = at.In(loc)
			}
			signedAt = at.Format(time.RFC3339)
		}
		apierror.Respond(c, http.StatusConflict, apierror.CodeDailyReviewAlreadySigned, map[string]any{
			"date": signed.Date, "signer": signed.Signer, "signed_at": signedAt, "timezone": signed.Timezone,
		})
	case errors.Is(err, audit.ErrAlreadySigned):
		// 裸 sentinel 保底：僅保住狀態碼
		apierror.Respond(c, http.StatusConflict, apierror.CodeDailyReviewAlreadySigned, map[string]any{
			"date": "", "signer": "", "signed_at": "", "timezone": "",
		})
	case errors.Is(err, audit.ErrDailyReviewDateInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDateInvalid, nil)
	case errors.Is(err, audit.ErrDailyReviewDayNotEnded):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDayNotEnded, nil)
	case errors.As(err, &settling):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDaySettling,
			map[string]any{"signable_at": settling.SignableAt.Format(time.RFC3339)})
	case errors.Is(err, audit.ErrDailyReviewOutOfScope):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDayOutOfScope, nil)
	case errors.As(err, &pending):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewAlertsPending, map[string]any{"count": pending.Count})
	case errors.Is(err, audit.ErrDailyReviewDelayReasonRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewDelayReasonRequired, nil)
	case errors.As(err, &tooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeDailyReviewTextTooLong, map[string]any{"field": tooLong.Field})
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewSign, err)
	}
}

// List 已簽紀錄（新到舊）；late_only=true 只列遲簽者
func (h *DailyReviewHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	rows, total, err := h.reviewService.List(page, pageSize, c.Query("late_only") == "true")
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalDailyReviewListQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"items": rows, "total": total}})
}

// RegisterRoutes 註冊每日審閱路由：查詢掛 audit:view、簽核掛 alert:manage
// （auditor/admin 有；每日審閱是日常審閱操作，非管理層確認語義）。
// 權限檢查在 handler 之前：無權者對任何日期得到同一個 403，不洩漏該日狀態
func (h *DailyReviewHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	reviews := r.Group("/daily-reviews")
	reviews.Use(middleware.AuthMiddleware(authService))
	h.registerOn(reviews)
}

// registerOn 在已掛認證的群組上註冊路由與權限（測試以替身認證共用同一張路由表）
func (h *DailyReviewHandler) registerOn(reviews *gin.RouterGroup) {
	reviews.GET("/status", middleware.EnforceRegistry(), h.Status)
	reviews.GET("/pending", middleware.EnforceRegistry(), h.Pending)
	reviews.GET("/pending/count", middleware.EnforceRegistry(), h.PendingCount)
	reviews.GET("/days/:date", middleware.EnforceRegistry(), h.Day)
	reviews.GET("/stats", middleware.EnforceRegistry(), h.Stats)
	reviews.GET("", middleware.EnforceRegistry(), h.List)
	reviews.POST("", middleware.EnforceRegistry(), h.Sign)
}
