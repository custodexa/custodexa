package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// CommandAlertServiceInterface 告警查詢服務接口（用於測試注入）
type CommandAlertServiceInterface interface {
	List(filter *audit.CommandAlertFilter) (*audit.CommandAlertListResponse, error)
	Review(alertID, reviewerID uint, disposition, note string) error
	ReviewInBatch(alertID, reviewerID uint, disposition, note string) error
	ReviewBatch(in audit.AlertBatchReviewInput) (*audit.AlertBatchReviewResult, error)
	IsTriggeredBy(alertID, userID uint) (bool, error)
}

// maxAlertIDsQuery `ids` 查詢參數的個數上限（與前端批次上限同量級）
const maxAlertIDsQuery = 50

// CommandAlertHandler 告警查詢 API handler（command-alerts，audit:view）
type CommandAlertHandler struct {
	alertService CommandAlertServiceInterface
	// auditService 審閱處置的顯式審計；nil 表示停用
	auditService *audit.AuditLogService
}

// NewCommandAlertHandler 創建告警查詢 handler
func NewCommandAlertHandler(alertService CommandAlertServiceInterface) *CommandAlertHandler {
	return &CommandAlertHandler{alertService: alertService}
}

// SetAuditService 注入審計服務（審閱處置事件留痕）
func (h *CommandAlertHandler) SetAuditService(auditService *audit.AuditLogService) {
	h.auditService = auditService
}

// List 告警列表查詢
func (h *CommandAlertHandler) List(c *gin.Context) {
	filter := &audit.CommandAlertFilter{
		Kind:     c.Query("kind"),
		Page:     1,
		PageSize: 20,
	}

	// severity 在 handler 層先驗證：非法值直接 400 比靜默回空集合更可診斷
	if severity := c.Query("severity"); severity != "" {
		if !model.ValidAlertSeverity(severity) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAlertSeverity, nil)
			return
		}
		filter.Severity = severity
	}

	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := strconv.ParseUint(userIDStr, 10, 32); err == nil {
			uid := uint(userID)
			filter.UserID = &uid
		}
	}
	if assetIDStr := c.Query("asset_id"); assetIDStr != "" {
		if assetID, err := strconv.ParseUint(assetIDStr, 10, 32); err == nil {
			aid := uint(assetID)
			filter.AssetID = &aid
		}
	}
	if raw, present := c.GetQuery("session_id"); present {
		id, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || id == 0 {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		sessionID := uint(id)
		filter.SessionID = &sessionID
	}
	if raw, present := c.GetQuery("blocked"); present {
		if raw != "true" && raw != "false" {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		blocked := raw == "true"
		filter.Blocked = &blocked
	}

	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = &startTime
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = &endTime
		}
	}

	// 未審閱篩選（audit-workflows）：供每日審閱走查（10.4.1）
	if c.Query("unreviewed") == "true" {
		filter.Unreviewed = true
	}

	// 指定 id 清單（批次審閱）：批次中斷後查回每筆實際處置
	if raw := c.Query("ids"); raw != "" {
		parts := strings.Split(raw, ",")
		if len(parts) > maxAlertIDsQuery {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCommandAlertID, nil)
			return
		}
		for _, p := range parts {
			id, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
			if err != nil || id == 0 {
				apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCommandAlertID, nil)
				return
			}
			filter.IDs = append(filter.IDs, uint(id))
		}
		if filter.PageSize < len(filter.IDs) {
			filter.PageSize = len(filter.IDs)
		}
	}

	if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 0 {
		filter.Page = page
	}
	if pageSize, err := strconv.Atoi(c.Query("page_size")); err == nil && pageSize > 0 {
		filter.PageSize = pageSize
	}

	result, err := h.alertService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCommandAlertQuery, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Review 審閱處置一筆告警（audit-workflows，PCI 10.4.1）
func (h *CommandAlertHandler) Review(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCommandAlertID, nil)
		return
	}

	var req struct {
		Disposition string `json:"disposition" binding:"required"`
		Note        string `json:"note"`
		// BatchID 批次關聯碼：同一批逐筆送出的每筆帶同一個值，
		// 經稽核放行集原樣進該筆的稽核列。帶了才套批次條件（理由必填、不收本人
		// 觸發、不覆蓋已審閱）；不帶則維持單筆語義（含重新審閱）
		BatchID string `json:"batch_id" binding:"omitempty,uuid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewRequest, nil)
		return
	}

	reviewerID, _ := middleware.GetCurrentUserID(c)
	// 審閱者是否即觸發者：在更新前讀出，供顯式稽核列標示（不影響判定；帶批次關聯碼的
	// 舊路徑本來就不收本人觸發，恆為 false）
	// 讀不到觸發者時不寫這個鍵（不把「無法判定」記成「不是」）
	selfKnown, self := true, false
	if h.auditService != nil && req.BatchID == "" {
		var lookupErr error
		if self, lookupErr = h.alertService.IsTriggeredBy(uint(id), reviewerID); lookupErr != nil {
			selfKnown = false
		}
	}
	review := h.alertService.Review
	if req.BatchID != "" {
		review = h.alertService.ReviewInBatch
	}
	if err := review(uint(id), reviewerID, req.Disposition, req.Note); err != nil {
		switch err {
		case audit.ErrAlertNotFound:
			apierror.Respond(c, http.StatusNotFound, apierror.CodeCommandAlertNotFound, nil)
		case audit.ErrInvalidDisposition:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDisposition, nil)
		case audit.ErrAlertBatchNote, audit.ErrAlertNoteTooLong:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAlertBatchNote, nil)
		case audit.ErrAlertSelfTriggered:
			apierror.Respond(c, http.StatusForbidden, apierror.CodeAlertBatchSelfTriggered, nil)
		case audit.ErrAlertAlreadyReviewed:
			apierror.Respond(c, http.StatusConflict, apierror.CodeAlertAlreadyReviewed, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAlertReview, err)
		}
		return
	}

	// 審閱處置屬稽核動作，顯式留痕（誰在何時將哪筆告警處置為何）；
	// details 標出審閱者是否即觸發者（逐筆審閱本人觸發的告警理由仍選填，但留下標示）
	if h.auditService != nil {
		reviewerName, _ := middleware.GetCurrentUsername(c)
		alertID := uint(id)
		details := ""
		if selfKnown {
			raw, _ := json.Marshal(map[string]bool{"self_review": self})
			details = string(raw)
		}
		h.auditService.Log(middleware.AttributeAuditEntry(c, &audit.AuditLogEntry{
			UserID:     reviewerID,
			Username:   reviewerName,
			Action:     model.ActionUpdate,
			Resource:   model.ResourceCommandAlert,
			ResourceID: &alertID,
			Status:     model.StatusSuccess,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
			ErrorMsg:   "alert_disposition_" + req.Disposition,
			Details:    details,
		}))
	}

	// 成功訊息不落 payload：前端以自有 $t 文案顯示
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// alertBatchReviewBodyLimit 批次審閱請求本文的上限：上限筆數的編號加上理由遠小於此值
const alertBatchReviewBodyLimit = 64 << 10

// alertBatchReviewRequest 批次審閱的請求本文
type alertBatchReviewRequest struct {
	AlertIDs    []uint `json:"alert_ids" binding:"required"`
	Disposition string `json:"disposition" binding:"required"`
	Note        string `json:"note"`
	BatchID     string `json:"batch_id" binding:"required,uuid"`
	// SelfTriggeredAck 已確認看過的本人觸發筆數；沒有本人觸發時為 0 或不帶
	SelfTriggeredAck int `json:"self_triggered_ack"`
}

// BatchReview 一次請求審閱多筆告警（audit-workflows「告警批次審閱」）。
//
// 整批檢查（格式、關聯碼、筆數上限、處置分類、理由、本人觸發筆數）任一不成立即整批拒收、
// 一筆都不寫；通過後逐筆判定，結果逐筆回報（200）。逐筆的處置稽核列由服務層在同一交易內寫入
func (h *CommandAlertHandler) BatchReview(c *gin.Context) {
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, alertBatchReviewBodyLimit))
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewRequest, nil)
		return
	}
	var req alertBatchReviewRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewRequest, nil)
		return
	}
	if err := binding.Validator.ValidateStruct(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewRequest, nil)
		return
	}

	reviewerID, _ := middleware.GetCurrentUserID(c)
	reviewerName, _ := middleware.GetCurrentUsername(c)
	meta := gatewayapi.RequestMeta{Method: c.Request.Method, Path: c.Request.URL.Path,
		ClientIP: sourceip.Of(c), StatusCode: http.StatusOK, RequestID: c.GetString("request_id")}
	if o, ok := model.RequestOriginFrom(c.Request.Context()); ok {
		meta.RequestID, meta.ClientIP = o.RequestID, o.ClientIP
	}
	result, err := h.alertService.ReviewBatch(audit.AlertBatchReviewInput{
		AlertIDs: req.AlertIDs, Disposition: req.Disposition, Note: req.Note, BatchID: req.BatchID,
		SelfTriggeredAck: req.SelfTriggeredAck,
		Reviewer:         gatewayapi.Actor{UserID: reviewerID, Username: reviewerName},
		Request:          middleware.AttributeAuditMeta(c, meta),
	})
	if err != nil {
		var selfAck *audit.AlertBatchSelfAckError
		switch {
		case errors.As(err, &selfAck):
			apierror.Write(c, http.StatusConflict, apierror.ErrorResponse{Code: apierror.CodeAlertBatchSelfAck,
				Meta: map[string]any{"self_triggered": selfAck.SelfTriggered}})
		case errors.Is(err, audit.ErrAlertBatchTooLarge):
			apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{Code: apierror.CodeAlertBatchTooLarge,
				Meta: map[string]any{"limit": audit.AlertBatchReviewLimit}})
		case errors.Is(err, audit.ErrAlertBatchEmpty), errors.Is(err, audit.ErrAlertBatchID):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidReviewRequest, nil)
		case errors.Is(err, audit.ErrInvalidDisposition):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDisposition, nil)
		case errors.Is(err, audit.ErrAlertBatchNote):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAlertBatchNote, nil)
		case errors.Is(err, audit.ErrAlertBatchOutcomeUnknown):
			// 提交階段出錯、無法確定是否已提交：不得回 INTERNAL_ALERT_REVIEW（那個碼代表確定沒有生效），
			// 改回告警族既有的一般內部錯誤碼，呼叫端查回實際結果
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCommandAlertQuery, err)
		default:
			// 交易在提交前失敗（含時限在提交前到期），已確定回滾：整批沒有生效
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAlertReview, err)
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

// RegisterRoutes 註冊告警查詢路由：
// 與審計日誌/跨會話指令搜尋同掛 audit:view，無條件強制
func (h *CommandAlertHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	alerts := r.Group("/command-alerts")
	alerts.Use(middleware.AuthMiddleware(authService))
	h.registerOn(alerts)
}

// registerOn 在已掛認證的群組上註冊各路由（正式註冊與路由層測試共用同一份）
func (h *CommandAlertHandler) registerOn(alerts *gin.RouterGroup) {
	alerts.GET("", middleware.EnforceRegistry(), h.List)
	// 審閱處置屬告警管理，掛 alert:manage（auditor/admin 有；user 無）
	alerts.POST("/:id/review", middleware.EnforceRegistry(), h.Review)
	// 批次審閱：權限與單筆審閱相同（alert:manage）
	alerts.POST("/batch-review", middleware.EnforceRegistry(), h.BatchReview)
}
