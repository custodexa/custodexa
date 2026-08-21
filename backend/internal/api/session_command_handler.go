package api

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// SessionCommandServiceInterface 指令審計服務接口（用於測試注入）
type SessionCommandServiceInterface interface {
	ListBySession(sessionID uint) ([]model.SessionCommand, error)
	Search(filter *audit.SessionCommandFilter) (*audit.SessionCommandListResponse, error)
}

// SessionCommandHandler 指令審計 API handler
type SessionCommandHandler struct {
	commandService SessionCommandServiceInterface
}

// NewSessionCommandHandler 創建指令審計 handler
func NewSessionCommandHandler(commandService SessionCommandServiceInterface) *SessionCommandHandler {
	return &SessionCommandHandler{commandService: commandService}
}

// ListBySession 取得單一會話的指令流
func (h *SessionCommandHandler) ListBySession(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}

	commands, err := h.commandService.ListBySession(uint(id))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionCommandQuery, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  commands,
		"total": len(commands),
	})
}

// Search 跨會話指令搜尋
func (h *SessionCommandHandler) Search(c *gin.Context) {
	filter := &audit.SessionCommandFilter{
		Keyword:  c.Query("keyword"),
		Page:     1,
		PageSize: 20,
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

	// degraded 過濾：`true`＝只要降級列、`false`＝只要有文字的列、未帶＝不過濾。
	// 無法解析時**不套用**（與上方 user_id／asset_id 的既有寬鬆解析同紀律）：
	// 回傳的是超集而非子集，錯誤在呼叫端立刻看得見，不會靜默少給。
	if degradedStr := c.Query("degraded"); degradedStr != "" {
		if degraded, err := strconv.ParseBool(degradedStr); err == nil {
			filter.Degraded = &degraded
		}
	}

	if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 0 {
		filter.Page = page
	}
	if pageSize, err := strconv.Atoi(c.Query("page_size")); err == nil && pageSize > 0 {
		filter.PageSize = pageSize
	}

	result, err := h.commandService.Search(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionCommandSearch, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// RegisterRoutes 註冊指令審計路由（design D5）：
// - 單會話清單掛 session 檢視權限（與 session detail 同模式）
// - 跨會話搜尋掛 audit 檢視權限（與 audit_logs 同模式）
func (h *SessionCommandHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	sessions := r.Group("/sessions")
	sessions.Use(middleware.AuthMiddleware(authService))

	commands := r.Group("/commands")
	commands.Use(middleware.AuthMiddleware(authService))

	// per-session 指令含終端輸入原文（可能有密碼），無條件要求 session:view，
	// 無條件強制（session-access-scoping；權限旗標已退場）
	sessions.GET("/:id/commands", middleware.RequirePermission(middleware.PermSessionView), h.ListBySession)

	commands.GET("", middleware.RequirePermission(middleware.PermAuditView), h.Search)
}
