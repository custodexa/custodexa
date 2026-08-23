package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
)

// SessionServiceInterface Session 服務接口（用於測試注入）
type SessionServiceInterface interface {
	List(filter *session.SessionFilter) (*session.SessionListResponse, error)
	GetByID(id uint) (*model.Session, error)
	GetActiveSessions() ([]model.Session, error)
	Terminate(id uint, reason string) error
	GetStatistics() (map[string]interface{}, error)
}

// SessionHandler Session API handler
type SessionHandler struct {
	sessionService SessionServiceInterface
}

// NewSessionHandler 創建 Session handler
func NewSessionHandler(sessionService SessionServiceInterface) *SessionHandler {
	return &SessionHandler{
		sessionService: sessionService,
	}
}

// List 列出 Session
func (h *SessionHandler) List(c *gin.Context) {
	// 解析過濾參數
	filter := &session.SessionFilter{
		Page:     1,
		PageSize: 20,
	}

	// 解析使用者 ID
	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := strconv.ParseUint(userIDStr, 10, 32); err == nil {
			uid := uint(userID)
			filter.UserID = &uid
		}
	}

	// 解析資產 ID
	if assetIDStr := c.Query("asset_id"); assetIDStr != "" {
		if assetID, err := strconv.ParseUint(assetIDStr, 10, 32); err == nil {
			aid := uint(assetID)
			filter.AssetID = &aid
		}
	}

	// 解析協議
	if protocol := c.Query("protocol"); protocol != "" {
		filter.Protocol = model.ProtocolType(protocol)
	}

	// 解析狀態
	if status := c.Query("status"); status != "" {
		filter.Status = model.SessionStatus(status)
	}

	// 解析時間範圍
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

	// 解析頁碼
	if page, err := strconv.Atoi(c.Query("page")); err == nil && page > 0 {
		filter.Page = page
	}

	// 解析每頁大小
	if pageSize, err := strconv.Atoi(c.Query("page_size")); err == nil && pageSize > 0 {
		filter.PageSize = pageSize
	}

	// 查詢 Session
	result, err := h.sessionService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionAdminQuery, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get 取得 Session 詳情
func (h *SessionHandler) Get(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}

	// 查詢 Session
	sess, err := h.sessionService.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionAdminQuery, err)
		return
	}

	c.JSON(http.StatusOK, sess)
}

// GetActive 取得所有活動 Session
func (h *SessionHandler) GetActive(c *gin.Context) {
	sessions, err := h.sessionService.GetActiveSessions()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionActiveQuery, err)
		return
	}

	c.JSON(http.StatusOK, sessions)
}

// Terminate 強制終止 Session
func (h *SessionHandler) Terminate(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}

	// 檢查管理員權限（僅管理員可強制斷線）
	role, exists := c.Get("role")
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	roleStr, ok := role.(string)
	if !ok || roleStr != "admin" {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSessionTerminateAdminOnly, nil)
		return
	}

	// 終止 Session
	if err := h.sessionService.Terminate(uint(id), model.EndReasonAdminTerminate); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		if errors.Is(err, session.ErrSessionAlreadyClosed) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeSessionClosed, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionTerminate, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// GetStatistics 取得統計資訊
func (h *SessionHandler) GetStatistics(c *gin.Context) {
	stats, err := h.sessionService.GetStatistics()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionStatistics, err)
		return
	}

	c.JSON(http.StatusOK, stats)
}

// RegisterRoutes 註冊 Session 相關路由
func (h *SessionHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	sessions := r.Group("/sessions")
	sessions.Use(middleware.AuthMiddleware(authService))

	// 敏感讀取端點無條件要求 session:view：
	// session 列表/詳情/活動/統計含他人連線紀錄，不得因
	// debug 旁路而對一般登入者敞開（該旁路已隨權限旗標退場）
	sessions.GET("", middleware.RequirePermission(middleware.PermSessionView), h.List)
	sessions.GET("/active", middleware.RequirePermission(middleware.PermSessionView), h.GetActive)
	sessions.GET("/statistics", middleware.RequirePermission(middleware.PermSessionView), h.GetStatistics)
	sessions.GET("/:id", middleware.RequirePermission(middleware.PermSessionView), h.Get)

	// 寫入端點維持既有 flag 行為（Terminate 另有 handler 內 admin 檢查）
	sessions.POST("/:id/terminate", middleware.RequirePermission(middleware.PermSessionTerminate), h.Terminate)
}
