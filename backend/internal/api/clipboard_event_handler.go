package api

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
)

// ClipboardEventLister 會話剪貼簿記錄查詢能力（消費者側窄介面，SD-2 收斂）。
// handler 不再自持 `*gorm.DB`：剪貼簿留存屬 session 域，由 `service.SessionService` 實作。
type ClipboardEventLister interface {
	ListClipboardEvents(sessionID uint) ([]model.ClipboardEvent, error)
}

// ClipboardEventHandler 剪貼簿留存查詢 API（clipboard-audit）
type ClipboardEventHandler struct {
	events ClipboardEventLister
}

// NewClipboardEventHandler 建立 handler
func NewClipboardEventHandler(events ClipboardEventLister) *ClipboardEventHandler {
	return &ClipboardEventHandler{events: events}
}

// List 按時間序回傳會話剪貼簿記錄
func (h *ClipboardEventHandler) List(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	events, err := h.events.ListClipboardEvents(uint(id))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalClipboardQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": events, "total": len(events)})
}

// RegisterRoutes 註冊路由（audit 權限，與會話指令流一致）
func (h *ClipboardEventHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/sessions/:id/clipboard-events")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.RequirePermission(middleware.PermAuditView))
	{
		g.GET("", h.List)
	}
}
