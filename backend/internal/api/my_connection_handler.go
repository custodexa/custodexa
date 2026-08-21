package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/session"
)

// MyConnectionServiceInterface 自助連線服務接口（用於測試注入）
type MyConnectionServiceInterface interface {
	ListMyConnections(userID uint, page, pageSize int) (*session.MyConnectionListResponse, error)
	TerminateMyConnection(userID, sessionID uint) error
}

// MyConnectionHandler 自助連線紀錄 API handler（my-connections）
type MyConnectionHandler struct {
	myConnectionService MyConnectionServiceInterface
}

// NewMyConnectionHandler 創建自助連線 handler
func NewMyConnectionHandler(myConnectionService MyConnectionServiceInterface) *MyConnectionHandler {
	return &MyConnectionHandler{myConnectionService: myConnectionService}
}

// List 列出呼叫者自己的連線紀錄
func (h *MyConnectionHandler) List(c *gin.Context) {
	// owner 一律取自 JWT context；不解析任何 client 傳入的 user_id（spec：參數操縱免疫）
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	page := 1
	if v, err := strconv.Atoi(c.Query("page")); err == nil && v > 0 {
		page = v
	}
	pageSize := 20
	if v, err := strconv.Atoi(c.Query("page_size")); err == nil && v > 0 {
		pageSize = v
	}

	result, err := h.myConnectionService.ListMyConnections(userID, page, pageSize)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalMyConnectionQuery, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Terminate 終止呼叫者自己的進行中連線
func (h *MyConnectionHandler) Terminate(c *gin.Context) {
	// owner 一律取自 JWT context；owner 檢查即授權（spec：不受權限旗標影響）
	userID, ok := middleware.GetCurrentUserID(c)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidConnectionID, nil)
		return
	}

	if err := h.myConnectionService.TerminateMyConnection(userID, uint(id)); err != nil {
		switch {
		case errors.Is(err, session.ErrSessionNotFound):
			apierror.Respond(c, http.StatusNotFound, apierror.CodeMyConnectionNotFound, nil)
		case errors.Is(err, session.ErrConnectionNotActive):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeMyConnectionEnded, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalMyConnectionTerminate, err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// RegisterRoutes 註冊自助連線路由：僅 AuthMiddleware，任何登入者可用。
// /my/* 與 /sessions/* 位於不同第一層路徑，不與 /sessions/:id 動態段衝突
func (h *MyConnectionHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	my := r.Group("/my")
	my.Use(middleware.AuthMiddleware(authService))
	my.GET("/connections", h.List)
	my.POST("/connections/:id/terminate", h.Terminate)
}
