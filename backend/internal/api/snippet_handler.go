package api

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
)

// SnippetServiceInterface 片段服務接口（測試注入）
type SnippetServiceInterface interface {
	List(userID uint) ([]model.Snippet, error)
	Create(userID uint, req *session.SnippetRequest) (*model.Snippet, error)
	Update(userID, id uint, req *session.SnippetRequest) (*model.Snippet, error)
	Delete(userID, id uint) error
}

// SnippetHandler 命令片段 API（terminal-snippets，user-scoped）
type SnippetHandler struct {
	snippetService SnippetServiceInterface
}

// NewSnippetHandler 創建片段 handler
func NewSnippetHandler(snippetService SnippetServiceInterface) *SnippetHandler {
	return &SnippetHandler{snippetService: snippetService}
}

// respondSnippetError 映射 service 錯誤：輸入問題 400、不存在 404，其餘走呼叫端
// 指定的 internalCode（各端點 action 不同、碼各自獨立）
func respondSnippetError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	switch {
	case errors.Is(err, session.ErrSnippetNameEmpty):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSnippetNameEmpty, nil)
	case errors.Is(err, session.ErrSnippetTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSnippetTooLong, nil)
	case errors.Is(err, session.ErrSnippetNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSnippetNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// List 列出目前使用者全部片段
func (h *SnippetHandler) List(c *gin.Context) {
	userID, _ := middleware.GetCurrentUserID(c)
	snippets, err := h.snippetService.List(userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSnippetQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": snippets, "total": len(snippets)})
}

// Create 建立片段
func (h *SnippetHandler) Create(c *gin.Context) {
	userID, _ := middleware.GetCurrentUserID(c)
	var req session.SnippetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	snippet, err := h.snippetService.Create(userID, &req)
	if err != nil {
		respondSnippetError(c, apierror.CodeInternalSnippetCreate, err)
		return
	}
	c.JSON(http.StatusCreated, snippet)
}

// Update 更新片段
func (h *SnippetHandler) Update(c *gin.Context) {
	userID, _ := middleware.GetCurrentUserID(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "snippet"})
		return
	}
	var req session.SnippetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	snippet, err := h.snippetService.Update(userID, uint(id), &req)
	if err != nil {
		respondSnippetError(c, apierror.CodeInternalSnippetUpdate, err)
		return
	}
	c.JSON(http.StatusOK, snippet)
}

// Delete 刪除片段
func (h *SnippetHandler) Delete(c *gin.Context) {
	userID, _ := middleware.GetCurrentUserID(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "snippet"})
		return
	}
	if err := h.snippetService.Delete(userID, uint(id)); err != nil {
		respondSnippetError(c, apierror.CodeInternalSnippetDelete, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

// RegisterRoutes 註冊片段路由（登入即可，user-scoped 無需角色）
func (h *SnippetHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	snippets := r.Group("/snippets")
	snippets.Use(middleware.AuthMiddleware(authService))
	{
		snippets.GET("", h.List)
		snippets.POST("", h.Create)
		snippets.PUT("/:id", h.Update)
		snippets.DELETE("/:id", h.Delete)
	}
}
