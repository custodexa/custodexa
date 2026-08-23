package api

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// ExportSigningHandler 匯出簽章公鑰端點
type ExportSigningHandler struct {
	signing *keyvault.ExportSigningService
}

// NewExportSigningHandler 建立公鑰 handler
func NewExportSigningHandler(signing *keyvault.ExportSigningService) *ExportSigningHandler {
	return &ExportSigningHandler{signing: signing}
}

// PublicKey 下載驗簽公鑰（Ed25519 base64）
func (h *ExportSigningHandler) PublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"algorithm":  "Ed25519",
		"public_key": h.signing.PublicKeyBase64(),
	}})
}

// RegisterRoutes 註冊公鑰路由（同匯出：audit:view，無條件強制）
func (h *ExportSigningHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/audit-export")
	g.Use(middleware.AuthMiddleware(authService))
	g.GET("/public-key", middleware.RequirePermission(middleware.PermAuditView), h.PublicKey)
}
