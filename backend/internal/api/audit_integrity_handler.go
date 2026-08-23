package api

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// AuditIntegrityHandler audit_logs 完整性驗證 API
//（admin 與 auditor 皆可讀）
type AuditIntegrityHandler struct {
	db        *gorm.DB
	integrity *audit.AuditIntegrityService
}

// NewAuditIntegrityHandler 建立完整性驗證 handler
func NewAuditIntegrityHandler(db *gorm.DB, integrity *audit.AuditIntegrityService) *AuditIntegrityHandler {
	return &AuditIntegrityHandler{db: db, integrity: integrity}
}

// Verify 掃描時間範圍重算 HMAC 比對
func (h *AuditIntegrityHandler) Verify(c *gin.Context) {
	now := time.Now()
	from := now.AddDate(0, 0, -7)
	to := now.AddDate(0, 0, 1)
	if s := c.Query("from"); s != "" {
		t, err := time.ParseInLocation("2006-01-02", s, time.Local)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAuditIntegrityFromFormat, nil)
			return
		}
		from = t
	}
	if s := c.Query("to"); s != "" {
		t, err := time.ParseInLocation("2006-01-02", s, time.Local)
		if err != nil {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAuditIntegrityToFormat, nil)
			return
		}
		to = t.AddDate(0, 0, 1) // 含當日
	}
	if !to.After(from) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAuditIntegrityRangeInvalid, nil)
		return
	}

	report, err := h.integrity.Verify(h.db, from, to)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuditIntegrityVerify, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": report})
}

// RegisterRoutes 註冊完整性驗證路由（admin 或 auditor）。
//
// **自 audit-checkpoint-chain 起開放 auditor**：原本 admin 限定，使得
// auditor 只能證「序列少沒少」（檢查點），內容真偽仍須請 admin 代驗——
// 「被監督者代為出具監督證明」的角色錯配只解一半。本端點唯讀且不含設定面，
// 開放不擴大寫入權
func (h *AuditIntegrityHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	integrity := r.Group("/audit-integrity")
	integrity.Use(middleware.AuthMiddleware(authService))
	integrity.Use(middleware.RequireAnyRole(model.RoleAdmin, model.RoleAuditor))
	{
		integrity.GET("/verify", h.Verify)
	}
}
