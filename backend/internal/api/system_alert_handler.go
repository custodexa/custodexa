package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
)

// SystemAlertServiceInterface 系統告警目錄與明細服務接口（用於測試注入）。
type SystemAlertServiceInterface interface {
	List(withRecent bool) ([]audit.SystemAlertCatalogEntry, error)
	SetSeverity(key, severity string, actor audit.SystemAlertSeverityActor) (audit.SystemAlertSeverityChange, error)
	Detail(alertID uint) (*audit.SystemAlertDetailView, error)
}

// SystemAlertHandler 系統告警目錄（分級權限點）與明細（稽核檢視）API。
// 沒有 DELETE 與啟停路由：系統告警不可刪除或停用，只能調分級。
type SystemAlertHandler struct {
	service SystemAlertServiceInterface
	// canAuditView 判定呼叫者是否具稽核檢視（決定目錄是否附近 30 天筆數）。
	canAuditView func(c *gin.Context) bool
}

// NewSystemAlertHandler 建立 handler。
func NewSystemAlertHandler(service SystemAlertServiceInterface) *SystemAlertHandler {
	return &SystemAlertHandler{service: service, canAuditView: principalHasAuditView}
}

func principalHasAuditView(c *gin.Context) bool {
	// 與告警列表同一個判定：具稽核檢視者才看得到告警筆數。
	return authz.DecideRoute(http.MethodGet, "/api/v1/command-alerts", middleware.PrincipalFrom(c)).Allowed
}

type systemAlertCatalogItem struct {
	Key               string `json:"key"`
	Group             string `json:"group"`
	DefaultSeverity   string `json:"default_severity"`
	EffectiveSeverity string `json:"effective_severity"`
	Adjusted          bool   `json:"adjusted"`
	Recent30d         *int64 `json:"recent_30d,omitempty"`
}

// List GET /system-alert-types
func (h *SystemAlertHandler) List(c *gin.Context) {
	entries, err := h.service.List(h.canAuditView(c))
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCommandAlertQuery, err)
		return
	}
	items := make([]systemAlertCatalogItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, systemAlertCatalogItem{
			Key: string(e.Key), Group: string(e.Group), DefaultSeverity: e.DefaultSeverity,
			EffectiveSeverity: e.EffectiveSeverity, Adjusted: e.Adjusted, Recent30d: e.Recent30d,
		})
	}
	c.JSON(http.StatusOK, gin.H{"types": items})
}

// UpdateSeverity PUT /system-alert-types/:key
//
// 嚴格解碼：只接受 severity 一個欄位；其他欄位（含 enabled 這類停用意圖）一律
// VALIDATION_SYSTEM_ALERT_LOCKED。
func (h *SystemAlertHandler) UpdateSeverity(c *gin.Context) {
	key := c.Param("key")
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 4096))
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	for name := range fields {
		if name != "severity" {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeSystemAlertLocked, nil)
			return
		}
	}
	var severity string
	if raw, ok := fields["severity"]; !ok || json.NewDecoder(bytes.NewReader(raw)).Decode(&severity) != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSystemAlertSeverity, nil)
		return
	}
	actorID, _ := middleware.GetCurrentUserID(c)
	actorName, _ := middleware.GetCurrentUsername(c)
	change, err := h.service.SetSeverity(key, severity, audit.SystemAlertSeverityActor{
		ID: actorID, Name: actorName, IP: sourceip.Of(c),
	})
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"key": key, "severity_before": change.Before, "severity_after": change.After})
	case errors.Is(err, audit.ErrSystemAlertTypeUnknown):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSystemAlertTypeNotFound, nil)
	case errors.Is(err, audit.ErrSystemAlertSeverityInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSystemAlertSeverity, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSystemAlertRaise, err)
	}
}

type systemAlertDeliveryItem struct {
	DestType      string     `json:"dest_type"`
	DestName      string     `json:"dest_name"`
	State         string     `json:"state"`
	Attempts      int        `json:"attempts"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
}

// SystemDetail GET /command-alerts/:id/system-detail
func (h *SystemAlertHandler) SystemDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCommandAlertID, nil)
		return
	}
	v, err := h.service.Detail(uint(id))
	if err != nil {
		if errors.Is(err, audit.ErrAlertNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeCommandAlertNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalCommandAlertQuery, err)
		return
	}
	deliveries := make([]systemAlertDeliveryItem, 0, len(v.Deliveries))
	for _, d := range v.Deliveries {
		deliveries = append(deliveries, systemAlertDeliveryItem{
			DestType: d.DestType, DestName: d.DestName, State: d.State,
			Attempts: d.Attempts, DeliveredAt: d.DeliveredAt, NextAttemptAt: d.NextAttemptAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"alert_id": v.AlertID, "alert_type": v.AlertType, "group": string(v.Group),
		"severity": v.Severity, "triggered_at": v.TriggeredAt, "actor": v.ActorName,
		"target_kind": v.TargetKind, "target_id": v.TargetID, "params": v.Params,
		"correlation_id": v.CorrelationID, "audit_log_id": v.AuditLogID, "client_ip": v.ClientIP,
		"deliveries": deliveries,
	})
}

// RegisterRoutes 註冊目錄與明細路由。權限只由路由登錄表裁決（EnforceRegistry）。
func (h *SystemAlertHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	types := r.Group("/system-alert-types")
	types.Use(middleware.AuthMiddleware(authService), middleware.EnforceRegistry())
	types.GET("", h.List)
	types.PUT("/:key", h.UpdateSeverity)

	r.GET("/command-alerts/:id/system-detail", middleware.AuthMiddleware(authService), middleware.EnforceRegistry(), h.SystemDetail)
}
