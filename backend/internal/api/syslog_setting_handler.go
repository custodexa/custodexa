package api

import (
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"gorm.io/gorm"
)

// syslog 設定驗證 sentinel（backend-i18n-unification A6）：errors.Is 映射至
// apierror 碼；err.Error() 不再直傳客戶端
var (
	errSyslogPortRange       = errors.New("port 須在 1-65535")
	errSyslogProtocolInvalid = errors.New("protocol 須為 udp/tcp/tcp+tls")
	// errSyslogHostRequired Update（enabled 時）與 Test（恆須 host）共用
	errSyslogHostRequired = errors.New("host 不可為空")
)

// SyslogSettingHandler syslog 轉發設定 API（audit-log-compliance 10.3.3，admin 限定）
type SyslogSettingHandler struct {
	db           *gorm.DB
	forwarder    *audit.SyslogForwarder
	auditService *audit.AuditLogService
	// transmission 傳輸政策閘（transmission-security-policy D6）；nil＝閘不生效
	transmission *policy.TransmissionPolicyService
}

// NewSyslogSettingHandler 建立 syslog 設定 handler（auditService 可為 nil，表示停用審計）
func NewSyslogSettingHandler(db *gorm.DB, forwarder *audit.SyslogForwarder, auditService *audit.AuditLogService) *SyslogSettingHandler {
	return &SyslogSettingHandler{db: db, forwarder: forwarder, auditService: auditService}
}

// SetTransmissionPolicy 注入傳輸政策閘（main 組裝時）
func (h *SyslogSettingHandler) SetTransmissionPolicy(tp *policy.TransmissionPolicyService) {
	h.transmission = tp
}

// syslogSettingRequest 設定更新/測試請求
type syslogSettingRequest struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLSCA    string `json:"tls_ca"`
	// RiskAcknowledged 傳輸風險確認聲明（transmission-security-policy D6）：
	// warn 檔存非 TLS 傳輸時必須為 true，聲明入審計
	RiskAcknowledged bool `json:"risk_acknowledged"`
}

// validate 共用驗證（更新與測試同一套）
func (r *syslogSettingRequest) validate() error {
	if r.Port <= 0 || r.Port > 65535 {
		return errSyslogPortRange
	}
	switch r.Protocol {
	case model.SyslogProtocolUDP, model.SyslogProtocolTCP, model.SyslogProtocolTCPTLS:
	default:
		return errSyslogProtocolInvalid
	}
	if r.Enabled && r.Host == "" {
		return errSyslogHostRequired
	}
	return nil
}

// respondSyslogValidateErr 將 validate() 的 sentinel 映射為 apierror 碼（400）
func respondSyslogValidateErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errSyslogPortRange):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSyslogPortRange, nil)
	case errors.Is(err, errSyslogProtocolInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSyslogProtocol, nil)
	case errors.Is(err, errSyslogHostRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSyslogHostRequired, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogGateCheck, err)
	}
}

// Get 取得 syslog 設定與轉發狀態
func (h *SyslogSettingHandler) Get(c *gin.Context) {
	var s model.SyslogSetting
	if err := h.db.First(&s, 1).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogSettingQuery, err)
			return
		}
		s = model.SyslogSetting{ID: 1, Port: 514, Protocol: model.SyslogProtocolUDP}
	}
	// 傳輸偏離標示（transmission-security-policy 3.1）：存量非 TLS 轉發
	// 不中斷但誠實標示；未啟用＝無傳輸即無偏離
	deviation := false
	if h.transmission != nil && s.Enabled {
		deviation = len(h.transmission.SyslogRisks(s.Protocol)) > 0
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"setting":                s,
		"dropped":                h.forwarder.Dropped(),
		"transmission_deviation": deviation,
	}})
}

// Update 更新 syslog 設定（變更入審計）
func (h *SyslogSettingHandler) Update(c *gin.Context) {
	var req syslogSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if err := req.validate(); err != nil {
		respondSyslogValidateErr(c, err)
		return
	}

	username, _ := middleware.GetCurrentUsername(c)
	userID, _ := middleware.GetCurrentUserID(c)

	// 傳輸政策閘（transmission-security-policy D6）：只攔存檔動作，
	// 存量非 TLS 轉發不中斷（審計外送優先於強制，spec 場景鎖定）。
	// 未啟用轉發的存檔不受閘——沒有傳輸就沒有傳輸風險
	if h.transmission != nil && req.Enabled {
		risks := h.transmission.SyslogRisks(req.Protocol)
		if err := h.transmission.CheckSettingSave(policy.TransportChannelSyslog, risks, req.RiskAcknowledged); err != nil {
			var gateErr *policy.TransmissionGateError
			if errors.As(err, &gateErr) {
				respondTransmissionGate(c, gateErr)
				return
			}
			// 防禦分支：CheckSettingSave 目前只回 nil 或 *TransmissionGateError，
			// 理論不可達；未知錯誤一律 RespondInternal（不直傳 err.Error()）
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogGateCheck, err)
			return
		}
		// warn 確認聲明入審計（管理員/時間/設定摘要/風險項）
		if len(risks) > 0 && req.RiskAcknowledged &&
			h.transmission.ChannelLevel(policy.TransportChannelSyslog) == policy.TransportLevelWarn &&
			h.auditService != nil {
			details, _ := json.Marshal(gin.H{
				"event": "setting_ack", "channel": policy.TransportChannelSyslog,
				"host": req.Host, "port": req.Port, "protocol": req.Protocol, "risks": risks,
			})
			h.auditService.Log(&audit.AuditLogEntry{
				UserID: userID, Username: username,
				Action: model.ActionUpdate, Resource: model.ResourceTransmission,
				Status: model.StatusSuccess, Method: c.Request.Method,
				Path: c.Request.URL.Path, ClientIP: sourceip.Of(c),
				StatusCode: http.StatusOK, Details: string(details),
			})
		}
	}

	row := model.SyslogSetting{
		ID: 1, Enabled: req.Enabled, Host: req.Host, Port: req.Port,
		Protocol: req.Protocol, TLSCA: req.TLSCA, UpdatedBy: username,
	}
	if err := h.db.Save(&row).Error; err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogSettingSave, err)
		return
	}
	h.forwarder.Reload()

	if h.auditService != nil {
		// 留痕不含 TLSCA 內容（體積大且無敏感變更語義），僅記是否設定
		details, _ := json.Marshal(gin.H{
			"enabled": req.Enabled, "host": req.Host, "port": req.Port,
			"protocol": req.Protocol, "tls_ca_set": req.TLSCA != "",
		})
		h.auditService.Log(&audit.AuditLogEntry{
			UserID: userID, Username: username,
			Action: model.ActionUpdate, Resource: model.ResourceSyslogSetting,
			Status: model.StatusSuccess, Method: c.Request.Method,
			Path: c.Request.URL.Path, ClientIP: sourceip.Of(c),
			StatusCode: http.StatusOK, Details: string(details),
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// Test 發送測試訊息（用請求中的表單值，未儲存也可測）
func (h *SyslogSettingHandler) Test(c *gin.Context) {
	var req syslogSettingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if req.Host == "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSyslogHostRequired, nil)
		return
	}
	if err := (&syslogSettingRequest{
		Enabled: true, Host: req.Host, Port: req.Port, Protocol: req.Protocol, TLSCA: req.TLSCA,
	}).validate(); err != nil {
		respondSyslogValidateErr(c, err)
		return
	}

	// 傳輸政策閘（同 Update；transmission-security-policy 6.5 收口）：
	// 測試即對外實送，不受 enabled 影響——strict 下不得對非 TLS 端點發送，
	// warn 下須帶風險確認聲明
	if h.transmission != nil {
		risks := h.transmission.SyslogRisks(req.Protocol)
		if err := h.transmission.CheckSettingSave(policy.TransportChannelSyslog, risks, req.RiskAcknowledged); err != nil {
			var gateErr *policy.TransmissionGateError
			if errors.As(err, &gateErr) {
				respondTransmissionGate(c, gateErr)
				return
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogGateCheck, err)
			return
		}
		if len(risks) > 0 && req.RiskAcknowledged &&
			h.transmission.ChannelLevel(policy.TransportChannelSyslog) == policy.TransportLevelWarn &&
			h.auditService != nil {
			username, _ := middleware.GetCurrentUsername(c)
			userID, _ := middleware.GetCurrentUserID(c)
			details, _ := json.Marshal(gin.H{
				"event": "test_ack", "channel": policy.TransportChannelSyslog,
				"host": req.Host, "port": req.Port, "protocol": req.Protocol, "risks": risks,
			})
			h.auditService.Log(&audit.AuditLogEntry{
				UserID: userID, Username: username,
				Action: model.ActionUpdate, Resource: model.ResourceTransmission,
				Status: model.StatusSuccess, Method: c.Request.Method,
				Path: c.Request.URL.Path, ClientIP: sourceip.Of(c),
				StatusCode: http.StatusOK, Details: string(details),
			})
		}
	}

	err := h.forwarder.SendTest(model.SyslogSetting{
		Host: req.Host, Port: req.Port, Protocol: req.Protocol, TLSCA: req.TLSCA,
	})
	if err != nil {
		// 送達失敗回 502＋registered code（asset-syslog-debt-cleanup D1）：狀態碼
		// 表達成敗，與通知通道測試端點同語義；具體原因（連線拒絕/逾時/TLS 驗證
		// 失敗）僅入伺服端 log，對外泛化以免目的地可達性成為可探測訊號。
		// RespondInternal 已記 cause/path/userID，故不另行 log.Printf
		apierror.RespondInternal(c, http.StatusBadGateway, apierror.CodeSyslogTestFailed, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"success": true}})
}

// RegisterRoutes 註冊 syslog 設定路由（admin 限定）
func (h *SyslogSettingHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	settings := r.Group("/syslog-settings")
	settings.Use(middleware.AuthMiddleware(authService))
	settings.Use(middleware.RequireRole("admin"))
	{
		settings.GET("", h.Get)
		settings.PUT("", h.Update)
		settings.POST("/test", h.Test)
	}
}
