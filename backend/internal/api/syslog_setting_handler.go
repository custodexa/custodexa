package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"gorm.io/gorm"
)

// syslog 設定驗證 sentinel：errors.Is 映射至
// apierror 碼；err.Error() 不再直傳客戶端
var (
	errSyslogPortRange       = errors.New("port 須在 1-65535")
	errSyslogProtocolInvalid = errors.New("protocol 須為 udp/tcp/tcp+tls")
	// errSyslogHostRequired Update（enabled 時）與 Test（恆須 host）共用
	errSyslogHostRequired = errors.New("host 不可為空")
)

// syslogForwarderOps 轉發器在本 handler 用到的操作（測試以替身計數 Reload）。
type syslogForwarderOps interface {
	Reload()
	Dropped() uint64
	SendTest(s model.SyslogSetting) error
}

// SyslogSettingHandler syslog 轉發設定 API（admin 限定）
type SyslogSettingHandler struct {
	db        *gorm.DB
	forwarder syslogForwarderOps
	// auditService 保留給 Test 路徑以外的既有呼叫端；設定存檔的兩列審計改走 txSink
	auditService *audit.AuditLogService
	// transmission 傳輸政策閘；nil＝閘不生效
	transmission *policy.TransmissionPolicyService
	// txSink／alerts 設定存檔的交易內審計與系統告警落地面（組裝根注入；缺任一即存檔失敗）
	txSink port.TxSink
	alerts port.SystemAlertSink
}

// NewSyslogSettingHandler 建立 syslog 設定 handler（auditService 可為 nil）
func NewSyslogSettingHandler(db *gorm.DB, forwarder *audit.SyslogForwarder, auditService *audit.AuditLogService) *SyslogSettingHandler {
	return &SyslogSettingHandler{db: db, forwarder: forwarder, auditService: auditService}
}

// SetEvidenceSinks 注入交易內審計與系統告警落地面（組裝根在兩者建構與自檢之後呼叫）。
func (h *SyslogSettingHandler) SetEvidenceSinks(txSink port.TxSink, alerts port.SystemAlertSink) {
	h.txSink, h.alerts = txSink, alerts
}

// EvidenceSinksReady 組裝根啟動自檢：兩個落地面都已注入。
func (h *SyslogSettingHandler) EvidenceSinksReady() error {
	if h.txSink == nil {
		return fmt.Errorf("syslog 設定: %w", port.ErrTxSinkMissing)
	}
	if h.alerts == nil {
		return fmt.Errorf("syslog 設定: %w", port.ErrSystemAlertSinkMissing)
	}
	return nil
}

// syslogSettingLockKey syslog 設定讀改寫序列化用的交易級鎖鍵（pg advisory lock）。
// 用諮詢鎖而非列鎖：初次設定時設定列不存在，列鎖鎖不到
const syslogSettingLockKey int64 = 0x7379_736c_6f67 // "syslog"

// syslogSettingHooks 測試同步點（生產為 nil）：取鎖之後、讀舊列之前
var syslogSettingHooks struct {
	afterLock func(host string)
}

// lockSyslogSettingTx 取 syslog 設定的交易級鎖（SQLite 單一寫入者本身已序列化，不另取）。
func lockSyslogSettingTx(tx *gorm.DB) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", syslogSettingLockKey).Error; err != nil {
		return fmt.Errorf("取得 syslog 設定寫入鎖失敗: %w", err)
	}
	return nil
}

// syslogDestinationChange 依變更前後判定告警的 change 參數（不告警回空字串）：
// 啟用改停用＝disabled；變更後為啟用且 host、port、protocol 任一與變更前不同（含由停用
// 改為啟用到不同目的地）＝destination_changed。只改 TLS CA 不告警。
func syslogDestinationChange(before, after model.SyslogSetting) string {
	switch {
	case before.Enabled && !after.Enabled:
		return "disabled"
	case after.Enabled && (before.Host != after.Host || before.Port != after.Port || before.Protocol != after.Protocol):
		return "destination_changed"
	}
	return ""
}

// errSyslogAlertRaise syslog 設定變更的系統告警寫入失敗（整筆已回滾）
var errSyslogAlertRaise = errors.New("syslog 設定變更告警寫入失敗")

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
	// RiskAcknowledged 傳輸風險確認聲明：
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
	// 傳輸偏離標示：存量非 TLS 轉發
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

	// 傳輸政策閘：只攔存檔動作，
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
	}
	var ackRisks []policy.RiskItem
	if h.transmission != nil && req.Enabled {
		risks := h.transmission.SyslogRisks(req.Protocol)
		if len(risks) > 0 && req.RiskAcknowledged &&
			h.transmission.ChannelLevel(policy.TransportChannelSyslog) == policy.TransportLevelWarn {
			ackRisks = risks
		}
	}
	if err := h.EvidenceSinksReady(); err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogSettingSave, err)
		return
	}

	actor := gatewayapi.Actor{UserID: userID, Username: username}
	meta := gatewayapi.RequestMeta{Method: c.Request.Method, Path: c.Request.URL.Path,
		ClientIP: sourceip.Of(c), StatusCode: http.StatusOK}
	row := model.SyslogSetting{
		ID: 1, Enabled: req.Enabled, Host: req.Host, Port: req.Port,
		Protocol: req.Protocol, TLSCA: req.TLSCA, UpdatedBy: username,
	}
	// 單一交易：先取鎖再讀舊列，寫新列、風險確認與設定更新兩列審計、目的地變更告警；
	// 分類與審計的 before 只用鎖內讀到的舊列。提交成功後才重載轉發器
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := lockSyslogSettingTx(tx); err != nil {
			return err
		}
		if hook := syslogSettingHooks.afterLock; hook != nil {
			hook(req.Host)
		}
		before := model.SyslogSetting{ID: 1, Port: 514, Protocol: model.SyslogProtocolUDP}
		if err := tx.First(&before, 1).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("讀取 syslog 設定失敗: %w", err)
		}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		change := syslogDestinationChange(before, row)
		correlationID := ""
		if change != "" {
			cid, err := newEvidenceCorrelationID()
			if err != nil {
				return err
			}
			correlationID = cid
		}
		// warn 確認聲明入審計（管理員/時間/設定摘要/風險項）
		if ackRisks != nil {
			ack := gin.H{
				"event": "setting_ack", "channel": policy.TransportChannelSyslog,
				"host": req.Host, "port": req.Port, "protocol": req.Protocol, "risks": ackRisks,
			}
			if correlationID != "" {
				ack["correlation_id"] = correlationID
			}
			details, _ := json.Marshal(ack)
			if err := port.WriteInTx(h.txSink, tx, port.AuditEvent{
				Actor: actor, Action: string(model.ActionUpdate), Resource: string(model.ResourceTransmission),
				Status: string(model.StatusSuccess), Request: meta, Details: string(details),
			}); err != nil {
				return fmt.Errorf("寫入 syslog 傳輸風險確認審計失敗: %w", err)
			}
		}
		// 留痕不含 TLSCA 內容（體積大且無敏感變更語義），僅記是否設定
		upd := gin.H{
			"enabled": req.Enabled, "host": req.Host, "port": req.Port,
			"protocol": req.Protocol, "tls_ca_set": req.TLSCA != "",
			"before": gin.H{
				"enabled": before.Enabled, "host": before.Host, "port": before.Port,
				"protocol": before.Protocol, "tls_ca_set": before.TLSCA != "",
			},
		}
		if correlationID != "" {
			upd["correlation_id"] = correlationID
		}
		details, _ := json.Marshal(upd)
		if err := port.WriteInTx(h.txSink, tx, port.AuditEvent{
			Actor: actor, Action: string(model.ActionUpdate), Resource: string(model.ResourceSyslogSetting),
			Status: string(model.StatusSuccess), Request: meta, Details: string(details),
		}); err != nil {
			return fmt.Errorf("寫入 syslog 設定更新審計失敗: %w", err)
		}
		if change == "" {
			return nil
		}
		if _, err := port.RaiseInTx(h.alerts, tx, port.SystemAlertEvent{
			Type:          port.SystemAlertOffsiteOrSyslogChanged,
			Actor:         port.SystemAlertActor{UserID: userID, Username: username},
			ClientIP:      meta.ClientIP,
			Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetSystemSetting, ID: "syslog"},
			CorrelationID: correlationID,
			Params:        map[string]string{"subject": "syslog", "change": change},
		}); err != nil {
			return fmt.Errorf("%w: %w", errSyslogAlertRaise, err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errSyslogAlertRaise) {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSystemAlertRaise, err)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSyslogSettingSave, err)
		return
	}
	h.forwarder.Reload()
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

	// 傳輸政策閘（同 Update）：
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
		// 送達失敗回 502＋registered code：狀態碼
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
	settings.Use(middleware.EnforceRegistry())
	{
		settings.GET("", h.Get)
		settings.PUT("", h.Update)
		settings.POST("/test", h.Test)
	}
}
