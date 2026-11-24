package api

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/gin-gonic/gin"
)

// NotificationChannelServiceInterface 通知通道服務接口（用於測試注入）
type NotificationChannelServiceInterface interface {
	List() ([]model.NotificationChannel, error)
	GetByID(id uint) (*model.NotificationChannel, error)
	// GetForDelivery 投遞用（url/secret 解密明文）：僅測試發送使用，不得入回應
	GetForDelivery(id uint) (*model.NotificationChannel, error)
	Create(req *audit.NotificationChannelRequest) (*model.NotificationChannel, error)
	Update(id uint, req *audit.NotificationChannelRequest) (*model.NotificationChannel, error)
	Delete(id uint, actor audit.ChannelActor) error
	// ListDeliveries 某個通道的投遞紀錄（唯讀；不含網址、秘密與通知參數的值）
	ListDeliveries(channelID uint, q audit.ChannelDeliveryQuery) (*audit.ChannelDeliveryPage, error)
	// TestToSelf 「傳給我自己」：以請求者自己的電子郵件與通道已存設定完成一次對應與私訊（同步、不重試、不排入）
	TestToSelf(ch *model.NotificationChannel, requesterID uint) (audit.SelfTestResult, error)
}

// NotificationChannelHandler 通知通道 API handler（alert-notifications）。
// 權限依通知通道管理權限點（notification_channel:manage），由路由登錄表裁決。
type NotificationChannelHandler struct {
	channelService NotificationChannelServiceInterface
	// testSender 可注入：handler 測試不該真的發 HTTP，預設為 audit.SendTestNotificationShape
	testSender func(ch *model.NotificationChannel, shape string) (int, error)
}

// NewNotificationChannelHandler 創建通知通道 handler
func NewNotificationChannelHandler(channelService NotificationChannelServiceInterface) *NotificationChannelHandler {
	return &NotificationChannelHandler{
		channelService: channelService,
		testSender:     audit.SendTestNotificationShape,
	}
}

// respondChannelError 將 service 錯誤映射為 HTTP 狀態：
// 輸入問題（URL/type/language/min_severity 非法）回 400 並附機器碼，找不到回 404，
// 傳輸閘拒絕回 400＋風險項（前端據此顯示確認聲明或政策原因），其餘 500
func respondChannelError(c *gin.Context, err error) {
	var gateErr *policy.TransmissionGateError
	switch {
	case errors.As(err, &gateErr):
		respondTransmissionGate(c, gateErr)
	case errors.Is(err, audit.ErrInvalidChannelURL):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelURL, nil)
	case errors.Is(err, audit.ErrInvalidChannelTyp):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelType, nil)
	case errors.Is(err, audit.ErrInvalidChannelLanguage):
		// 既有的語系 sentinel：空值／白名單外皆走此碼
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelLanguage, nil)
	case errors.Is(err, audit.ErrInvalidChannelMinSeverity):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelMinSeverity, nil)
	case errors.Is(err, audit.ErrInvalidChannelTarget):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelTarget, nil)
	case errors.Is(err, audit.ErrInvalidChannelSecret):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelSecret, nil)
	case errors.Is(err, audit.ErrChannelSecretRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChannelSecretRequired, nil)
	case errors.Is(err, audit.ErrChannelTypeChangeNeedsURL):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChannelTypeChangeNeedsURL, nil)
	case errors.Is(err, audit.ErrChannelURLChangeNeedsSecret):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChannelURLChangeNeedsSecret, nil)
	case errors.Is(err, audit.ErrChannelNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeChannelNotFound, nil)
	case errors.Is(err, audit.ErrDirectMessageConflict):
		name := ""
		var conflict *audit.DirectMessageConflictError
		if errors.As(err, &conflict) {
			name = conflict.Name
		}
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChannelDMConflict, map[string]any{"name": name})
	case errors.Is(err, audit.ErrDirectMessageURLNotAllowed), errors.Is(err, audit.ErrSelfTestURLNotAllowed):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChannelDMURLNotAllowed, nil)
	case errors.Is(err, audit.ErrDirectMessageUnsupportedType), errors.Is(err, audit.ErrSelfTestUnsupportedType):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChannelDMTypeUnsupported, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChannelOp, err)
	}
}

// fillChannelActor 從 JWT context 填操作者（傳輸確認聲明審計用）
func fillChannelActor(c *gin.Context, req *audit.NotificationChannelRequest) {
	req.ActorID, _ = middleware.GetCurrentUserID(c)
	req.ActorName, _ = middleware.GetCurrentUsername(c)
	req.ActorIP = sourceip.Of(c)
	req.APIToken = middleware.APITokenRefOf(c)
}

// List 列出所有通知通道
func (h *NotificationChannelHandler) List(c *gin.Context) {
	channels, err := h.channelService.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChannelQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  channels,
		"total": len(channels),
	})
}

// Create 建立通知通道
func (h *NotificationChannelHandler) Create(c *gin.Context) {
	var req audit.NotificationChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	fillChannelActor(c, &req)

	channel, err := h.channelService.Create(&req)
	if err != nil {
		respondChannelError(c, err)
		return
	}
	c.JSON(http.StatusCreated, channel)
}

// Update 更新通知通道
func (h *NotificationChannelHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelID, nil)
		return
	}

	var req audit.NotificationChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	fillChannelActor(c, &req)

	channel, err := h.channelService.Update(uint(id), &req)
	if err != nil {
		respondChannelError(c, err)
		return
	}
	c.JSON(http.StatusOK, channel)
}

// Delete 刪除通知通道
func (h *NotificationChannelHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelID, nil)
		return
	}

	actorID, _ := middleware.GetCurrentUserID(c)
	actorName, _ := middleware.GetCurrentUsername(c)
	actor := audit.ChannelActor{ID: actorID, Name: actorName, IP: sourceip.Of(c), APIToken: middleware.APITokenRefOf(c)}
	if err := h.channelService.Delete(uint(id), actor); err != nil {
		respondChannelError(c, err)
		return
	}
	// 成功訊息不落 payload：前端以自有 $t 文案顯示
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// notificationTestRequest 測試發送的請求本文：shape（webhook 的形狀，可省略）與 to_self（傳給我自己）。
// 目的地一律是路徑上通道識別碼的已存設定；本文即使帶了網址、秘密、目標、型別、電子郵件或使用者識別碼也不會被讀取。
type notificationTestRequest struct {
	Shape  string `json:"shape"`
	ToSelf bool   `json:"to_self"`
}

// Test 對指定通道同步發送測試 payload：
// admin 即時回饋——投遞結果直接回傳而非丟佇列。
// 送達對端：HTTP 200 + body success/status_code（對端 2xx 才算成功）；
// 連線層失敗（DNS/逾時/拒連）：HTTP 502 + 統一錯誤封套
func (h *NotificationChannelHandler) Test(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelID, nil)
		return
	}
	// 本文可省略（升級前的呼叫方式）；有帶就必須是合法 JSON 且 shape 在三個值之內
	var req notificationTestRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
	}
	if !audit.ValidTestShape(req.Shape) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	// 投遞需要明文 url/secret；此物件不得入回應
	channel, err := h.channelService.GetForDelivery(uint(id))
	if err != nil {
		respondChannelError(c, err)
		return
	}
	if req.ToSelf {
		h.testToSelf(c, channel)
		return
	}

	status, err := h.testSender(channel, req.Shape)
	// 平台已回應但表明失敗（例如 token 無效、頻道不存在）：請求有送到，回 200 並帶淨化後的平台錯誤碼，
	// 讓操作者看到平台的原因，而不是被引導去查網路
	var platformErr *audit.ChannelPlatformError
	if errors.As(err, &platformErr) {
		c.JSON(http.StatusOK, gin.H{
			"success":        false,
			"status_code":    platformErr.Status,
			"platform_error": platformErr.Code,
		})
		return
	}
	// 轉址規則擋下（次數過多、目的地不符傳輸政策）：請求有送出，回 200 並帶與投遞紀錄相同的原因代碼
	if reason := audit.ChannelTestRedirectReason(err); reason != "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "reason_code": reason})
		return
	}
	if err != nil {
		// 連線層失敗（DNS/逾時/拒連）：回 502 與分類摘要。err 原文含完整
		// URL（webhook secret 在路徑），回應與日誌都只落脫敏版——sanitized cause
		// 同時交給 RespondInternal（其內部亦會 log），故不另行 log.Printf 原文
		code := apierror.CodeChannelTestConnFailed
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			code = apierror.CodeChannelTestTimeout
		}
		cause := fmt.Errorf("channel id=%d type=%s: %s",
			channel.ID, channel.Type, audit.SanitizeChannelError(err, channel.URL, channel.Secret))
		apierror.RespondInternal(c, http.StatusBadGateway, code, cause)
		return
	}
	body := gin.H{
		"success":     status >= 200 && status < 300,
		"status_code": status,
	}
	if reason := audit.ChannelTestStatusReason(status); reason != "" {
		body["reason_code"] = reason
	}
	c.JSON(http.StatusOK, body)
}

// testToSelf 「傳給我自己」：結果碼為 delivered、no_email、email_ambiguous、recipient_not_found、platform_error；
// 成功時帶對到的平台顯示名稱（請求者本人的）。回應不含電子郵件與平台使用者識別碼。連線層失敗回 502。
func (h *NotificationChannelHandler) testToSelf(c *gin.Context, channel *model.NotificationChannel) {
	userID, _ := middleware.GetCurrentUserID(c)
	res, err := h.channelService.TestToSelf(channel, userID)
	if err != nil {
		if errors.Is(err, audit.ErrSelfTestUnsupportedType) || errors.Is(err, audit.ErrSelfTestURLNotAllowed) {
			respondChannelError(c, err)
			return
		}
		code := apierror.CodeChannelTestConnFailed
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			code = apierror.CodeChannelTestTimeout
		}
		cause := fmt.Errorf("channel id=%d type=%s to_self: %s",
			channel.ID, channel.Type, audit.SanitizeChannelError(err, channel.URL, channel.Secret))
		apierror.RespondInternal(c, http.StatusBadGateway, code, cause)
		return
	}
	body := gin.H{"success": res.Outcome == audit.SelfTestDelivered, "result": res.Outcome}
	if res.Status != 0 {
		body["status_code"] = res.Status
	}
	if res.PlatformError != "" {
		body["platform_error"] = res.PlatformError
	}
	if res.DisplayName != "" {
		body["display_name"] = res.DisplayName
	}
	c.JSON(http.StatusOK, body)
}

// Deliveries 列出某個通道的投遞紀錄（唯讀、分頁、依建立時間倒序、可依狀態篩選），另帶該通道等待中與重送中的筆數。
// 回應不含網址、秘密與通知參數的值；帶快照且早於目的地最後變更時間的列以 snapshot_before_change 標示。
func (h *NotificationChannelHandler) Deliveries(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelID, nil)
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	// state：可省略；多個狀態以逗號分隔（例如 pending,retrying），每個都要在值域內
	var states []string
	if raw := strings.TrimSpace(c.Query("state")); raw != "" {
		for _, v := range strings.Split(raw, ",") {
			states = append(states, strings.TrimSpace(v))
		}
	}
	audience := strings.TrimSpace(c.Query("audience"))
	result, err := h.channelService.ListDeliveries(uint(id), audit.ChannelDeliveryQuery{Page: page, PageSize: pageSize, States: states, Audience: audience})
	if err != nil {
		if errors.Is(err, audit.ErrChannelNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeChannelNotFound, nil)
			return
		}
		if errors.Is(err, audit.ErrInvalidDeliveryState) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDeliveryState, nil)
			return
		}
		if errors.Is(err, audit.ErrInvalidDeliveryAudience) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDeliveryAudience, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChannelQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result.Rows, "total": result.Total, "pending_counts": result.PendingCounts})
}

// RegisterRoutes 註冊通知通道路由：
// 通道含 secret 且控制告警外發目的地，整組端點都要求通知通道管理權限點
// （notification_channel:manage），由路由登錄表裁決，不寫死角色名稱
func (h *NotificationChannelHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	channels := r.Group("/notification-channels")
	channels.Use(middleware.AuthMiddleware(authService))
	channels.Use(middleware.EnforceRegistry())
	{
		channels.GET("", h.List)
		channels.POST("", h.Create)
		channels.PUT("/:id", h.Update)
		channels.DELETE("/:id", h.Delete)
		channels.POST("/:id/test", h.Test)
		channels.GET("/:id/deliveries", h.Deliveries)
	}
}
