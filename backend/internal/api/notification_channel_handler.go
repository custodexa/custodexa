package api

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
)

// NotificationChannelServiceInterface 通知通道服務接口（用於測試注入）
type NotificationChannelServiceInterface interface {
	List() ([]model.NotificationChannel, error)
	GetByID(id uint) (*model.NotificationChannel, error)
	// GetForDelivery 投遞用（url/secret 解密明文）：僅測試發送使用，不得入回應
	GetForDelivery(id uint) (*model.NotificationChannel, error)
	Create(req *audit.NotificationChannelRequest) (*model.NotificationChannel, error)
	Update(id uint, req *audit.NotificationChannelRequest) (*model.NotificationChannel, error)
	Delete(id uint) error
}

// NotificationChannelHandler 通知通道 API handler（alert-notifications D4，admin only）
type NotificationChannelHandler struct {
	channelService NotificationChannelServiceInterface
	// testSender 可注入：handler 測試不該真的發 HTTP，預設為 service.SendTestNotification
	testSender func(ch *model.NotificationChannel) (int, error)
}

// NewNotificationChannelHandler 創建通知通道 handler
func NewNotificationChannelHandler(channelService NotificationChannelServiceInterface) *NotificationChannelHandler {
	return &NotificationChannelHandler{
		channelService: channelService,
		testSender:     audit.SendTestNotification,
	}
}

// respondChannelError 將 service 錯誤映射為 HTTP 狀態：
// 輸入問題（URL/type/language 非法）回 400 並附機器碼，找不到回 404，
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
		// M7 已埋的語系 sentinel（design D5）：空值／白名單外皆走此碼
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelLanguage, nil)
	case errors.Is(err, audit.ErrChannelNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeChannelNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalChannelOp, err)
	}
}

// fillChannelActor 從 JWT context 填操作者（傳輸確認聲明審計用）
func fillChannelActor(c *gin.Context, req *audit.NotificationChannelRequest) {
	req.ActorID, _ = middleware.GetCurrentUserID(c)
	req.ActorName, _ = middleware.GetCurrentUsername(c)
	req.ActorIP = sourceip.Of(c)
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

	if err := h.channelService.Delete(uint(id)); err != nil {
		respondChannelError(c, err)
		return
	}
	// 成功訊息不落 payload（design D9）：前端以自有 $t 文案顯示
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Test 對指定通道同步發送測試 payload（design D4）：
// admin 即時回饋——投遞結果直接回傳而非丟佇列。
// 送達對端：HTTP 200 + body success/status_code（對端 2xx 才算成功）；
// 連線層失敗（DNS/逾時/拒連）：HTTP 502 + 統一錯誤封套（error-message-consistency）
func (h *NotificationChannelHandler) Test(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidChannelID, nil)
		return
	}

	// 投遞需要明文 url/secret（key-management-envelope G8）；此物件不得入回應
	channel, err := h.channelService.GetForDelivery(uint(id))
	if err != nil {
		respondChannelError(c, err)
		return
	}

	status, err := h.testSender(channel)
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
			channel.ID, channel.Type, audit.SanitizeDeliveryError(err, channel.URL))
		apierror.RespondInternal(c, http.StatusBadGateway, code, cause)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success":     status >= 200 && status < 300,
		"status_code": status,
	})
}

// RegisterRoutes 註冊通知通道路由：
// 通道含 secret 且控制告警外發目的地，整組 admin only（與 alert-rules 同模式，design D4）
func (h *NotificationChannelHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	channels := r.Group("/notification-channels")
	channels.Use(middleware.AuthMiddleware(authService))
	channels.Use(middleware.RequireRole("admin"))
	{
		channels.GET("", h.List)
		channels.POST("", h.Create)
		channels.PUT("/:id", h.Update)
		channels.DELETE("/:id", h.Delete)
		channels.POST("/:id/test", h.Test)
	}
}
