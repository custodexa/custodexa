package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/sourceip"
)

// ClipboardEventLister 會話剪貼簿記錄查詢能力（消費者側窄介面）。
// handler 不再自持 `*gorm.DB`：剪貼簿留存屬 session 域，由 `service.SessionService` 實作。
type ClipboardEventLister interface {
	ListClipboardEvents(sessionID uint) ([]model.ClipboardEvent, error)
}

// ClipboardContentReader 單筆剪貼簿內容調閱能力（消費者側窄介面，
// 由 session.ClipboardContentService 實作）。
type ClipboardContentReader interface {
	ReadContent(ctx context.Context, sessionID, eventID uint,
		op session.ClipboardReadOperator) (*session.ClipboardContentView, error)
}

// ClipboardEventHandler 剪貼簿留存查詢 API（clipboard-audit）
type ClipboardEventHandler struct {
	events  ClipboardEventLister
	content ClipboardContentReader
}

// NewClipboardEventHandler 建立 handler
func NewClipboardEventHandler(events ClipboardEventLister, content ClipboardContentReader) *ClipboardEventHandler {
	return &ClipboardEventHandler{events: events, content: content}
}

// clipboardEventFact List 的事實投影。
//
// **顯式 DTO 而非直接序列化 model**：列表回應的欄位集是 spec 契約
// （識別、時間、方向、內容長度、內容狀態，SHALL NOT 含內容），model 日後
// 增欄不得順帶進入本回應。content_status 讓呈現端分得出「內容可調閱」與
// 「內容留存失敗（缺口）」，不以密文為空或長度為零推斷。
type clipboardEventFact struct {
	ID            uint      `json:"id"`
	SessionID     uint      `json:"session_id"`
	Direction     string    `json:"direction"`
	ContentLength int       `json:"content_length"`
	ContentStatus string    `json:"content_status"`
	CreatedAt     time.Time `json:"created_at"`
}

func clipboardFactOf(ev model.ClipboardEvent) clipboardEventFact {
	return clipboardEventFact{
		ID:            ev.ID,
		SessionID:     ev.SessionID,
		Direction:     ev.Direction,
		ContentLength: ev.ContentLength,
		ContentStatus: ev.ContentStatus,
		CreatedAt:     ev.CreatedAt,
	}
}

// List 按時間序回傳會話剪貼簿記錄的事實投影（不含內容）
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
	// 調閱審計的筆數面（頁面級粒度）：
	// 操作者與會話 id 由審計中介層的敏感資源形態涵蓋（resource=clipboard_event、
	// resource_id=連線 id、details.session_id——見 middleware/audit_log.go 與其
	// 剪貼簿守衛測試），但「這次取走幾筆證物」只有 handler 知道，故經
	// audit_details 併入同一筆審計列。留痕放伺服器端不放前端：前端記錄可被
	// 直呼 API 繞過。審計寫入失敗不影響本回應——中介層在回應寫出後才記錄，
	// 失敗走既有降級鏈（fallback 檔案／告警），不回 500
	c.Set("audit_details", map[string]string{"result_count": strconv.Itoa(len(events))})
	facts := make([]clipboardEventFact, 0, len(events))
	for _, ev := range events {
		facts = append(facts, clipboardFactOf(ev))
	}
	c.JSON(http.StatusOK, gin.H{"data": facts, "total": len(facts)})
}

// GetContent 解密回傳單筆剪貼簿內容。
//
// 伺服器端逐筆留痕由 service 承擔且為交付前置（fail-close）；此處只做參數
// 解析與錯誤收斂。事件不存在／識別非法／不屬路徑中會話三種情形一律收斂為
// 同一 404 機器碼，不洩存在性細節。缺口紀錄（content_status=failed）回事實
// 而 content 鍵缺席——不以空字串冒充內容。
func (h *ClipboardEventHandler) GetContent(c *gin.Context) {
	sessionID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	eventID, err := strconv.ParseUint(c.Param("eventID"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeClipboardEventNotFound, nil)
		return
	}
	op := session.ClipboardReadOperator{
		UserID:    c.GetUint("userID"),
		Username:  c.GetString("username"),
		ClientIP:  sourceip.Of(c),
		RequestID: c.GetString("request_id"),
		Path:      c.Request.URL.Path,
	}
	view, err := h.content.ReadContent(c.Request.Context(), uint(sessionID), uint(eventID), op)
	if err != nil {
		if errors.Is(err, session.ErrClipboardEventNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeClipboardEventNotFound, nil)
			return
		}
		// 解密失敗、審計不可用（fail-close 拒絕）等一律收斂：原因只進
		// 伺服器端 log 與告警鏈，不對外展開（audit-detail-not-outward）
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalClipboardQuery, err)
		return
	}
	payload := gin.H{
		"id":             view.Event.ID,
		"session_id":     view.Event.SessionID,
		"direction":      view.Event.Direction,
		"content_length": view.Event.ContentLength,
		"content_status": view.Event.ContentStatus,
		"created_at":     view.Event.CreatedAt,
	}
	if view.Event.ContentStatus == model.ClipboardContentAvailable {
		payload["content"] = view.Content
	}
	c.JSON(http.StatusOK, gin.H{"data": payload})
}

// RegisterRoutes 註冊路由（audit 權限，與會話指令流一致）
func (h *ClipboardEventHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/sessions/:id/clipboard-events")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.RequirePermission(middleware.PermAuditView))
	{
		g.GET("", h.List)
		g.GET("/:eventID/content", h.GetContent)
	}
}
