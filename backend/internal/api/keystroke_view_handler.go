package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

// KeystrokeReasonMaxRunes 查看理由的字元上限（以字元計，中文理由不被位元組長度提早截斷）。
const KeystrokeReasonMaxRunes = 1000

// KeystrokeViewer 鍵盤紀錄中繼資料與查看能力（消費者側窄介面，由 session.KeystrokeViewService 實作）。
type KeystrokeViewer interface {
	Meta(sessionID uint) (*session.KeystrokeMeta, error)
	View(ctx context.Context, sessionID uint, req session.KeystrokeViewRequest,
		op session.KeystrokeViewOperator) (*session.KeystrokeView, error)
}

// KeystrokeRevealReporter 交付成功後的可選揭露告警。
type KeystrokeRevealReporter interface {
	Report(context.Context, audit.SensitiveRevealInput)
}

// KeystrokeViewHandler 鍵盤紀錄查看 API。
type KeystrokeViewHandler struct {
	viewer  KeystrokeViewer
	reveals KeystrokeRevealReporter
}

// NewKeystrokeViewHandler 建立 handler。
func NewKeystrokeViewHandler(viewer KeystrokeViewer) *KeystrokeViewHandler {
	return &KeystrokeViewHandler{viewer: viewer}
}

// SetSensitiveRevealReporter 接上政策控制的揭露告警。
func (h *KeystrokeViewHandler) SetSensitiveRevealReporter(r KeystrokeRevealReporter) { h.reveals = r }

// Meta 回傳鍵盤紀錄中繼資料，不解密。
func (h *KeystrokeViewHandler) Meta(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	meta, err := h.viewer.Meta(uint(id))
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeystrokeView, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": meta})
}

type keystrokeViewBody struct {
	Reason    string `json:"reason"`
	FromEvent int    `json:"from_event"`
	Limit     int    `json:"limit"`
}

// View 帶理由查看。理由只取自請求本文；查詢字串中的 reason 一律不採用。
func (h *KeystrokeViewHandler) View(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return
	}
	var body keystrokeViewBody
	if err := c.ShouldBindJSON(&body); err != nil {
		// 本文無法解析視同沒有理由；錯誤內容不回顯
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeystrokeReasonRequired, nil)
		return
	}
	reason := strings.TrimSpace(body.Reason)
	switch n := utf8.RuneCountInString(reason); {
	case n == 0:
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeystrokeReasonRequired, nil)
		return
	case n > KeystrokeReasonMaxRunes:
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeystrokeReasonTooLong, nil)
		return
	}
	op := session.KeystrokeViewOperator{
		UserID: c.GetUint("userID"), Username: c.GetString("username"),
		ClientIP: sourceip.Of(c), RequestID: c.GetString("request_id"), Path: c.Request.URL.Path,
	}
	// 回應本文是使用者原樣鍵入的內容：禁止任何中介快取
	c.Header("Cache-Control", "no-store")
	view, err := h.viewer.View(c.Request.Context(), uint(id),
		session.KeystrokeViewRequest{Reason: reason, FromEvent: body.FromEvent, Limit: body.Limit}, op)
	if err != nil {
		var nv *session.KeystrokeNotViewableError
		switch {
		case errors.Is(err, session.ErrSessionNotFound):
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
		case errors.As(err, &nv):
			c.Set("audit_details", map[string]string{"state": nv.State})
			apierror.Respond(c, http.StatusNotFound, apierror.CodeKeystrokeNotViewable, nil)
		case errors.Is(err, session.ErrKeystrokeVaultSealed):
			apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeKeystrokeVaultSealed, nil)
		case errors.Is(err, session.ErrKeystrokeRecordRejected):
			apierror.Respond(c, http.StatusUnprocessableEntity, apierror.CodeKeystrokeRecordRejected, nil)
		default:
			// 留痕失敗（fail-close）、讀取失敗等一律收斂；原因只進伺服器端 log 與告警鏈
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeystrokeView, err)
		}
		return
	}
	// 留痕已提交、內容已組好；揭露告警不能撤回交付
	if h.reveals != nil {
		h.reveals.Report(c.Request.Context(), audit.SensitiveRevealInput{
			Actor:      gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
			SourceType: "keystroke_record", SourceID: view.RecordID, SessionID: view.SessionID,
			AssetID: view.AssetID, AccessRequestID: view.AccessRequestID, Reason: reason, RequestID: op.RequestID,
		})
	}
	data := gin.H{
		"events": view.Events, "integrity": view.Integrity, "record_status": view.RecordStatus,
		"last_event_ms": view.LastEventMs,
	}
	if view.NextEvent != nil {
		data["next_event"] = *view.NextEvent
	}
	if view.FailedSegment != nil {
		data["failed_segment"] = *view.FailedSegment
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// RegisterRoutes 註冊路由（keystroke:view，全域）。
func (h *KeystrokeViewHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/sessions/:id/keystrokes")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.EnforceRegistry())
	{
		g.GET("", h.Meta)
		g.POST("/view", h.View)
	}
}
