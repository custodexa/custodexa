package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/converter"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/sourceip"
)

// RecordingHandler 錄製 API handler
type RecordingHandler struct {
	recordingService *session.RecordingService
	sessionService   *session.SessionService
	recordingTokens  *RecordingTokenManager
	// auditService 供 by-token 串流自寫審計列。**由建構子強制注入而非 setter**：
	// 那條路由是全系統唯一「取走錄影本體卻不經審計中介層」的入口，
	// 忘記接線的後果是取證無痕，不該有一個「忘了呼叫 SetXxx」的形態存在
	auditService *audit.AuditLogService
}

// NewRecordingHandler 創建錄製 handler
func NewRecordingHandler(recordingService *session.RecordingService, sessionService *session.SessionService,
	auditService *audit.AuditLogService) *RecordingHandler {
	return &RecordingHandler{
		recordingService: recordingService,
		sessionService:   sessionService,
		recordingTokens:  NewRecordingTokenManager(),
		auditService:     auditService,
	}
}

// TokenManager 暴露錄影 token 管理器供**撤銷**接線（idp-oidc-integration 1.9b/2.8）。
//
// 錄影 token 是 in-memory、TTL 120 秒且刻意不做世代比對（Resolve 為 HTTP Range
// 熱路徑），故帳號停用／解綁／外部化轉換時唯一的失效途徑是直接撤銷；
// 組裝根據此把 RevokeByUser 接到使用者級撤銷管道上。簽發仍只由本 handler 進行
func (h *RecordingHandler) TokenManager() *RecordingTokenManager {
	return h.recordingTokens
}

// GetRecordingMetadata 取得錄製元數據
func (h *RecordingHandler) GetRecordingMetadata(c *gin.Context) {
	// 解析 Session ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "session"})
		return
	}

	// 獲取元數據
	metadata, err := h.recordingService.GetRecordingMetadata(uint(id))
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		if errors.Is(err, session.ErrSessionHasNoRecording) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionHasNoRecording, nil)
			return
		}
		if errors.Is(err, session.ErrRecordingNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeRecordingFileNotFound, nil)
			return
		}

		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingMetadataQuery, err)
		return
	}

	c.JSON(http.StatusOK, metadata)
}

// DownloadRecording 下載錄製檔案
func (h *RecordingHandler) DownloadRecording(c *gin.Context) {
	// 解析 Session ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "session"})
		return
	}

	// 獲取錄製檔案路徑
	filePath, err := h.recordingService.GetRecordingBySessionID(uint(id))
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		if errors.Is(err, session.ErrSessionHasNoRecording) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionHasNoRecording, nil)
			return
		}
		if errors.Is(err, session.ErrRecordingNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeRecordingFileNotFound, nil)
			return
		}

		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingFileQuery, err)
		return
	}

	// 設定檔案名稱
	fileName := filepath.Base(filePath)

	// MIME 依副檔名分流：.cast 為 asciicast；.guac（RDP/VNC）等其餘格式回 octet-stream
	contentType := "application/octet-stream"
	if strings.HasSuffix(fileName, ".cast") {
		contentType = "application/x-asciicast"
	}
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))

	// 發送檔案
	c.File(filePath)
}

// StreamRecording 串流播放錄製檔案（支援 HTTP Range）
func (h *RecordingHandler) StreamRecording(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "session"})
		return
	}
	h.serveRecordingForSession(c, uint(id))
}

// IssueRecordingToken 簽發短時效、不透明的錄影存取 token，供播放器放進串流 URL，
// 取代原本放在 query 的長效登入 JWT（JWT 會被 access log 完整記下）。
func (h *RecordingHandler) IssueRecordingToken(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "session"})
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	username, _ := middleware.GetCurrentUsername(c)
	// 脈絡於**簽發**階段取得：兌換階段只剩 grant，已無從得知經哪個 provider 認證。
	// 使用者名稱同理——兌換端點無認證中介層，身分只能靠這份簽發時快照
	authCtx := middleware.GetAuthContext(c)
	token, err := h.recordingTokens.Issue(userID, uint(id), username, authCtx)
	if err != nil {
		// 世代閘拒發（帳號停用／解綁／provider 停用）是可預期的認證結果，不是故障：
		// 回 401 讓前端導向重新登入；混進 500 會讓撤銷生效看起來像系統壞掉。
		// ErrUserNotFound 一併歸此類——帳號已被刪除
		if errors.Is(err, identity.ErrCredentialGenerationStale) ||
			errors.Is(err, identity.ErrUserNotFound) {
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeRecordingTokenRevoked, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingTokenIssue, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// StreamRecordingByToken 以不透明錄影 token 串流（token 即授權，無需 JWT）。
// 路由註冊於未套 AuthMiddleware 的群組——播放器僅持有短時效 token、不接觸 JWT。
//
// **審計由本 handler 自寫，不能靠中介層**：`AuditLogMiddleware` 在 context 沒有
// userID／username 時整筆跳過（`middleware/audit_log.go:52-56`），而本路由鏈中
// 沒有任何東西會設定它們。修法前，取走錄影本體（全系統最敏感的證物：完整終端
// 畫面、憑證輸入、跳板後的一切操作）在 `audit_logs` 是**零列**——稽核鏈對這個
// 動作全盲。身分取自 grant 的簽發時快照，見 `auditRecordingRetrieval`。
func (h *RecordingHandler) StreamRecordingByToken(c *gin.Context) {
	start := time.Now()
	rtoken := c.Query("rtoken")
	if rtoken == "" {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeRecordingTokenMissing, nil)
		return
	}
	grant, ok := h.recordingTokens.Resolve(rtoken)
	if !ok {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeRecordingTokenInvalid, nil)
		return
	}
	h.serveRecordingForSession(c, grant.SessionID)
	h.auditRecordingRetrieval(c, rtoken, grant, start)
}

// auditRecordingRetrieval 為「以錄影 token 取走錄影本體」寫審計列。
//
// # 什麼算一次取證
//
// 一個 grant ＋ 一次實際交付＝一列。去重的判準與理由見
// `RecordingTokenManager.MarkRetrievalAudited`（HTTP Range 分塊不得各記一列）。
// **只有成功交付才去重**：失敗（檔案不存在／轉檔失敗）逐次記列——那不在熱路徑上，
// 且每一次都是獨立訊號（「有人拿著有效授權來取，但取不到」）。
//
// # 為什麼不阻塞傳輸
//
// 兩層：去重命中時只做一次 in-memory map 操作（與 Resolve 同量級，不碰 DB）；
// 真要寫列時走 `AuditLogService.Log`，它是 buffered channel 的非同步投遞。
// 故錄影檔多大都與審計無關——審計成本固定在「每 grant 一次」。
//
// # 記在傳輸之後
//
// 取 `c.Writer.Status()` 需要 handler 已回應完畢，故本函式在 serve 之後呼叫。
// 客戶端中途中斷仍會留痕（handler 照樣返回）；**明載邊界**：行程於傳輸中途硬當
// 則該列不存在，與其餘非同步審計列同一風險等級。
//
// # 明載邊界（不得表述為「取流者身分可驗證」）
//
// 本列記的是 grant 的**簽發者**。token 可轉交，持有者即可取流——此修法讓
// 「誰調閱了這場錄影」可查，不改變 token 可轉交這件事。
func (h *RecordingHandler) auditRecordingRetrieval(c *gin.Context, rtoken string,
	grant recordingGrant, start time.Time) {
	code := c.Writer.Status()
	delivered := code >= 200 && code < 400
	if delivered && !h.recordingTokens.MarkRetrievalAudited(rtoken) {
		return
	}
	if h.auditService == nil {
		// 組裝漏接時**不得靜默**：這條路由沒有中介層兜底，審計服務缺席即等於
		// 回到零留痕的缺陷態
		log.Printf("[Recording] 審計服務未注入，%s 的錄影取證未留痕（session=%d）",
			c.Request.URL.Path, grant.SessionID)
		return
	}
	status := model.StatusSuccess
	if !delivered {
		status = model.StatusFailure
	}
	sessionID := grant.SessionID
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     grant.UserID,
		Username:   grant.Username,
		Action:     model.ActionRead,
		Resource:   model.ResourceRecording,
		ResourceID: &sessionID,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.FullPath(),
		ClientIP:   sourceip.Of(c),
		StatusCode: code,
		Duration:   time.Since(start),
		RequestID:  c.GetString("request_id"),
		// via=rtoken 使這條「無認證中介層」的取證路徑在審計上可與
		// /sessions/:id/recording/stream（走 JWT＋權限檢查）區分
		Details: fmt.Sprintf(`{"session_id":"%d","via":"rtoken"}`, sessionID),
	})
}

// serveRecordingForSession 依 sessionID 串流錄影檔（StreamRecording 與 by-token 共用）
func (h *RecordingHandler) serveRecordingForSession(c *gin.Context, sessionID uint) {
	// 獲取錄製檔案路徑
	filePath, err := h.recordingService.GetRecordingBySessionID(sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		if errors.Is(err, session.ErrSessionHasNoRecording) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionHasNoRecording, nil)
			return
		}
		if errors.Is(err, session.ErrRecordingNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeRecordingFileNotFound, nil)
			return
		}

		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingFileQuery, err)
		return
	}

	// Check if file is .cast format already (SSH asciinema)
	if strings.HasSuffix(filePath, ".cast") {
		// Serve .cast file directly
		h.serveCastFile(c, filePath)
		return
	}

	// Check if file is .guac format (RDP Guacamole recording)
	if strings.HasSuffix(filePath, ".guac") {
		// Serve .guac file directly
		h.serveGuacFile(c, filePath)
		return
	}

	// If .typescript file, convert to .cast
	if strings.HasSuffix(filePath, ".typescript") {
		castPath := strings.TrimSuffix(filePath, ".typescript") + ".cast"

		// Check if .cast already exists
		if _, err := os.Stat(castPath); err == nil {
			// .cast exists, serve it
			h.serveCastFile(c, castPath)
			return
		}

		// .cast doesn't exist, convert typescript -> cast
		timingPath := filePath + ".timing"

		// Check if timing file exists
		if _, err := os.Stat(timingPath); os.IsNotExist(err) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeRecordingTimingNotFound, nil)
			return
		}

		// Get session metadata for header
		session, err := h.sessionService.GetByID(sessionID)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionQuery, err)
			return
		}

		// Perform conversion
		err = converter.ConvertTypescriptToAsciinema(filePath, timingPath, castPath, session)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeRecordingConvert, err)
			return
		}

		// Update session recording_path to point to .cast file
		fileInfo, _ := os.Stat(castPath)
		if fileInfo != nil {
			h.sessionService.UpdateRecording(sessionID, castPath, fileInfo.Size())
		}

		// Serve converted file
		h.serveCastFile(c, castPath)
		return
	}

	// Unknown format, serve as-is
	h.serveCastFile(c, filePath)
}

// serveCastFile serves a .cast file with proper headers and Range support
func (h *RecordingHandler) serveCastFile(c *gin.Context, filePath string) {
	// 開啟檔案
	file, err := os.Open(filePath)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingFileOpen, err)
		return
	}
	defer file.Close()

	// 獲取檔案資訊
	fileInfo, err := file.Stat()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingFileStat, err)
		return
	}

	// 設定 MIME 類型
	c.Header("Content-Type", "application/x-asciicast")
	c.Header("Accept-Ranges", "bytes")

	// 使用 Gin 的 ServeContent 支援 Range 請求
	http.ServeContent(c.Writer, c.Request, filepath.Base(filePath), fileInfo.ModTime(), file)
}

// serveGuacFile serves a .guac file (Guacamole recording) with proper headers and Range support
func (h *RecordingHandler) serveGuacFile(c *gin.Context, filePath string) {
	// 開啟檔案
	file, err := os.Open(filePath)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingFileOpen, err)
		return
	}
	defer file.Close()

	// 獲取檔案資訊
	fileInfo, err := file.Stat()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingFileStat, err)
		return
	}

	// 設定 MIME 類型為 application/octet-stream（Guacamole 協議二進制格式）
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Accept-Ranges", "bytes")
	c.Header("Cache-Control", "no-cache")

	// 使用 Gin 的 ServeContent 支援 Range 請求
	http.ServeContent(c.Writer, c.Request, filepath.Base(filePath), fileInfo.ModTime(), file)
}

// GetRecordingStats 取得儲存統計
func (h *RecordingHandler) GetRecordingStats(c *gin.Context) {
	stats, err := h.recordingService.GetRecordingStats()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingStatsQuery, err)
		return
	}

	c.JSON(http.StatusOK, stats)
}

// DeleteRecording 刪除錄製檔案
func (h *RecordingHandler) DeleteRecording(c *gin.Context) {
	// 檢查管理員權限（僅管理員可刪除錄製）
	role, exists := c.Get("role")
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	roleStr, ok := role.(string)
	if !ok || roleStr != "admin" {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeRoleRequired, map[string]any{"role": "admin"})
		return
	}

	// 解析 Session ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "session"})
		return
	}

	// 刪除錄製
	err = h.recordingService.DeleteRecording(uint(id))
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
			return
		}
		if errors.Is(err, session.ErrSessionHasNoRecording) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionHasNoRecording, nil)
			return
		}

		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRecordingDelete, err)
		return
	}

	// message 欄已移除（D9：成功回應不攜帶 UI 文案，前端自有 $t 文案）；
	// 仍回空 JSON 物件而非空 body，維持「200 一律是 JSON」的回應形狀慣例。
	c.JSON(http.StatusOK, gin.H{})
}

// RegisterRoutes 註冊錄製相關路由
func (h *RecordingHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	// Session 錄製相關路由
	sessions := r.Group("/sessions")
	sessions.Use(middleware.AuthMiddleware(authService))

	sessions.GET("/:id/recording", middleware.RequirePermission(middleware.PermAuditView), h.GetRecordingMetadata)
	sessions.GET("/:id/recording/download", middleware.RequirePermission(middleware.PermAuditView), h.DownloadRecording)
	sessions.GET("/:id/recording/stream", middleware.RequirePermission(middleware.PermAuditView), h.StreamRecording)
	sessions.POST("/:id/recording/token", middleware.RequirePermission(middleware.PermAuditView), h.IssueRecordingToken)
	sessions.DELETE("/:id/recording", middleware.RequirePermission(middleware.PermSessionTerminate), h.DeleteRecording)

	// 以不透明錄影 token 串流：註冊於未套 AuthMiddleware 的 v1 群組，
	// 播放器持短時效 token 即可取流，不再把長效 JWT 放進 URL query（避免進 access log）
	r.GET("/recordings/stream", h.StreamRecordingByToken)

	// 錄製統計路由
	recordings := r.Group("/recordings")
	recordings.Use(middleware.AuthMiddleware(authService))

	recordings.GET("/stats", middleware.RequirePermission(middleware.PermAuditView), h.GetRecordingStats)
}
