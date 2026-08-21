package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/sourceip"
	"gorm.io/gorm"
)

// SFTPHandler SSH 資產的檔案管理 API（sftp-file-management）
//
// 資產收口模式：client 只送 asset_id 與路徑，憑證由後端解析；
// 權限沿用連線授權（能連線即能傳檔，收口點一致）；全操作審計。
type SFTPHandler struct {
	sftpService          *session.SFTPService
	authorizationService *authz.AssetAuthorizationService
	auditService         *audit.AuditLogService
	// authService 角色現況重判（codex 階段 4 high）：檔案面與三個連線強制點
	// 共用同一事實源 CurrentConnectRole。不設此欄即等於信任 JWT 角色快照——
	// 已被降權／停用的舊 admin JWT 在 token 效期內仍能以 admin 短路存取任意帳號的
	// 檔案面。**建構期必填**（由 RegisterRoutes 的組裝端提供）
	authService *identity.AuthService
	// accessPolicy 存取政策閘（access-policy-approval，codex 審查 #1）：
	// 檔案資料面與 connect-token 共用同一閘，非 open 段位須擋常設 connect。
	// nil＝不套政策閘（既有測試路徑，等同全域 open）
	accessPolicy *policy.AccessPolicyService
	// dataTransfer 資料傳輸閘（data-transfer-control D3）：於 requireConnectPermission
	// 之後、動作之前判定。**List 不判**——列目錄不是資料傳輸，且 connect 授權已涵蓋
	// 可見性（列目錄與 stat 不搬運內容，不屬資料傳輸動作）。
	// nil＝不套傳輸閘（既有測試路徑，等同五鍵全允許）
	dataTransfer *policy.DataTransferService
}

// SetDataTransfer 注入資料傳輸閘（組裝端呼叫）
func (h *SFTPHandler) SetDataTransfer(dt *policy.DataTransferService) {
	h.dataTransfer = dt
}

// NewSFTPHandler 建立檔案管理處理器
func NewSFTPHandler(
	sftpService *session.SFTPService,
	authorizationService *authz.AssetAuthorizationService,
	auditService *audit.AuditLogService,
	authService *identity.AuthService,
) *SFTPHandler {
	return &SFTPHandler{
		sftpService:          sftpService,
		authorizationService: authorizationService,
		auditService:         auditService,
		authService:          authService,
	}
}

// SetAccessPolicy 注入存取政策閘（組裝端呼叫）
func (h *SFTPHandler) SetAccessPolicy(ap *policy.AccessPolicyService) {
	h.accessPolicy = ap
}

// sftpConnectionAuthCode 可連線複查錯誤 → 狀態＋機器碼（與 sshproxy 的
// connectionAuthError 同語義：停用／鎖定／查無使用者各自可辨，不併為單一 401）
func sftpConnectionAuthCode(err error) (int, apierror.ErrCode) {
	switch {
	case errors.Is(err, identity.ErrAccountLocked):
		return http.StatusLocked, apierror.CodeAccountLocked
	case errors.Is(err, identity.ErrUserInactive):
		return http.StatusForbidden, apierror.CodeUserInactive
	case errors.Is(err, identity.ErrUserNotFound):
		return http.StatusUnauthorized, apierror.CodeTokenInvalid
	default:
		return http.StatusUnauthorized, apierror.CodeTokenInvalid
	}
}

// RegisterRoutes 註冊檔案管理路由
func (h *SFTPHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	files := r.Group("/assets/:id/files")
	files.Use(middleware.AuthMiddleware(authService))

	files.GET("", h.List)
	files.GET("/download", h.Download)
	files.POST("/upload", h.Upload)
	files.POST("/mkdir", h.Mkdir)
	files.DELETE("", h.Delete)

	// 資料傳輸有效能力查詢（data-transfer-control 6.2）：前端據此把不可用動作
	// 呈現為不可用＋原因，而非讓使用者點下去才失敗。
	// **這是呈現用的讀取面，不是強制點**——強制在 SFTP／K8s 端點、tunnel 與 guacd
	// 參數三處，前端隱藏按鈕不構成控制（D11-1）。
	caps := r.Group("/assets/:id/transfer-capabilities")
	caps.Use(middleware.AuthMiddleware(authService))
	caps.GET("", h.TransferCapabilities)
}

// TransferCapabilities 回傳當前使用者對該資產的五項有效傳輸能力與其邊界事實。
//
// 授權前置與檔案端點同一把尺（requireConnectAsset）：未授權回 404 資產不存在，
// 不因為「只是查能力」就放寬——否則本端點成了資產存在性的探測器。
//
// 解析失敗時回**全禁**（fail-close）而非 500：呼叫端是 UI，拿到全禁只會多顯示
// 不可用與原因，拿到 500 則會退回「全部當可用」的預設呈現。
func (h *SFTPHandler) TransferCapabilities(c *gin.Context) {
	userID, assetID, _, ok := h.requireConnectAsset(c)
	if !ok {
		return
	}

	// dataTransfer 未注入＝既有測試路徑，等同五鍵全允許（與 requireTransferAllowed 一致）
	caps := policy.TransferCapabilities{
		ClipboardSend: true,
		ClipboardRecv: true,
		FileUpload:    true,
		FileDownload:  true,
		FileDelete:    true,
	}
	if h.dataTransfer != nil {
		resolved, err := h.dataTransfer.EffectiveTransfer(c.Request.Context(), userID, assetID,
			policy.TransferChannelWeb)
		if err != nil {
			log.Printf("[SFTP] 傳輸能力解析失敗（fail-close 全禁呈現）: userID=%d assetID=%d err=%v",
				userID, assetID, err)
			resolved = policy.TransferCapabilities{} // 零值＝全禁
		}
		caps = resolved
	}

	c.JSON(http.StatusOK, gin.H{
		"capabilities": caps,
		// 誠實邊界隨能力一起下發，讓 UI 不必在前端硬編這些事實（D11）：
		// 剪貼簿只對圖形協議有強制力，且是連線參數——改政策不影響進行中連線（D4）
		"clipboard_enforced_protocols": []string{"rdp", "vnc"},
		"clipboard_requires_reconnect": true,
	})
}

// requireConnectAsset 資產層前置閘：解析 asset_id、角色現況重判、連線授權、
// 資產啟用狀態、存取政策段位。失敗時已寫入回應。
// 回傳 (userID, assetID, role, ok)——role 為 DB 現查值，呼叫端不得改用 JWT 快照。
//
// **自 requireConnectPermission 抽出（data-transfer-control 6.2）**：能力查詢端點
// 需要同一組資產層判定，但**不需要**其後的 SSH 連線帳號解析（那段以
// `model.ProtocolSSH` 判定帳號授權，對 RDP／VNC 資產不適用）。抽出而非複製——
// 安全前置條件複製一份即是日後兩邊分岔的起點。
func (h *SFTPHandler) requireConnectAsset(c *gin.Context) (uint, uint, string, bool) {
	assetID64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || assetID64 == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return 0, 0, "", false
	}
	assetID := uint(assetID64)

	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return 0, 0, "", false
	}

	// 角色現況重判（codex 階段 4 high，與 connect token 簽發／兌換三點對稱）：
	// AuthMiddleware 不查 DB，停用／鎖定／降權者持變更前簽發的正式 JWT 仍能走到這裡。
	// 不以 DB 現查角色覆蓋，其後所有 admin 短路（授權判定、帳號範圍全量）都會憑
	// JWT 角色快照放行——降權的前 admin 在 token 效期內仍可存取任意帳號的檔案面。
	// 順帶完成 AUTH-1 可連線複查（停用／鎖定），與連線面同一事實源
	role, connErr := h.authService.CurrentConnectRole(userID)
	if connErr != nil {
		status, code := sftpConnectionAuthCode(connErr)
		apierror.Respond(c, status, code, nil)
		return 0, 0, "", false
	}

	ctx := sftpRoleContext(c, role)
	hasPermission, err := h.authorizationService.CheckPermission(ctx, userID, assetID, model.PermissionConnect)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSFTPPermissionCheck, err)
		return 0, 0, "", false
	}
	if !hasPermission {
		// 未授權統一回 404「資產不存在」語義（access-policy-approval D8 順修）：
		// 與 RequireAssetVisible 逐資產守門一致，不洩漏資產存在性
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
		return 0, 0, "", false
	}

	// 停用資產硬擋（asset-list-info-layering D8）：檔案面與 connect-token 同收口；
	// 授權檢查之後無存在性洩漏，403 機器可辨；admin 不豁免
	active, err := h.authorizationService.AssetActive(assetID)
	if err != nil {
		// 資產不存在（含軟刪）回 404 而非誤報「已停用」（asset-syslog-debt-cleanup D3）：
		// 走到這裡的兩種呼叫者——權限短路的 admin，以及持軟刪資產殘留授權的
		// 一般 user/auditor（刪資產不撤銷授權、權限查詢不 join assets）。
		// 404 與上方未授權同語義，不新增可區分訊號、不洩漏存在性
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return 0, 0, "", false
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSFTPAssetStatus, err)
		return 0, 0, "", false
	}
	if !active {
		apierror.Write(c, http.StatusForbidden, apierror.ErrorResponse{
			Code: apierror.CodeAssetDisabled,
			Meta: map[string]any{"reason": "asset_disabled"},
		})
		return 0, 0, "", false
	}

	// 存取政策閘（codex 審查 #1）：檔案資料面與 connect-token 共用同一閘——
	// 非 open 段位僅時窗內臨時授權放行，常設 connect 被擋（強制審核不能只保護終端）；
	// admin 豁免（檔案操作本就逐筆審計），auditor 與一般 user 同攔。
	// role 用上方 DB 現查值，不再讀 JWT 快照——否則降權的前 admin 仍能豁免政策閘
	if h.accessPolicy != nil {
		decision, err := h.accessPolicy.CheckConnectByAssetID(userID, role, assetID)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSFTPAccessPolicy, err)
			return 0, 0, "", false
		}
		if !decision.Allowed {
			// 政策攔截於檔案端點回 404 資產不存在語義（不洩漏存在性、不引導檔案端點做申請）：
			// 申請入口在資產列表/連線頁，此處僅擋
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
			return 0, 0, "", false
		}
	}

	return userID, assetID, role, true
}

// sftpRoleContext 把 DB 現查角色掛進 ctx（沿既有 CheckPermission 慣例）
func sftpRoleContext(c *gin.Context, role string) context.Context {
	ctx := c.Request.Context()
	if role != "" {
		ctx = context.WithValue(ctx, "role", role) //nolint:staticcheck // 沿用既有 CheckPermission 慣例
	}
	return ctx
}

// requireConnectPermission 資產層前置閘（requireConnectAsset）＋SSH 連線帳號解析；
// 失敗時已寫入回應。回傳 (userID, assetID, accountID, ok)，accountID=0＝預設帳號
func (h *SFTPHandler) requireConnectPermission(c *gin.Context) (uint, uint, uint, bool) {
	userID, assetID, role, ok := h.requireConnectAsset(c)
	if !ok {
		return 0, 0, 0, false
	}
	ctx := sftpRoleContext(c, role)
	var err error

	// 連線帳號解析（asset-multi-account D9）：帶 session_id＝自會話分頁進入，
	// 沿用該會話的帳號（終端開 root、旁邊卻以 app 傳檔是審計語義的斷裂）；
	// 不帶＝檔案管理獨立入口，走預設帳號。非本人／非本資產的會話一律 fail-close，
	// 不靜默退回預設帳號（否則 session_id 成了換帳號的旁路）
	accountID := uint(0)
	if raw := c.Query("session_id"); raw != "" {
		sessionID64, perr := strconv.ParseUint(raw, 10, 32)
		if perr != nil || sessionID64 == 0 {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
			return 0, 0, 0, false
		}
		accountID, err = h.sftpService.AccountForSession(userID, assetID, uint(sessionID64))
		if err != nil {
			if errors.Is(err, session.ErrSessionAccountNotFound) {
				apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
				return 0, 0, 0, false
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSessionAdminQuery, err)
			return 0, 0, 0, false
		}
	}

	// 帳號授權範圍複查（asset-multi-account D5 強制點 3／3）：
	//
	// **歷史 session 快照只決定「用哪個帳號」，不決定「還能不能用」**。
	// session_id 路徑取的是連線當下的帳號快照（D7 不可變審計欄），若逕以它建線，
	// 帳號被移出授權範圍後使用者仍可翻出舊 session id 無限延續檔案存取——
	// 舊快照成為繞過現行授權的旁路。故此處一律以現行有效帳號集合重判。
	// 獨立入口（accountID=0，走預設帳號）同受此判定：連線面已擋預設帳號的
	// 未授權情形，檔案面不得留一道語義較寬的門
	identity, ierr := h.sftpService.AccountIdentity(assetID, accountID)
	if ierr != nil {
		if errors.Is(ierr, asset.ErrAssetAccountNotFound) {
			apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
			return 0, 0, 0, false
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetAccountResolve, ierr)
		return 0, 0, 0, false
	}
	if identity.Found {
		// 檔案管理僅 SSH（session.connect 硬性檢查），協議以 SSH 判定
		if aerr := h.authorizationService.AuthorizeConnectAccount(
			ctx, userID, assetID, model.ProtocolSSH, identity.Username); aerr != nil {
			if errors.Is(aerr, authz.ErrAccountNotAuthorized) {
				log.Printf("[SFTP] 帳號已移出授權範圍，拒絕檔案操作: userID=%d assetID=%d accountID=%d", userID, assetID, identity.AccountID)
				// 與未授權同語義（404 資產不存在）：檔案端點一律不洩漏存在性
				apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)
				return 0, 0, 0, false
			}
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalSFTPPermissionCheck, aerr)
			return 0, 0, 0, false
		}
	}

	return userID, assetID, accountID, true
}

// requireTransferAllowed 資料傳輸閘（data-transfer-control 4.1）。
//
// 於 requireConnectPermission 之後、動作之前呼叫。被拒時已寫入 403 回應**與
// StatusDenied 審計**，回傳 false。
//
// **拒絕必須留痕**：現行四個檔案端點的審計全在成功路徑（成功才呼叫 h.audit），
// 拒絕分支直接 return 會讓「有沒有人試著把資料帶出去」這個稽核問題無法回答（D6）。
//
// **不豁免任何角色**：解析函式內沒有 role 分支，此處也不得補一個。
func (h *SFTPHandler) requireTransferAllowed(c *gin.Context, userID, assetID uint, action string, remotePath string) bool {
	return h.requireTransferAllowedAudited(c, userID, assetID, action, transferAuditAction(action), remotePath)
}

// requireTransferAllowedAudited 同上，但由呼叫端指定**留痕動作**。
//
// **判定粒度與留痕粒度分離的唯一落實點**：mkdir 走 `file_upload` 鍵判定
// （D3 註 2：對遠端檔案系統的寫入，upload 全禁時不該留一個能建目錄的洞），
// 但審計必須記 `file_mkdir`，否則被擋下的建目錄與被擋下的傳檔在 `action` 欄
// 完全同形，事後查不出「被擋的是建目錄還是傳檔」。
//
// 判定鍵仍原樣進 403 envelope 的 `action` 欄（那回答的是「哪一條政策擋的」，
// 是機器可讀的政策鍵，不是操作名）——兩者刻意不同源。
func (h *SFTPHandler) requireTransferAllowedAudited(c *gin.Context, userID, assetID uint,
	action string, auditAction model.AuditAction, remotePath string) bool {
	if h.dataTransfer == nil {
		return true
	}
	allowed, err := h.dataTransfer.AllowsAction(c.Request.Context(), userID, assetID,
		policy.TransferChannelWeb, action)
	if err != nil {
		// fail-close：傳輸控制的失敗方向必須是擋住而非放行
		log.Printf("[SFTP] 傳輸能力解析失敗（fail-close 拒絕）: userID=%d assetID=%d action=%s err=%v",
			userID, assetID, action, err)
		allowed = false
	}
	if allowed {
		return true
	}
	h.auditDenied(c, userID, assetID, auditAction, remotePath, action)
	apierror.Respond(c, http.StatusForbidden, apierror.CodeTransferDenied, map[string]any{
		"action": action,
		"reason": "global_policy",
	})
	return false
}

// transferAuditAction 傳輸**判定鍵** → 審計動作的預設對映。
//
// 只適用於「判定鍵即操作名」的三個動作；mkdir 不走這裡（它的判定鍵是
// `file_upload`，資訊在此已無從還原），改由 `requireTransferAllowedAudited`
// 於呼叫端顯式帶入 `model.ActionFileMkdir`
func transferAuditAction(action string) model.AuditAction {
	switch action {
	case policy.TransferActionFileDownload:
		return model.ActionFileDownload
	case policy.TransferActionFileDelete:
		return model.ActionFileDelete
	default:
		return model.ActionFileUpload
	}
}

// auditDenied 記錄被拒的檔案操作（status=denied）
func (h *SFTPHandler) auditDenied(c *gin.Context, userID, assetID uint, action model.AuditAction, remotePath, transferAction string) {
	username, _ := middleware.GetCurrentUsername(c)
	aid := assetID
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:      userID,
		Username:    username,
		Action:      action,
		Resource:    model.ResourceFile,
		ResourceID:  &aid,
		Status:      model.StatusDenied,
		Method:      c.Request.Method,
		Path:        c.FullPath(),
		ClientIP:    sourceip.Of(c),
		StatusCode:  http.StatusForbidden,
		RequestBody: fmt.Sprintf(`{"remote_path":%q,"transfer_action":%q,"reason":"global_policy"}`, remotePath, transferAction),
	})
}

// audit 記錄成功的檔案操作
func (h *SFTPHandler) audit(c *gin.Context, userID, assetID uint, action model.AuditAction, remotePath string, detail string) {
	username, _ := middleware.GetCurrentUsername(c)
	aid := assetID
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   model.ResourceFile,
		ResourceID: &aid,
		// ResourceID 維持既有語義（resource=file 的既有查詢靠它），主體鍵另記：
		// 工作台的檔案傳輸類只讀 asset_id（auditor-workbench D4）
		AssetID:     &aid,
		Status:      model.StatusSuccess,
		Method:      c.Request.Method,
		Path:        c.FullPath(),
		ClientIP:    sourceip.Of(c),
		StatusCode:  http.StatusOK,
		RequestBody: fmt.Sprintf(`{"remote_path":%q%s}`, remotePath, detail),
	})
}

// List 目錄列表
func (h *SFTPHandler) List(c *gin.Context) {
	userID, assetID, accountID, ok := h.requireConnectPermission(c)
	if !ok {
		return
	}

	remotePath := c.Query("path")
	entries, err := h.sftpService.List(assetID, accountID, remotePath)
	if err != nil {
		respondSFTPError(c, err, apierror.CodeInternalSFTPListFailed)
		return
	}

	h.audit(c, userID, assetID, model.ActionFileList, remotePath, "")
	c.JSON(http.StatusOK, gin.H{"path": remotePath, "entries": entries})
}

// Download 串流下載
func (h *SFTPHandler) Download(c *gin.Context) {
	userID, assetID, accountID, ok := h.requireConnectPermission(c)
	if !ok {
		return
	}

	remotePath := c.Query("path")
	if !h.requireTransferAllowed(c, userID, assetID, policy.TransferActionFileDownload, remotePath) {
		return
	}
	reader, size, closeFn, err := h.sftpService.Download(assetID, accountID, remotePath)
	if err != nil {
		respondSFTPError(c, err, apierror.CodeInternalSFTPDownloadFailed)
		return
	}
	defer closeFn()
	defer reader.Close()

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, path.Base(remotePath)))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(size, 10))

	// 內容摘要（clipboard-audit spec）：TeeReader 邊傳邊算，零額外 IO
	hasher := sha256.New()
	if _, err := io.Copy(c.Writer, io.TeeReader(reader, hasher)); err != nil {
		log.Printf("[SFTP] 下載串流中斷: %v", err)
		return
	}

	h.audit(c, userID, assetID, model.ActionFileDownload, remotePath,
		fmt.Sprintf(`,"size":%d,"sha256":"%x"`, size, hasher.Sum(nil)))
}

// Upload 串流上傳（multipart: path + file）
func (h *SFTPHandler) Upload(c *gin.Context) {
	userID, assetID, accountID, ok := h.requireConnectPermission(c)
	if !ok {
		return
	}

	remoteDir := c.PostForm("path")
	fileHeader, err := c.FormFile("file")
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSFTPFileMissing, nil)
		return
	}

	src, err := fileHeader.Open()
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSFTPUploadReadFailed, nil)
		return
	}
	defer src.Close()

	remotePath := path.Join(remoteDir, path.Base(fileHeader.Filename))
	if !h.requireTransferAllowed(c, userID, assetID, policy.TransferActionFileUpload, remotePath) {
		return
	}
	hasher := sha256.New()
	written, err := h.sftpService.Upload(assetID, accountID, remotePath, io.TeeReader(src, hasher))
	if err != nil {
		respondSFTPError(c, err, apierror.CodeInternalSFTPUploadFailed)
		return
	}

	h.audit(c, userID, assetID, model.ActionFileUpload, remotePath,
		fmt.Sprintf(`,"size":%d,"sha256":"%x"`, written, hasher.Sum(nil)))
	c.JSON(http.StatusOK, gin.H{"path": remotePath, "size": written})
}

// Mkdir 建立目錄
func (h *SFTPHandler) Mkdir(c *gin.Context) {
	userID, assetID, accountID, ok := h.requireConnectPermission(c)
	if !ok {
		return
	}

	var req struct {
		Path string `json:"path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSFTPMkdirPathMissing, nil)
		return
	}

	// Mkdir 判 FileUpload（D3 註 2）：它是對遠端檔案系統的寫入，upload 全禁時
	// 留一個能建目錄的洞不合理——建目錄與傳檔同為對遠端檔案系統的寫入。
	// **留痕仍記 file_mkdir**：被擋的建目錄與被擋的傳檔若同記 file_upload，
	// 稽核者以 action 篩選時分不出兩者，且同一操作會因成功／被擋而落在不同
	// action 值（成功記 file_mkdir，見下方 h.audit）——判定粒度與留痕粒度
	// 刻意分離，故此處顯式帶入審計動作
	if !h.requireTransferAllowedAudited(c, userID, assetID,
		policy.TransferActionFileUpload, model.ActionFileMkdir, req.Path) {
		return
	}

	if err := h.sftpService.Mkdir(assetID, accountID, req.Path); err != nil {
		respondSFTPError(c, err, apierror.CodeInternalSFTPMkdirFailed)
		return
	}

	h.audit(c, userID, assetID, model.ActionFileMkdir, req.Path, "")
	c.JSON(http.StatusOK, gin.H{"path": req.Path})
}

// Delete 刪除檔案或空目錄
func (h *SFTPHandler) Delete(c *gin.Context) {
	userID, assetID, accountID, ok := h.requireConnectPermission(c)
	if !ok {
		return
	}

	remotePath := c.Query("path")
	if !h.requireTransferAllowed(c, userID, assetID, policy.TransferActionFileDelete, remotePath) {
		return
	}
	if err := h.sftpService.Delete(assetID, accountID, remotePath); err != nil {
		respondSFTPError(c, err, apierror.CodeInternalSFTPDeleteFailed)
		return
	}

	h.audit(c, userID, assetID, model.ActionFileDelete, remotePath, "")
	c.JSON(http.StatusOK, gin.H{"path": remotePath})
}

// respondSFTPError 分類錯誤回應：路徑驗證 400，其餘 502（遠端操作失敗）。
// service 層錯誤格式為「動作描述: %w」——僅動作描述屬使用者語言，
// 被包裝的 ssh/sftp 庫原文留在伺服器日誌不外洩。
//
// actionCode 由呼叫點傳入（V2 對抗驗收 H3）：五個動作各自的失敗碼，
// 使「下載時失敗」不會顯示為泛化的「檔案操作失敗」。可行動的
// ErrRemoveDirNotEmpty 另走專碼；狀態碼分類不變（400/502）
func respondSFTPError(c *gin.Context, err error, actionCode apierror.ErrCode) {
	switch {
	case errors.Is(err, session.ErrInvalidRemotePath):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSFTPInvalidPath, nil)
	case errors.Is(err, asset.ErrAssetNoUsableAccount):
		// 零帳號資產：可行動的設定問題（400），不是遠端操作失敗（502）
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
	case errors.Is(err, asset.ErrAssetAccountNotFound):
		// 會話帳號已被刪除／不屬該資產（session_id 路徑的 fail-close）：
		// 與帳號 CRUD 端點同碼同狀態，不洩漏存在性、不回泛化的 502
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetAccountNotFound, nil)
	case errors.Is(err, session.ErrRemoveDirNotEmpty):
		apierror.RespondInternal(c, http.StatusBadGateway, apierror.CodeSFTPDirNotEmpty, err)
	default:
		apierror.RespondInternal(c, http.StatusBadGateway, actionCode, err)
	}
}
