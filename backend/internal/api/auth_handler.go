package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
)

// AuthHandler 認證 API handler
type AuthHandler struct {
	authService  *identity.AuthService
	auditService *audit.AuditLogService
	// userService 自助改密（/auth/change-password）用；nil 時該端點回 503
	userService *identity.UserService
	// trustProxy 是否已顯式約定可信代理鏈（TRUSTED_PROXIES）。
	// **零值 false＝不採信轉送標頭**，故未經 NewAuthHandler 建構的實例
	// （測試與 sealgate 佔位）自動落在安全的那一邊，見 auditSourceIP
	trustProxy bool
	// loginGuard 本地登入端點的來源濫用防護（security-backlog-settlement D3）。
	//
	// **與帳號級鎖定防的是不同攻擊**：`failed_login_attempts`＋`locked_until` 擋
	// 對單一帳號的暴力破解；本 guard 擋**換帳號輪流試**的密碼噴灑——每個帳號各試
	// 三次即換下一個，永遠碰不到帳號門檻。只有帳號鎖定 SHALL NOT 視為已涵蓋此面。
	//
	// nil 安全：未經 NewAuthHandler 建構的實例不限流（測試與 sealgate 佔位）
	loginGuard *sourceAbuseGuard
	// changePasswordGuard 自助改密端點的來源濫用防護
	// （auth-cost-based-concurrency）。**該端點原本完全沒有併發上限**，
	// 而其每請求的雜湊成本是登入的 7 倍（預設組態）至 27 倍（政策上界 24）。
	changePasswordGuard *sourceAbuseGuard
	// refreshCookies refresh 憑證的 httpOnly cookie 下發／清除
	// （refresh-token-httponly-cookie）。nil 安全：視為非 Secure，功能不斷
	refreshCookies *RefreshCookieWriter
}

// loginEventThrottled 登入限流的聚合審計事件名。
//
// 語義為**政策拒絕**（denied，與 RBAC 403 同語義），非憑證不成立——
// 被擋下的請求根本沒走到密碼比對
const loginEventThrottled = "login_throttled"

// changePasswordEventThrottled 改密限流的聚合審計事件名（語義同上：政策拒絕）。
const changePasswordEventThrottled = "change_password_throttled"

// defaultLoginGuardParams 本地登入端點的限流參數。
//
// 量級沿 defaultOIDCGuardParams：per-IP 60 burst／每秒補 1 個，涵蓋 NAT 後整個
// 辦公室同時上班登入；全域 600 burst 遠高於任何正常尖峰。密碼噴灑要有效必須
// 跨大量帳號持續送，那個速率遠在此門檻之上。
//
// **MaxInFlight 較 OIDC 低**：登入的每個請求都會做一次密碼雜湊（刻意的慢函式），
// 並發堆積直接吃 CPU；OIDC 的出站請求是 I/O 等待，兩者的堆積代價不同。
//
// 上限**由雜湊實作回報的成本推導**（auth-cost-based-concurrency 2.2），
// 不再寫死——原本的常數 `16` 其註解直接寫死「bcrypt」，換演算法後那個依據就消失了。
func defaultLoginGuardParams() sourceGuardParams {
	p := defaultOIDCGuardParams()
	p.MaxInFlight = hashInFlightBudget(loginHashUnits)
	return p
}

// 認證端點的雜湊成本單位：以「一次驗證」為 1 單位。
//
// 實測（2026-08-19，cost=10）單次雜湊約 68–78ms，據此換算各端點的每請求成本：
//   - 登入：1 次驗證 ＝ 1 單位。**遷移期例外**：登入成功且 `NeedsRehash` 為真時，
//     `rehashPasswordIfNeeded` 會多做 1 次 Hash → 該次登入為 2 單位。
//     那是機會性且一次性的（升級後即不再觸發），故上限仍以穩態的 1 單位推導。
//   - 改密：驗舊 ＋ 比對現行 ＋ N 筆歷史 ＋ 產生新雜湊 ＝ 3+N 單位
//     預設 `password_history_count=4` → 7 單位（登入的約 7 倍）
//     政策上界 24（2026-08-19 由 100 調降）→ 27 單位（登入的約 27 倍）
//
// **倍率是可攜的，絕對毫秒不是**：獨立驗收在不同負載下測得同一組倍率
// （2.6／6.6／102.6，當時上界仍為 100），但絕對值差到 2.6 倍。
// 倍率恆落在 (2+N, 3+N) 區間是數學性質，與機器無關；引用時用單位數，不要引毫秒。
const (
	loginHashUnits = 1
	// changePasswordHashUnits 改密端點的保守成本估計。
	//
	// 取預設歷史筆數（4）而非上界（24）：上界是政策可調的極端值，
	// 以它推導（27 單位 → 上限 1）會使正常的併發改密全部排隊。
	// 上界本身已於 2026-08-19 由 100 調降為 24（使用者裁決），
	// 最壞情況因而從 103 單位降為 27 單位。
	changePasswordHashUnits = 7
)

// hashInFlightBudget 依成本單位推導同時處理中的請求上限。
//
// 設計：以「全端點的雜湊工作量預算」為固定值，各端點按其每請求成本分攤。
// 預算取 16 單位——即登入端點維持原有的 16 並發（行為不變），
// 而成本 7 倍的改密端點自動得到 16/7 ≈ 2。
//
// **下限為 1**：再貴的端點也要能處理請求，否則等於關閉功能。
func hashInFlightBudget(unitsPerRequest int) int {
	const totalHashUnits = 16
	if unitsPerRequest <= 0 {
		unitsPerRequest = 1
	}
	n := totalHashUnits / unitsPerRequest
	if n < 1 {
		return 1
	}
	return n
}

// defaultChangePasswordGuardParams 自助改密端點的限流參數。
//
// **這個端點原本完全沒有併發上限**，而它每請求的雜湊成本是登入的 7 倍（預設組態）
// 到 27 倍（政策上界 24）。只需一個已通過認證的一般帳號即可觸發
// ——對堡壘機而言一般使用者正是被稽核的對象，不屬於可信任的一方。
//
// per-IP 與全域的權杖桶沿用登入端點：改密是低頻動作，正常使用者不會連續送。
func defaultChangePasswordGuardParams() sourceGuardParams {
	p := defaultOIDCGuardParams()
	p.MaxInFlight = hashInFlightBudget(changePasswordHashUnits)
	return p
}

// NewAuthHandler 建立認證 handler（auditService 可為 nil，表示停用審計）。
//
// 可信代理是否設定於此判定一次（部署期常數，不逐請求重讀），
// 比照 NewOIDCHandler
func NewAuthHandler(authService *identity.AuthService, auditService *audit.AuditLogService) *AuthHandler {
	trustProxy := config.LoadSeal().TrustedProxyConfigured()
	h := &AuthHandler{
		authService:  authService,
		auditService: auditService,
		trustProxy:   trustProxy,
	}
	// 具型別的 nil 指標存入介面欄位會使 sink != nil 成立而在呼叫時 panic
	// （同 NewOIDCHandler 的處置）
	var sink sourceAbuseAuditSink
	if auditService != nil {
		sink = &loginAbuseSink{audit: auditService}
	}
	h.loginGuard = newSourceAbuseGuard(defaultLoginGuardParams(), trustProxy, sink)
	h.changePasswordGuard = newSourceAbuseGuard(defaultChangePasswordGuardParams(), trustProxy, sink)
	h.refreshCookies = defaultRefreshCookieWriter()
	return h
}

// SetRefreshCookieWriter 注入共用的 refresh cookie writer（cmd/server 接線）。
// 建構函式已備妥同源的 fail-safe 預設，本方法只是讓三個 handler 共用同一實例
func (h *AuthHandler) SetRefreshCookieWriter(w *RefreshCookieWriter) {
	h.refreshCookies = w
}

// loginAbuseSink 登入限流的聚合審計出口。
//
// 公開端點的失敗**不逐筆落審計**：偵測訊號本身不得成為 DoS 載體——攻擊者持續
// 送登入請求即等於持續寫 DB。由 guard 以（事件, 來源 IP, 時間窗）聚合，
// 窗結束時落一筆帶計數與首末時間的記錄
type loginAbuseSink struct {
	audit *audit.AuditLogService
}

func (s *loginAbuseSink) LogAggregatedFailure(event, clientIP string, status model.AuditStatus,
	count int, firstAt, lastAt time.Time) {
	if s.audit == nil {
		return
	}
	// **來源位址取聚合鍵而非落地當下的請求**：本列描述的是一個已結束的時間窗，
	// 觸發結清的那個請求可能來自別處。路徑／方法／狀態碼同理留空——
	// 一個窗涵蓋多個請求，沒有單一值可填
	s.audit.Log(&audit.AuditLogEntry{
		Action:   model.ActionLogin,
		Resource: model.ResourceAuth,
		Status:   status,
		ClientIP: clientIP,
		Details: fmt.Sprintf(`{"event":"login_abuse_aggregate","reason":%q,"client_ip":%q,`+
			`"count":%d,"first_at":%q,"last_at":%q}`,
			event, clientIP, count,
			firstAt.UTC().Format(time.RFC3339), lastAt.UTC().Format(time.RFC3339)),
	})
}

// auditSourceIP 認證類審計列的來源位址。
//
// **本檔全部審計列共用此取法，不得改回 `c.ClientIP()`**：`/auth/login`、
// `/auth/mfa/verify`、`/auth/refresh`、`/auth/change-password` 全是公開端點，
// 未設可信代理時 gin 信任任意 `X-Forwarded-For`，攻擊者送一個標頭即可為自己那筆
// 登入列指定任何來源位址——稽核追人時追到的是他挑的那個 IP，且不需任何權限。
// 與 OIDC 路徑（`OIDCHandler.auditSourceIP`）同一條紀律、同一個實作
func (h *AuthHandler) auditSourceIP(c *gin.Context) string {
	return requestSourceIP(c, h.trustProxy)
}

// SetUserService 注入使用者服務（自助改密端點依賴）
func (h *AuthHandler) SetUserService(userService *identity.UserService) {
	h.userService = userService
}

// Login 登入 API
func (h *AuthHandler) Login(c *gin.Context) {
	// 來源濫用防護（security-backlog-settlement D3）：**在解析 body 之前**——
	// 被擋下的請求不應付出任何解析成本，且限流的判準與請求內容無關。
	// 回應不含剩餘額度或重試時間（沿帳號鎖定「不透露剩餘時間與次數」的既有語義）
	if h.loginGuard != nil {
		ip := h.loginGuard.sourceIP(c)
		release, ok := h.loginGuard.acquire(ip)
		if !ok {
			h.loginGuard.record(loginEventThrottled, ip)
			apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeAuthLoginRateLimited, nil)
			return
		}
		defer release()
	}

	var req identity.LoginRequest

	// 綁定 JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	// 執行登入
	resp, err := h.authService.Login(&req)
	if err != nil {
		// 僅 sentinel 錯誤可回原文對應 code；DB/LDAP 等內部錯誤一律泛化避免洩漏
		status := http.StatusUnauthorized
		var code apierror.ErrCode
		switch {
		case errors.Is(err, identity.ErrUserInactive):
			status = http.StatusForbidden
			code = apierror.CodeUserInactive
		case errors.Is(err, identity.ErrAccountLocked):
			// 423 Locked：鎖定訊息明示（D2），不透露剩餘時間/次數
			status = http.StatusLocked
			code = apierror.CodeAccountLocked
		case errors.Is(err, identity.ErrInvalidCredentials):
			// 維持 401 與 sentinel 訊息
			code = apierror.CodeInvalidCredentials
		case errors.Is(err, identity.ErrUserNotFound):
			code = apierror.CodeUserNotFound
		case errors.Is(err, identity.ErrLDAPTransportRejected):
			// 傳輸安全政策 strict 拒絕：sentinel 原文即明確原因（spec 要求），非內部錯誤
			status = http.StatusForbidden
			code = apierror.CodeLDAPTransportRejected
		default:
			status = http.StatusInternalServerError
			log.Printf("[ERROR] login failed: user=%s err=%v", req.Username, err)
		}

		// 審計 middleware 在登入前無用戶 context 會跳過，
		// 登入失敗（暴力破解偵測的關鍵訊號）必須在此記錄
		h.auditLogin(c, 0, req.Username, model.StatusFailure, status, err.Error())

		if status >= http.StatusInternalServerError {
			apierror.Respond(c, status, apierror.CodeInternalLogin, nil)
		} else {
			apierror.Respond(c, status, code, nil)
		}
		return
	}

	// 登入時政策合規偵測審計（login-password-policy-gate D3）：偵測發生在憑證驗證
	// 當下（MFA 分流前），故不論後續走 pending/enrollment/改密分支皆須落一筆
	h.auditPasswordNoncompliant(c, resp)

	// MFA 用戶第一階段：密碼通過但尚未完成驗證，標註 mfa_pending 供稽核區分
	if resp.MFARequired {
		h.auditLogin(c, resp.PendingUserID, resp.PendingUsername, model.StatusSuccess, http.StatusOK,
			annotateAuthSource("mfa_pending", resp.AuthSource))
		c.JSON(http.StatusOK, resp)
		return
	}

	// 受強制但未註冊 MFA：密碼通過，導向強制註冊流程
	if resp.MFAEnrollmentRequired {
		h.auditLogin(c, resp.PendingUserID, resp.PendingUsername, model.StatusSuccess, http.StatusOK,
			annotateAuthSource("mfa_enrollment_required", resp.AuthSource))
		c.JSON(http.StatusOK, resp)
		return
	}

	// 強制改密：認證已全過但須先改密，標註供稽核區分
	if resp.PasswordChangeRequired {
		h.auditLogin(c, resp.PendingUserID, resp.PendingUsername, model.StatusSuccess, http.StatusOK,
			annotateAuthSource("password_change_required", resp.AuthSource))
		c.JSON(http.StatusOK, resp)
		return
	}

	h.auditLogin(c, resp.User.ID, resp.User.Username, model.StatusSuccess, http.StatusOK,
		annotateAuthSource("", resp.AuthSource))

	// 發放端點 1／6：refresh 憑證僅經 httpOnly cookie 下發，回應 body 不再含明文
	h.refreshCookies.SetFromLogin(c, resp)
	c.JSON(http.StatusOK, resp)
}

// annotateAuthSource 在審計慣例欄位（ErrorMsg）附註認證來源。
// 本地登入 source 為空字串時不附註，維持既有審計輸出零變化
func annotateAuthSource(msg, source string) string {
	if source == "" {
		return msg
	}
	if msg == "" {
		return "source=" + source
	}
	return msg + "; source=" + source
}

// auditPasswordNoncompliant 記錄登入時密碼不符政策的偵測事件（Details 僅違規類別，
// 無密碼材料）；未偵測到（category 空）時零動作
func (h *AuthHandler) auditPasswordNoncompliant(c *gin.Context, resp *identity.LoginResponse) {
	if h.auditService == nil || resp.PolicyNoncompliantCategory == "" {
		return
	}
	userID := resp.PendingUserID
	username := resp.PendingUsername
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     model.ActionPasswordNoncompliant,
		Resource:   model.ResourceAuth,
		Status:     model.StatusSuccess,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   h.auditSourceIP(c),
		StatusCode: http.StatusOK,
		Details:    fmt.Sprintf(`{"category":%q}`, resp.PolicyNoncompliantCategory),
	})
}

// auditLogin 記錄登入事件（成功與失敗）
func (h *AuthHandler) auditLogin(c *gin.Context, userID uint, username string, status model.AuditStatus, statusCode int, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     model.ActionLogin,
		Resource:   model.ResourceAuth,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   h.auditSourceIP(c),
		StatusCode: statusCode,
		ErrorMsg:   errMsg,
	})
}

// Logout 登出 API。
//
// 憑證取值來源為 refresh cookie（refresh-token-httponly-cookie 決策 5），
// 不再自 request body 讀取——**分叉偵測語義原樣保留**：提交已輪替憑證＝分叉訊號，
// 家族撤銷＋高價值審計事件，僅換了取值來源。
func (h *AuthHandler) Logout(c *gin.Context) {
	// 登出撤銷目前 refresh 憑證（spec 會話撤銷）；access token 無狀態，
	// 由客戶端刪除、殘餘存活 ≤15 分（D6 撤銷殘窗）。
	// 登出事件由 AuditLogMiddleware 記錄（action=logout，已驗證）
	if plain := readRefreshCookie(c); plain != "" {
		if err := h.authService.RevokeRefreshToken(plain, model.RefreshRevokeLogout); err != nil {
			// 登出提交已 rotated 憑證＝分叉訊號（F1）：已家族撤銷，記高價值審計事件
			var reuse *identity.RefreshReuseError
			if errors.As(err, &reuse) {
				h.auditRefresh(c, reuse.UserID, reuse.Username,
					"logout_stale_token_reuse_detected; all refresh tokens revoked")
			} else {
				// 撤銷失敗不阻擋登出（客戶端仍會清除本地憑證）；記日誌供跟進
				log.Printf("[ERROR] logout revoke refresh failed: %v", err)
			}
		}
	}

	username, _ := middleware.GetCurrentUsername(c)

	// 撤銷成敗一律清除 cookie（決策 5）：撤銷失敗不阻擋登出的既有原則不變，
	// 但瀏覽器不該留著一枚使用者以為已失效的憑證
	h.refreshCookies.Clear(c)
	c.JSON(http.StatusOK, gin.H{
		"username": username,
	})
}

// Refresh 會話刷新 API（auth-hardening D6）：以 refresh 憑證換發新 access token
// 並輪替 refresh。失敗一律 401 同文案（不洩漏憑證狀態），前端收 401 導向重新登入。
//
// 憑證**僅**自 httpOnly cookie 讀取（決策 4），無 body fallback。
// cookie 缺失回 401 而非 400：body 時代的 400 是「格式錯誤」語義，
// 而 cookie 缺失語義上就是「未提供憑證」，且走統一失敗回應才不會給攻擊者
// 區分「沒帶／無效／已撤銷」的訊號
func (h *AuthHandler) Refresh(c *gin.Context) {
	plain := readRefreshCookie(c)
	if plain == "" {
		h.respondRefreshError(c, identity.ErrRefreshInvalid)
		return
	}

	resp, err := h.authService.RefreshSession(plain)
	if err != nil {
		h.respondRefreshError(c, err)
		return
	}
	// 成功輪替留痕（audit-coverage-closure 批 4／auth-session spec）：
	// 原本只有失敗留痕，使「憑證遭竊後被持續用於維持存取」這條路徑在稽核上不可見
	// ——成功的輪替正是該情境**唯一**會留下的訊號（攻擊者不會製造失敗）。
	// 來源位址逐次落地，稽核比對同一帳號的輪替來源即可辨識異常他處使用。
	h.auditRefreshEvent(c, resp.UserID, resp.Username, model.StatusSuccess,
		http.StatusOK, "refresh_rotated")

	// 發放端點 6／6：輪替後的新憑證。效期取**剩餘**壽命——rotation 沿用原
	// `expires_at`，給滿額會讓 cookie 活得比憑證久
	h.refreshCookies.Set(c, resp.RefreshToken, resp.RefreshExpiresAt)
	c.JSON(http.StatusOK, resp)
}

// respondRefreshError 刷新失敗回應與審計：
// reuse detection（家族撤銷）為高價值安全事件必須入審計；其餘失敗記失敗事件。
// 對外一律 401 同文案，不給攻擊者區分憑證狀態的訊號
func (h *AuthHandler) respondRefreshError(c *gin.Context, err error) {
	var reuse *identity.RefreshReuseError
	switch {
	case errors.As(err, &reuse):
		h.auditRefresh(c, reuse.UserID, reuse.Username,
			"refresh_reuse_detected; all refresh tokens revoked")
	case errors.Is(err, identity.ErrRefreshInvalid):
		h.auditRefresh(c, 0, "", "refresh_rejected")
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRefresh, err)
		return
	}
	apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSessionExpired, nil)
}

// auditRefresh 刷新失敗審計（公開端點無 middleware 用戶 context，handler 自記）
func (h *AuthHandler) auditRefresh(c *gin.Context, userID uint, username, errMsg string) {
	h.auditRefreshEvent(c, userID, username, model.StatusFailure, http.StatusUnauthorized, errMsg)
}

// auditRefreshEvent 刷新事件審計的**單一寫入點**（成功輪替與各類失敗共用）。
//
// 兩者共用同一個字面量是刻意的：分成兩份就會有兩處各自演化的欄位集，
// 而「成功列少填了來源位址」這種偏差不會讓任何測試轉紅。
// 事件性質以 status＋errMsg 標記區分（`refresh_rotated`／`refresh_rejected`／
// `refresh_reuse_detected`），沿用 `annotateAuthSource` 已確立的
// 「ErrorMsg 作為審計註記欄」慣例。
func (h *AuthHandler) auditRefreshEvent(c *gin.Context, userID uint, username string,
	status model.AuditStatus, statusCode int, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     model.ActionLogin,
		Resource:   model.ResourceAuth,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   h.auditSourceIP(c),
		StatusCode: statusCode,
		ErrorMsg:   errMsg,
	})
}

// Me 取得目前使用者資訊
func (h *AuthHandler) Me(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	userInfo, err := h.authService.GetUserByID(userID)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserInfoQuery, err)
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// UpdateMe 自助更新個人資料（profile-display-name R1/R2）。
// 身分綁定：target userID 只取自 token claims（GetCurrentUserID），不接受 path/body 指定他人；
// 僅放行 local_display_name（其他欄位不可經此寫入）；重查帳號 active 拒停用/刪除帳號；
// 審計歸類覆寫為 resource=user, resource_id=當前使用者（避免歸 resource=auth 無 id）
func (h *AuthHandler) UpdateMe(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}

	// 審計歸類覆寫（R2）：即使後續驗證失敗，本次自助更新一律歸 resource=user、
	// resource_id=當前使用者，避免落 resource=auth 無 id 的模糊審計
	c.Set("audit_resource", model.ResourceUser)
	c.Set("audit_resource_id", userID)

	// 需明確提供 local_display_name 欄位（profile-display-name R1）：缺欄的 body
	//（如惡意 body 只帶 full_name/role，或空 body {}）一律 400，避免「未帶欄位被解成
	// nil」意外清除既有顯示名；且結構上杜絕經此端點寫入其他欄位。
	// 欄位值：字串→設定；null 或空白→清除（寫回 NULL）
	var body map[string]json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	rawVal, ok := body["local_display_name"]
	if !ok {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var localDisplayName *string
	if err := json.Unmarshal(rawVal, &localDisplayName); err != nil {
		// 型別錯誤（給了數字/物件/布林）→ 400
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	userInfo, err := h.authService.UpdateOwnDisplayName(userID, localDisplayName)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidDisplayName):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDisplayName, nil)
		case errors.Is(err, identity.ErrUserInactive):
			apierror.Respond(c, http.StatusForbidden, apierror.CodeUserInactive, nil)
		case errors.Is(err, identity.ErrUserNotFound):
			// token 有效但帳號已刪除：視為會話失效，要求重新登入
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeSessionExpired, nil)
		default:
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUserUpdate, err)
		}
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// ChangePasswordRequest 自助改密請求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword 自助改密（auth-hardening D4/D11/D12）。
// 接受兩種 token：正式 session token（自願改密）或 password_change scoped token
// （強制改密流程）；userID 一律取自 token claims，不接受路徑參數（防改他人密碼）。
// 成功後直接換發正式 token（D12：不重走登入）
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	if h.userService == nil {
		apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeChangePasswordUnavailable, nil)
		return
	}

	// 來源濫用防護（auth-cost-based-concurrency 2.1）：**在解析 token 與 body 之前**，
	// 與登入端點同一條紀律——被擋下的請求不應付出任何解析成本。
	//
	// 本端點的每請求雜湊成本是登入的約 7 倍（預設組態）至約 27 倍（政策上界 24），
	// 而它原本**完全沒有併發上限**。
	// 觸發只需一個已通過認證的一般帳號——對堡壘機而言那正是被稽核的對象。
	if h.changePasswordGuard != nil {
		ip := h.changePasswordGuard.sourceIP(c)
		release, ok := h.changePasswordGuard.acquire(ip)
		if !ok {
			h.changePasswordGuard.record(changePasswordEventThrottled, ip)
			apierror.Respond(c, http.StatusTooManyRequests,
				apierror.CodeAuthChangePasswordRateLimited, nil)
			return
		}
		defer release()
	}

	claims, ok := h.authenticateChangePassword(c)
	if !ok {
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeChangePasswordFields, nil)
		return
	}

	if err := h.userService.SelfChangePassword(claims.UserID, req.OldPassword, req.NewPassword); err != nil {
		h.respondChangePasswordError(c, claims, err)
		return
	}

	h.auditPasswordChange(c, claims, model.StatusSuccess, http.StatusOK, "")

	// D12：改密成功直接換發正式 token，不重走登入。
	// 自 change token 繼承 method/provider（本次仍是同一條認證），但世代由
	// IssueSessionResponse 內部現查——改密會推進 credential_epoch，若沿用
	// change token 內的舊世代，換發的 token 立即失效、使用者永久卡在改密迴圈
	resp, err := h.authService.IssueSessionResponse(claims.UserID, claims.EffectiveMethod(), claims.ProviderID)
	if err != nil {
		log.Printf("[ERROR] change-password token issue failed: user=%s err=%v", claims.Username, err)
		apierror.Respond(c, http.StatusInternalServerError, apierror.CodeInternalChangePasswordTokenIssue, nil)
		return
	}
	// 發放端點 4／6：改密換發的正式會話
	h.refreshCookies.SetFromLogin(c, resp)
	c.JSON(http.StatusOK, resp)
}

// authenticateChangePassword 解析改密端點的 token：
// 正式 token（Scope 空）或 password_change scoped token，其餘 scope 一律拒
func (h *AuthHandler) authenticateChangePassword(c *gin.Context) (*crypto.Claims, bool) {
	authHeader := c.GetHeader("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeTokenMissing, nil)
		return nil, false
	}

	claims, err := h.authService.ValidateToken(parts[1])
	if err != nil {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeTokenInvalid, nil)
		return nil, false
	}
	if claims.Scope != "" && claims.Scope != crypto.ScopePasswordChange {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeTokenNotForPasswordChange, nil)
		return nil, false
	}
	return claims, true
}

// respondChangePasswordError 改密錯誤映射（政策違規回可讀訊息，內部錯誤泛化）
func (h *AuthHandler) respondChangePasswordError(c *gin.Context, claims *crypto.Claims, err error) {
	var violation *policy.PasswordPolicyViolation
	status := http.StatusBadRequest
	var code apierror.ErrCode
	var params map[string]any
	switch {
	case errors.As(err, &violation):
		// 政策違規訊息可直接回給使用者（code+params 由 service 綁定）
		code = violation.Code
		params = violation.Params
	case errors.Is(err, identity.ErrOldPasswordMismatch):
		code = apierror.CodeOldPasswordMismatch
	case errors.Is(err, identity.ErrExternalUserPassword):
		// **只設 code，不自行寫回應**（M3）：本 switch 的所有分支共用函式尾端的
		// 單一寫出點；分支內呼叫 apierror.Respond 而未 return 會讓回應被寫兩次，
		// 第二次帶零值 ErrCode 落入 unregistered 分支串接一段泛化訊息
		code = apierror.CodeExternalUserPassword
	case errors.Is(err, identity.ErrLDAPUserPassword):
		code = apierror.CodeLDAPUserPassword
	case errors.Is(err, identity.ErrUserNotFound):
		status = http.StatusNotFound
		code = apierror.CodeUserNotFound
	default:
		status = http.StatusInternalServerError
		log.Printf("[ERROR] change-password failed: user=%s err=%v", claims.Username, err)
	}
	h.auditPasswordChange(c, claims, model.StatusFailure, status, err.Error())
	if status >= http.StatusInternalServerError {
		apierror.Respond(c, status, apierror.CodeInternalChangePassword, nil)
		return
	}
	apierror.Respond(c, status, code, params)
}

// auditPasswordChange 自助改密審計（端點不經 AuthMiddleware，middleware 無用戶 context 會跳過）
func (h *AuthHandler) auditPasswordChange(c *gin.Context, claims *crypto.Claims, status model.AuditStatus, statusCode int, errMsg string) {
	if h.auditService == nil {
		return
	}
	userID := claims.UserID
	h.auditService.Log(&audit.AuditLogEntry{
		UserID:     userID,
		Username:   claims.Username,
		Action:     model.ActionUpdate,
		Resource:   model.ResourceUser,
		ResourceID: &userID,
		Status:     status,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		ClientIP:   h.auditSourceIP(c),
		StatusCode: statusCode,
		ErrorMsg:   annotateAuthSource(errMsg, "self_change_password"),
	})
}

// RegisterRoutes 註冊認證相關路由
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	auth := r.Group("/auth")
	{
		// 不需要認證的路由
		auth.POST("/login", h.Login)
		// MFA 第二階段為公開路由：pending token 由 request body 自帶並專用解析
		auth.POST("/mfa/verify", h.MFAVerify)
		// 自助改密：token 自行解析（接受正式 token 或 password_change scoped token，
		// 後者被 AuthMiddleware deny-by-default 擋下，不可掛一般中間件）
		auth.POST("/change-password", h.ChangePassword)
		// MFA 強制註冊：enrollment scoped token 自帶解析（同被 deny-by-default 擋下一般 API，
		// 故為公開路由，僅接受 ScopeMFAEnrollment）
		auth.POST("/mfa/enroll/setup", h.MFAEnrollSetup)
		auth.POST("/mfa/enroll/confirm", h.MFAEnrollConfirm)
		// 會話刷新（D6）：refresh 憑證由 httpOnly cookie 自帶，access 可能已過期故為公開路由
		auth.POST("/refresh", h.Refresh)

		// 需要認證的路由
		authenticated := auth.Group("")
		authenticated.Use(middleware.AuthMiddleware(authService))
		{
			authenticated.POST("/logout", h.Logout)
			authenticated.GET("/me", h.Me)
			// 自助更新個人資料（profile-display-name）：僅放行 local_display_name，
			// 身分綁定 token claims，AuthMiddleware 已擋 scoped token
			authenticated.PATCH("/me", h.UpdateMe)
			// POST 而非 GET：setup 有寫入副作用（覆蓋 pending secret、重設 enabled）
			authenticated.POST("/mfa/setup", h.MFASetup)
			authenticated.POST("/mfa/enable", h.MFAEnable)
			authenticated.POST("/mfa/disable", h.MFADisable)
		}
	}

	// 管理員救援路由：與 UserHandler 相同的 admin 限定模式
	adminUsers := r.Group("/users")
	adminUsers.Use(middleware.AuthMiddleware(authService))
	adminUsers.Use(middleware.RequireRole("admin"))
	{
		adminUsers.POST("/:id/mfa/disable", h.AdminDisableMFA)
	}
}
