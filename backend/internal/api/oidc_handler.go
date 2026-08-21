package api

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// OIDCHandler OIDC provider 管理與登入流程端點（idp-oidc-integration）
type OIDCHandler struct {
	providers *identity.OIDCProviderService
	login     *identity.OIDCLoginService
	frontend  string // 對外基準網址，用於 callback 導回 SPA
	// audit 登入流程的審計出口。**留痕在 handler 而非 service**
	//（audit-coverage-closure D3 前置）：service 拿不到 *gin.Context，其寫出的列
	// 來源位址／路徑／方法／狀態碼必然全空，稽核無從判讀「誰從哪裡打了什麼」。
	// nil 時不留痕（與 AuthHandler 的 auditService 同慣例）
	audit *audit.AuditLogService

	// 三個公開端點各持一組限流器（3.7a）。**不共用**：共用時 callback 的洪水
	// 會連帶用光 exchange 的全域額度，使正在登入的正當使用者卡在最後一步——
	// 攻擊者因此得到一個比「打爆 DB」更廉價的可用性攻擊
	beginGuard    *sourceAbuseGuard
	callbackGuard *sourceAbuseGuard
	exchangeGuard *sourceAbuseGuard

	// refreshCookies refresh 憑證的 httpOnly cookie 下發（refresh-token-httponly-cookie）。
	// nil 安全：視為非 Secure，功能不斷
	refreshCookies *RefreshCookieWriter
}

// 聚合審計的事件鍵。命名對齊審計既有慣例（動作_結果），並保留端點區分——
// 「哪個端點被打」是處置時的第一個問題
const (
	oidcEventBeginThrottled       = "oidc_begin_throttled"
	oidcEventCallbackThrottled    = "oidc_callback_throttled"
	oidcEventCallbackStateInvalid = "oidc_callback_state_invalid"
	oidcEventExchangeThrottled    = "oidc_exchange_throttled"
	oidcEventExchangeTicketInvlid = "oidc_exchange_ticket_invalid"
)

// oidcAggregateStatus 聚合列的審計狀態（audit-coverage-closure D3 分流）。
//
// 兩類事件語義不同，不可一刀切：無效的 state／ticket 是**憑證不成立**的認證失敗
// （`failure`）；被限流擋下的請求是**政策拒絕**（`denied`，與 RBAC 403 同語義）。
// 對照表放在事件常數旁邊——放進 service 層即成為兩份會各自演化的副本
func oidcAggregateStatus(event string) model.AuditStatus {
	switch event {
	case oidcEventCallbackStateInvalid, oidcEventExchangeTicketInvlid:
		return model.StatusFailure
	default:
		return model.StatusDenied
	}
}

// NewOIDCHandler 建立 handler。
//
// 可信代理是否設定於此判定一次（部署期常數，不逐請求重讀）：未設定時
// 限流鍵一律取 socket peer IP，見 sourceAbuseGuard.sourceIP
func NewOIDCHandler(providers *identity.OIDCProviderService, login *identity.OIDCLoginService,
	baseURL string, auditService *audit.AuditLogService) *OIDCHandler {
	trustProxy := config.LoadSeal().TrustedProxyConfigured()
	// 具型別的 nil 指標存入介面欄位會使 sink != nil 成立而在呼叫時 panic
	var sink sourceAbuseAuditSink
	if login != nil {
		sink = login
	}
	return &OIDCHandler{
		providers:     providers,
		login:         login,
		frontend:      strings.TrimRight(baseURL, "/"),
		audit:         auditService,
		beginGuard:     newSourceAbuseGuard(defaultOIDCGuardParams(), trustProxy, sink),
		callbackGuard:  newSourceAbuseGuard(defaultOIDCGuardParams(), trustProxy, sink),
		exchangeGuard:  newSourceAbuseGuard(defaultOIDCGuardParams(), trustProxy, sink),
		refreshCookies: defaultRefreshCookieWriter(),
	}
}

// SetRefreshCookieWriter 注入共用的 refresh cookie writer（cmd/server 接線）
func (h *OIDCHandler) SetRefreshCookieWriter(w *RefreshCookieWriter) {
	h.refreshCookies = w
}

// throttle 限流前置：通過時回傳來源 IP 與釋放函式，未通過時已寫好 429 回應。
//
// 回應**不洩漏限流參數**（無 Retry-After、無剩餘額度）：那些數值會讓攻擊者
// 精確地把流量調到門檻之下持續消耗，而正當使用者只需要「稍後再試」
func (h *OIDCHandler) throttle(c *gin.Context, g *sourceAbuseGuard, event string) (string, func(), bool) {
	ip := g.sourceIP(c)
	release, ok := g.acquire(ip)
	if !ok {
		g.record(event, ip)
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeAuthOIDCRateLimited, nil)
		return ip, nil, false
	}
	return ip, release, true
}

// RegisterRoutes 註冊路由。
//
// 管理端（admin only）與登入流程（公開）分兩組——後者必須公開，因為使用者
// 尚未登入即需取得登入方法清單並發起流程
func (h *OIDCHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	admin := r.Group("/oidc-providers")
	admin.Use(middleware.AuthMiddleware(authService))
	admin.Use(middleware.RequireRole("admin"))
	{
		admin.GET("", h.List)
		admin.POST("", h.Create)
		admin.PUT("/:id", h.Update)
		admin.DELETE("/:id", h.Delete)
	}

	// 登入流程：公開端點（未認證可達）
	r.GET("/auth/methods", h.LoginMethods)
	r.GET("/auth/oidc/:id/begin", h.Begin)
	r.GET("/auth/oidc/callback", h.Callback)
	r.POST("/auth/oidc/exchange", h.Exchange)
}

// List 列出全部 provider（回應不含 client_secret 的任何形式）
func (h *OIDCHandler) List(c *gin.Context) {
	rows, err := h.providers.List()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOIDCProviderList, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// Create 建立 provider
func (h *OIDCHandler) Create(c *gin.Context) {
	var req identity.OIDCProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCProviderPayload, nil)
		return
	}
	dto, err := h.providers.Create(&req)
	if err != nil {
		h.respondProviderError(c, err)
		return
	}
	c.JSON(http.StatusCreated, dto)
}

// Update 更新 provider（issuer/client_id 不可變由 service 強制）
func (h *OIDCHandler) Update(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	var req identity.OIDCProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCProviderPayload, nil)
		return
	}
	dto, err := h.providers.Update(id, &req)
	if err != nil {
		h.respondProviderError(c, err)
		return
	}
	c.JSON(http.StatusOK, dto)
}

// Delete 刪除 provider（有身分關聯者回 409）
func (h *OIDCHandler) Delete(c *gin.Context) {
	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	if err := h.providers.Delete(id); err != nil {
		h.respondProviderError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// LoginMethods 登入方法清單（**未認證可讀**）。
//
// 只回識別與顯示所需欄位——不含 issuer/client_id 等設定值。停用者與設定不完整者
// 皆不列出（否則按鈕看得到、按下去必失敗）
func (h *OIDCHandler) LoginMethods(c *gin.Context) {
	methods, err := h.providers.ListLoginMethods()
	if err != nil {
		// 清單失敗不得阻斷登入頁：前端會降級為只顯示本地表單
		log.Printf("[OIDC] 讀取登入方法清單失敗: %v", err)
		c.JSON(http.StatusOK, gin.H{"local": true, "oidc": []identity.LoginMethod{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"local": true, "oidc": methods})
}

// Begin 發起 OIDC 登入（302 至 IdP）。
//
// binding 為前端產生並存於 sessionStorage 的隨機值，此處只收其雜湊——
// 它使流程與發起的瀏覽器綁定，防 login CSRF（攻擊者以自己的帳號完成授權後
// 把 callback URL 交給受害者）
func (h *OIDCHandler) Begin(c *gin.Context) {
	_, release, ok := h.throttle(c, h.beginGuard, oidcEventBeginThrottled)
	if !ok {
		return
	}
	defer release()

	id, ok := parseUintParam(c, "id")
	if !ok {
		return
	}
	bindingHash := strings.TrimSpace(c.Query("binding"))
	// 形狀須為 SHA256 十六進位：只驗非空會讓任意字串（含 SHA256("") 這種
	// 可被空 secret 滿足的值）成為合法綁定。真正的防線在 exchange 拒絕空 secret，
	// 此處是同一問題的前段收口——不合形狀的綁定值根本不該進入流程狀態
	if !isSHA256Hex(bindingHash) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCBindingMissing, nil)
		return
	}
	next := sanitizeRedirectNext(c.Query("next"))

	res, err := h.login.Begin(c.Request.Context(), id, bindingHash, next)
	if err != nil {
		h.respondLoginError(c, err)
		return
	}
	c.Redirect(http.StatusFound, res.AuthorizationURL)
}

// Callback IdP 回呼：完成驗證後以 **fragment** 交棒給 SPA。
//
// 用 fragment 而非 query：query 會完整送到反向代理與其 access log，fragment 不送伺服器。
// 另設 no-referrer 與 no-store，避免憑證經 Referer 或快取外洩
func (h *OIDCHandler) Callback(c *gin.Context) {
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Cache-Control", "no-store")

	// 限流在一切之前：本端點的 state 查找失敗**不必接觸 IdP、不受 flow state
	// 容量限制**，是全流程最便宜的洪水面（design D13 / codex HIGH-1）
	ip, release, ok := h.throttle(c, h.callbackGuard, oidcEventCallbackThrottled)
	if !ok {
		return
	}
	defer release()

	if errParam := c.Query("error"); errParam != "" {
		h.redirectToLogin(c, "oidc_provider_error")
		return
	}
	state := c.Query("state")
	code := c.Query("code")
	if state == "" || code == "" {
		h.callbackGuard.record(oidcEventCallbackStateInvalid, ip)
		h.redirectToLogin(c, "oidc_flow_invalid")
		return
	}

	res, err := h.login.Callback(c.Request.Context(), state, code)
	if err != nil {
		// state 查找階段的失敗走聚合（可被無成本大量製造）；其後各階段的失敗
		// **必然消耗過一個合法 flow state**，其筆數受全表容量上限約束，
		// 故逐筆落審計，不重複計入聚合
		if errors.Is(err, identity.ErrOIDCFlowStateNotFound) {
			h.callbackGuard.record(oidcEventCallbackStateInvalid, ip)
		}
		// callback 一律以 302 導回登入頁（成功與失敗皆然），故狀態碼取 Found
		h.writeOIDCAudit(c, identity.OIDCAuditEventsOf(err), http.StatusFound)
		h.redirectToLogin(c, oidcErrorSlug(err))
		return
	}

	// 成功路徑亦可能帶事件（JIT 首登建帳號）
	h.writeOIDCAudit(c, res.AuditEvents, http.StatusFound)
	target := h.frontend + "/login#sso_ticket=" + url.QueryEscape(res.Ticket)
	c.Redirect(http.StatusFound, target)
}

// Exchange 以交棒憑證換取正式登入回應（與 /auth/login 同形，含 MFA 分支）
func (h *OIDCHandler) Exchange(c *gin.Context) {
	// 限流置於解析請求體之前：隨機 ticket 的洪水要擋在觸及 DB 之前才有意義
	ip, release, ok := h.throttle(c, h.exchangeGuard, oidcEventExchangeThrottled)
	if !ok {
		return
	}
	defer release()

	var req struct {
		Ticket        string `json:"ticket" binding:"required"`
		BrowserSecret string `json:"browser_secret"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCTicketMissing, nil)
		return
	}
	resp, next, err := h.login.Exchange(req.Ticket, req.BrowserSecret)
	if err != nil {
		// 憑證無效（不存在／已消費／過期／綁定不符）同屬可大量製造的失敗，走聚合
		if errors.Is(err, identity.ErrOIDCTicketInvalid) {
			h.exchangeGuard.record(oidcEventExchangeTicketInvlid, ip)
		}
		h.respondLoginError(c, err)
		return
	}
	h.auditOIDCLogin(c, resp)
	// 發放端點 5／6（refresh-token-httponly-cookie 決策 3）：**巢狀回應是六者中最易漏的一個**。
	// `LoginResponse.RefreshToken` 已是 `json:"-"`，故 `gin.H{"login": resp}` 這條
	// 序列化路徑不會帶出明文；憑證改由此處的 cookie 下發。
	// MFA／強制註冊／強制改密分支尚未發出正式會話，SetFromLogin 對其零動作
	h.refreshCookies.SetFromLogin(c, resp)
	c.JSON(http.StatusOK, gin.H{"login": resp, "redirect_next": next})
}

// auditOIDCLogin 交換成功的登入留痕（比照 auth_handler.go 的 auditLogin）。
//
// **正式會話與待驗證階段各記一次、不重疊**：MFA 或強制註冊分支此刻尚未發出正式
// 會話，只記待驗證（`mfa_pending`／`mfa_enrollment_required`），正式會話的成功列
// 由 MFA 完成點寫出。兩處都記成功登入會使「一次登入」在稽核上看起來像兩次
func (h *OIDCHandler) auditOIDCLogin(c *gin.Context, resp *identity.LoginResponse) {
	stage := ""
	userID, username := resp.PendingUserID, resp.PendingUsername
	switch {
	case resp.MFARequired:
		stage = "mfa_pending"
	case resp.MFAEnrollmentRequired:
		stage = "mfa_enrollment_required"
	case resp.PasswordChangeRequired:
		stage = "password_change_required"
	default:
		userID, username = resp.User.ID, resp.User.Username
	}
	h.writeOIDCAudit(c, []identity.OIDCAuditEvent{{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusSuccess,
		UserID: userID, Username: username,
		Details: map[string]any{
			"event": "oidc_login", "stage": stage,
			"provider_id": resp.AuthProviderID, "provider_name": resp.AuthProviderName,
			"auth_method": resp.AuthSource,
		},
	}}, http.StatusOK)
}

// writeOIDCAudit 落地 service 交回的審計意向，補上**只有此處才有**的請求脈絡。
//
// 認證方式與 provider 一律以 ErrorMsg 附註（`annotateAuthSource` 既有慣例，
// 使 SSO 登入在既有審計視圖上與本地登入可直接區分），細節同時進 Details
func (h *OIDCHandler) writeOIDCAudit(c *gin.Context, events []identity.OIDCAuditEvent, statusCode int) {
	if h.audit == nil {
		return
	}
	for _, ev := range events {
		h.audit.Log(&audit.AuditLogEntry{
			UserID:     ev.UserID,
			Username:   ev.Username,
			Action:     ev.Action,
			Resource:   ev.Resource,
			ResourceID: ev.ResourceID,
			Status:     ev.Status,
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			ClientIP:   h.auditSourceIP(c),
			StatusCode: statusCode,
			ErrorMsg:   annotateAuthSource(oidcAuditReason(ev.Details), crypto.AuthMethodOIDC),
			Details:    ev.DetailsJSON(),
		})
	}
}

// auditSourceIP 審計列的來源位址，與限流鍵同一條紀律（spec：未設定可信代理時
// SHALL 取自連線對端、SHALL NOT 採信轉送標頭）。
//
// 這裡若圖方便用 `c.ClientIP()`，未設 SEAL/TRUSTED_PROXIES 的部署下 gin 會信任
// 任意 `X-Forwarded-For`——攻擊者可為自己那筆**成功登入列**指定任何來源位址，
// 稽核追人時追到的是他挑的那個 IP
func (h *OIDCHandler) auditSourceIP(c *gin.Context) string {
	if h.callbackGuard != nil {
		return h.callbackGuard.sourceIP(c)
	}
	// 未經 NewOIDCHandler 建構（僅測試路徑）：無可信代理約定可讀，
	// 一律走不採信轉送標頭的那一支——預設方向與生產一致
	return requestSourceIP(c, false)
}

// oidcAuditReason 取事件名作為 ErrorMsg 的前半（機器可讀，不新造散文字串）
func oidcAuditReason(details map[string]any) string {
	ev, _ := details["event"].(string)
	if reason, ok := details["reason"].(string); ok && reason != "" {
		return ev + ":" + reason
	}
	if stage, ok := details["stage"].(string); ok && stage != "" {
		return ev + ":" + stage
	}
	return ev
}

// redirectToLogin 失敗時導回登入頁並附機器可讀的原因 slug（前端據此顯示可行動訊息）
func (h *OIDCHandler) redirectToLogin(c *gin.Context, slug string) {
	c.Redirect(http.StatusFound, h.frontend+"/login#sso_error="+url.QueryEscape(slug))
}

// oidcErrorSlug 失敗成因對外收斂為兩類（不洩漏 IdP 內部狀態）
func oidcErrorSlug(err error) string {
	switch {
	case errors.Is(err, identity.ErrOIDCAdmissionDenied):
		return "oidc_admission_denied"
	case errors.Is(err, identity.ErrOIDCUsernameConflict):
		return "oidc_username_conflict"
	case errors.Is(err, identity.ErrOIDCProviderUnavailable):
		return "oidc_provider_unavailable"
	default:
		return "oidc_flow_invalid"
	}
}

// sanitizeRedirectNext 登入後導向目標的白名單化（防開放重導向）。
//
// 只接受同源相對路徑；scheme-relative（//evil）、絕對 URL、反斜線與多重編碼
// 一律拒絕並退回預設路徑
func sanitizeRedirectNext(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "/"
	}
	// PathUnescape 而非 QueryUnescape：後者會把 `+` 解為空白，
	// 使 `/sessions/a+b` 被竄改成 `/sessions/a b`（第一段仍合法故不會被拒，
	// 但回傳的已不是使用者要去的地方）
	if decoded, err := url.PathUnescape(s); err == nil {
		s = decoded
	}
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.Contains(s, "\\") {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	if len(s) > 255 {
		return "/"
	}
	// **dot-segment 一律拒絕**（codex）：枚舉只看第一段，而 `/dashboard/../../api/v1/users`
	// 的第一段是合法的 `dashboard`，瀏覽器卻會正規化成 `/api/v1/users`——
	// 不擋則枚舉可被任意包裝繞過。逐段比對而非事後正規化：正規化後再判定會讓
	// 「看起來合法、實際導向他處」的字串通過，此處要的是連形式都不接受
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return "/"
		}
	}
	// 路由枚舉比對（design 第 122 行）：同源相對路徑之外，第一段須為前端既有路由。
	// 以 u.Path 判定而非原字串——查詢字串與片段不參與路由匹配
	if !isAllowedRedirectRoute(u.Path) {
		return "/"
	}
	return s
}

func (h *OIDCHandler) respondProviderError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, identity.ErrOIDCProviderNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeNotFoundOIDCProvider, nil)
	case errors.Is(err, identity.ErrOIDCImmutableField):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCImmutableField, nil)
	case errors.Is(err, identity.ErrOIDCProviderInUse):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictOIDCProviderInUse, nil)
	case errors.Is(err, identity.ErrOIDCDuplicateIdentityDomain):
		apierror.Respond(c, http.StatusConflict, apierror.CodeConflictOIDCIdentityDomain, nil)
	case errors.Is(err, identity.ErrOIDCUnknownScope):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCScope, nil)
	case errors.Is(err, identity.ErrOIDCIssuerScheme), errors.Is(err, identity.ErrOIDCIssuerShape):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCIssuer, nil)
	case errors.Is(err, identity.ErrOIDCSharedCannotWiden):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCSharedWiden, nil)
	case errors.Is(err, identity.ErrAdmissionEmptyRuleSet),
		errors.Is(err, identity.ErrAdmissionSharedNeedsOrgRule),
		errors.Is(err, identity.ErrAdmissionConsumerTenant),
		errors.Is(err, identity.ErrAdmissionEmailNeedsVerified),
		errors.Is(err, identity.ErrAdmissionUnknownRule):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCAdmissionRules, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOIDCProviderSave, err)
	}
}

func (h *OIDCHandler) respondLoginError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, identity.ErrOIDCProviderUnavailable), errors.Is(err, identity.ErrOIDCProviderNotFound):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAuthOIDCProviderUnavailable, nil)
	case errors.Is(err, identity.ErrOIDCAdmissionDenied):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeAuthOIDCAdmissionDenied, nil)
	case errors.Is(err, identity.ErrOIDCUsernameConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAuthOIDCUsernameConflict, nil)
	case errors.Is(err, identity.ErrOIDCFlowCapacity):
		// 全表容量上限：對外與限流同碼同狀態——兩者對使用者的意義相同
		//（稍後再試），且不透露系統目前的儲存佔用
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeAuthOIDCRateLimited, nil)
	case errors.Is(err, identity.ErrOIDCTicketInvalid), errors.Is(err, identity.ErrOIDCFlowInvalid):
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeAuthOIDCFlowInvalid, nil)
	case errors.Is(err, identity.ErrUserInactive):
		apierror.Respond(c, http.StatusForbidden, apierror.CodeUserInactive, nil)
	case errors.Is(err, identity.ErrAccountLocked):
		apierror.Respond(c, http.StatusLocked, apierror.CodeAccountLocked, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalOIDCLogin, err)
	}
}

// parseUintParam 路徑參數解析（共用）
func parseUintParam(c *gin.Context, name string) (uint, bool) {
	v, err := strconv.ParseUint(c.Param(name), 10, 32)
	if err != nil || v == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeValidationOIDCProviderID, nil)
		return 0, false
	}
	return uint(v), true
}
