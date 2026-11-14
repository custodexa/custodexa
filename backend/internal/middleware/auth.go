package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
)

// authRejectionContextKey 認證中介層拒絕標記。
//
// 值＝該次拒絕的 apierror 機器碼。審計中介層在「無身分」分支據此判斷這一次 401
// 是不是**認證中介層**判的：是的話補寫匿名失敗列，不是的話維持原本的跳過。
//
// **為何不是「凡 401 且無身分就補寫」**：`/auth/login` 密碼錯誤、`/auth/refresh`
// 壞票證、MFA 驗證失敗這些路徑同樣是「401 且 context 無身分」，但它們**已由
// handler 自寫審計列**。無差別補寫會讓同一次事件在 audit_logs 出現兩次，直接汙染
// 每日覆核的登入失敗計數——修一個缺口的同時製造一個計數缺陷
const authRejectionContextKey = "auth_rejection_code"

// abortUnauthenticated `internal/middleware` 全套件**唯一**的 401 出口。
//
// 除了回應與 abort，它在 gin context 留下拒絕標記，使審計中介層能在無身分的情況下
// 仍寫一筆匿名失敗列。**認證中介層本身不碰 auditService**：把審計服務注入認證
// 中介層會讓兩個關注點永久耦合，標記只是一個字串。
//
// **不得繞過**：本套件內任何 401 出口都必須走這裡。新增 abort 分支時漏掉標記＝漏掉
// 留痕，而那不會有任何行為測試轉紅，故由 `anonymous_rejection_audit_test.go` 的
// AST 守衛機械核對（`TestAuthMiddlewareHasSingle401Exit`）
//
// `auditReason` 可覆寫**審計側**的原因碼（省略即等於對外機器碼）。對外回應一律以
// `code` 為準——審計要能區分「曾經有效但過期」與「偽造」，對外則絕不能：後者等於
// 開出一個憑證存在性的探測面（與 /connect 拒絕原因的處置一致）
func abortUnauthenticated(c *gin.Context, code apierror.ErrCode, auditReason ...string) {
	reason := string(code)
	if len(auditReason) > 0 && auditReason[0] != "" {
		reason = auditReason[0]
	}
	c.Set(authRejectionContextKey, reason)
	apierror.Respond(c, http.StatusUnauthorized, code, nil)
	c.Abort()
}

// tokenRejectionAuditReason token 驗證失敗的審計側原因碼。
//
// 已到期是**例行事件**（access token 每 15 分鐘到期一次，前端自動 refresh），
// 與「無憑證」「簽章無效」這兩種真正的無效存取嘗試混為一談時，每日覆核的登入
// 失敗數會被正常流量淹沒（每日覆核的計數口徑據此排除本原因）。
//
// 判別來源是 `crypto.ValidateToken` 已經分出來的 sentinel（`ErrExpiredToken` vs
// `ErrInvalidToken`），不在此重解 jwt 錯誤——重解等於把同一個判斷寫兩份
func tokenRejectionAuditReason(err error) string {
	if errors.Is(err, crypto.ErrExpiredToken) {
		return model.AuditReasonTokenExpired
	}
	return ""
}

// AuthMiddleware 認證中間件。
// JWT 僅從 Authorization header 接受：
// 長效權杖入 URL query 會被 access log 與 proxy 日誌完整記錄。
// 專用短效機制不受影響：錄影播放 rtoken 與一次性 connect-token 各走
// 專屬驗證路徑，不經本 middleware 的 token 取值
func AuthMiddleware(authService *identity.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		// 僅從 Authorization header 取得 token
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			// 解析 Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				tokenString = parts[1]
			}
		}

		// 如果沒有提供 token
		if tokenString == "" {
			abortUnauthenticated(c, apierror.CodeTokenMissing)
			return
		}

		if strings.HasPrefix(tokenString, identity.AgentTokenPrefix) {
			if kind, _ := GetPrincipalKind(c); kind != model.KindAgent {
				if !authenticateAgent(c, authService, tokenString) {
					return
				}
			}
			c.Next()
			return
		}

		// API token 由全域閘門認證一次，這裡只沿用已建立的主體、不重驗；沒有經過閘門的 API token
		// 請求不落入人類 JWT 的驗證路徑，直接以未認證拒絕
		if strings.HasPrefix(tokenString, identity.APITokenPrefix) {
			if kind, ok := GetRequestCredential(c); ok && kind == model.RequestCredentialAPIToken {
				c.Next()
				return
			}
			abortUnauthenticated(c, apierror.CodeTokenInvalid, "api_token_gate_absent")
			return
		}

		// 驗證 token
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			// 對外仍是同一則 AUTH_TOKEN_INVALID（過期與偽造不可區分），
			// 審計側才分流
			abortUnauthenticated(c, apierror.CodeTokenInvalid, tokenRejectionAuditReason(err))
			return
		}

		// scoped token deny-by-default：任何帶 scope 的中繼 token
		//（MFA pending/改密/enrollment）一律不得存取一般 API，各 scoped 端點自行
		// 專用解析對應 scope——新增 scope 預設被擋，不需逐處補防
		if claims.Scope != "" {
			code := apierror.CodeScopedTokenDenied
			if claims.Scope == crypto.ScopeMFAPending {
				code = apierror.CodeMFAIncomplete
			}
			abortUnauthenticated(c, code)
			return
		}

		// 憑證世代閘：provider 停用/刪除/密鑰輪替，
		// 或使用者被停用/解綁外部身分/改為僅外部登入時，既簽的 access token 立即失效，
		// 不必等其自然到期。**授權欄位現查 DB**——落入行程快取會使多副本下的停用失效。
		if err := authService.VerifyCredentialGenerationByUserID(claims.AuthContext, claims.UserID); err != nil {
			abortUnauthenticated(c, apierror.CodeTokenInvalid)
			return
		}

		// 伺服器端解析主體：每個請求自資料庫現查有效指派與能力，不快取；
		// 授權判斷不讀 JWT 內的 role claim，也不再把它放進脈絡。解析失敗一律拒絕，
		// 不以 token 內的角色兜底。
		principal, err := authService.ResolvePrincipal(claims.UserID, authz.TokenFacts{
			SubjectKind: model.KindHuman,
			AuthMethod:  claims.AuthContext.EffectiveMethod(),
			CredEpoch:   claims.AuthContext.CredEpoch,
		})
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalRoleQuery, err)
			c.Abort()
			return
		}

		// 將使用者資訊存入 context
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		BindRequestPrincipal(c, principal, model.RequestCredentialHumanSession)
		// 認證脈絡：connect token 簽發點須據此填入 grant，
		// 使協議連線可回溯其 provider。**不得以「查外部身分表反推」代替**——
		// 混合帳號（同時有本地密碼與外部身分）會被誤標，導致 provider 停用時
		// 誤殺以本地密碼建立的連線
		c.Set("authContext", claims.AuthContext)
		c.Set("principal_kind", model.KindHuman)

		c.Next()
	}
}

// GetCurrentUserID 從 context 取得目前使用者 ID
func GetCurrentUserID(c *gin.Context) (uint, bool) {
	userID, exists := c.Get("userID")
	if !exists {
		return 0, false
	}
	return userID.(uint), true
}

// GetAuthContext 從 gin context 取得本次請求的認證脈絡。
//
// 簽發新的長效能力（連線授權、監看訂閱）時必須帶上它——脈絡在**簽發**階段取得
// 才有意義：兌換階段只剩 grant，已無從得知「當初是經哪個 provider 認證的」。
// 缺值（升級期舊 token／未經中介層的路徑）回零值脈絡，語義即本地登入
func GetAuthContext(c *gin.Context) crypto.AuthContext {
	v, exists := c.Get("authContext")
	if !exists {
		return crypto.AuthContext{}
	}
	ctx, ok := v.(crypto.AuthContext)
	if !ok {
		return crypto.AuthContext{}
	}
	return ctx
}

// GetCurrentUsername 從 context 取得目前使用者名稱
func GetCurrentUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get("username")
	if !exists {
		return "", false
	}
	return username.(string), true
}

// AbortControlAuthentication uses the shared anonymous-rejection audit marker.
// It does not retain the authentication service or create another token path.
func AbortControlAuthentication(c *gin.Context, code apierror.ErrCode) {
	abortUnauthenticated(c, code)
}

func GetPrincipalKind(c *gin.Context) (string, bool) {
	v, ok := c.Get("principal_kind")
	kind, typed := v.(string)
	return kind, ok && typed && (kind == model.KindHuman || kind == model.KindAgent)
}
func GetAgentTokenID(c *gin.Context) (uint, bool) {
	v, ok := c.Get("agent_token_id")
	id, typed := v.(uint)
	return id, ok && typed && id != 0
}

// RejectAgentTokenOnHumanPaths precedes even public/scoped authentication flows.
func RejectAgentTokenOnHumanPaths() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.GetHeader("Authorization"), "Bearer "+identity.AgentTokenPrefix) {
			apierror.Respond(c, http.StatusForbidden, apierror.CodeAuthAgentForbiddenRoute, nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

func authenticateAgent(c *gin.Context, auth *identity.AuthService, token string) bool {
	if auth == nil {
		abortUnauthenticated(c, apierror.CodeAuthAgentTokenInvalid, "agent_auth_unavailable")
		return false
	}
	principal, reason := auth.ValidateAgentToken(token, sourceip.Of(c))
	if principal == nil {
		abortUnauthenticated(c, apierror.CodeAuthAgentTokenInvalid, reason)
		return false
	}
	c.Set("principal_kind", model.KindAgent)
	c.Set("agent_token_id", principal.TokenID)
	c.Set("userID", principal.UserID)
	c.Set("username", principal.Username)
	c.Set("email", principal.Email)
	// agent 主體：能力固定為一般使用者範本（method＋path allowlist 由既有中介層處理）
	BindRequestPrincipal(c, authz.NewPrincipal(principal.UserID, authz.TokenFacts{
		SubjectKind: model.KindAgent,
		CredEpoch:   principal.CredentialEpoch,
	}, nil), model.RequestCredentialAgentKey)
	// Agent tokens carry no claims, so the auth context is built from the live row:
	// local method (no provider dimension) and the principal's current credential
	// epoch. Without this, connect grants were issued with CredEpoch 0 and the
	// redemption recheck rejected every agent whose epoch had ever been bumped.
	c.Set("authContext", crypto.AuthContext{CredEpoch: principal.CredentialEpoch})
	return true
}

// GetAPITokenID 以 API token 認證的請求所經由的 token 識別；其他請求回 (0, false)。
func GetAPITokenID(c *gin.Context) (uint, bool) {
	if kind, ok := GetRequestCredential(c); !ok || kind != model.RequestCredentialAPIToken {
		return 0, false
	}
	v, ok := c.Get(apiTokenIDContextKey)
	id, typed := v.(uint)
	return id, ok && typed && id != 0
}

// GetAPITokenName 以 API token 認證的請求所經由的 token 在認證當下的名稱；其他請求回 ("", false)。
func GetAPITokenName(c *gin.Context) (string, bool) {
	if _, ok := GetAPITokenID(c); !ok {
		return "", false
	}
	v, ok := c.Get(apiTokenNameContextKey)
	name, typed := v.(string)
	return name, ok && typed && name != ""
}

// APITokenRefOf 以 API token 認證的請求所經由的 token（識別與名稱快照）；其他請求回零值。
func APITokenRefOf(c *gin.Context) model.APITokenRef {
	id, ok := GetAPITokenID(c)
	if !ok {
		return model.APITokenRef{}
	}
	name, ok := GetAPITokenName(c)
	if !ok {
		return model.APITokenRef{}
	}
	return model.APITokenRef{ID: id, Name: name}
}

// AttributeAuditEntry 在 handler 自組的稽核條目上補這次請求經由的 API token；其他請求不動。
func AttributeAuditEntry(c *gin.Context, e *audit.AuditLogEntry) *audit.AuditLogEntry {
	if e == nil || e.APITokenID != nil {
		return e
	}
	if ref := APITokenRefOf(c); ref.ID != 0 {
		id := ref.ID
		e.APITokenID, e.APITokenName = &id, ref.Name
	}
	return e
}

// AttributeAuditMeta 在 handler 自組的請求欄位上補這次請求經由的 API token；其他請求不動。
func AttributeAuditMeta(c *gin.Context, m gatewayapi.RequestMeta) gatewayapi.RequestMeta {
	ref := APITokenRefOf(c)
	return m.WithAPIToken(ref.ID, ref.Name)
}

// gin 脈絡中 API token 的識別與名稱快照鍵。
const (
	apiTokenIDContextKey   = "api_token_id"
	apiTokenNameContextKey = "api_token_name"
)

// authenticateAPIToken API token 的認證：現查 token、所屬帳號與來源，以授權角色為限定解析請求主體。
//
// 任何失敗都經唯一的未認證出口回同一個錯誤碼，真實原因只進稽核；全部步驟成功之前不在 gin 脈絡或
// request context 留下任何身分（含已撤銷的 token），失敗請求因此走匿名留痕的有限流分支。
// 授權角色即使為空集合也以非 nil 的限定傳入：限定為無與未限定是兩種不同的輸入。
func authenticateAPIToken(c *gin.Context, auth *identity.AuthService, token string) bool {
	if auth == nil {
		abortUnauthenticated(c, apierror.CodeTokenInvalid, "api_token_auth_unavailable")
		return false
	}
	id, reason := auth.ValidateAPIToken(token, sourceip.Of(c))
	if id == nil {
		abortUnauthenticated(c, apierror.CodeTokenInvalid, reason)
		return false
	}
	principal, err := auth.ResolvePrincipal(id.UserID, authz.TokenFacts{
		SubjectKind: model.KindHuman,
		AuthMethod:  identity.APITokenAuthMethod,
		CredEpoch:   id.CredentialEpoch,
		RoleFilter:  authz.NewRoleFilter(id.GrantedRoleIDs),
	})
	if err != nil || principal == nil {
		abortUnauthenticated(c, apierror.CodeTokenInvalid, "api_token_principal_unavailable")
		return false
	}
	c.Set("principal_kind", model.KindHuman)
	c.Set(apiTokenIDContextKey, id.TokenID)
	c.Set(apiTokenNameContextKey, id.TokenName)
	c.Set("userID", id.UserID)
	c.Set("username", id.Username)
	c.Set("email", id.Email)
	BindRequestPrincipal(c, principal, model.RequestCredentialAPIToken)
	if c.Request != nil {
		c.Request = c.Request.WithContext(model.WithAPITokenRef(c.Request.Context(), model.APITokenRef{ID: id.TokenID, Name: id.TokenName}))
	}
	// 認證脈絡：本地方法（不經外部身分來源）與所屬帳號當下的憑證世代，與 agent 鑰匙同一做法
	c.Set("authContext", crypto.AuthContext{CredEpoch: id.CredentialEpoch})
	return true
}
