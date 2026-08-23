package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/custodexa/backend/internal/modules/identity"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
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

		// 將使用者資訊存入 context
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("role", claims.Role)
		// 認證脈絡：connect token 簽發點須據此填入 grant，
		// 使協議連線可回溯其 provider。**不得以「查外部身分表反推」代替**——
		// 混合帳號（同時有本地密碼與外部身分）會被誤標，導致 provider 停用時
		// 誤殺以本地密碼建立的連線
		c.Set("authContext", claims.AuthContext)

		c.Next()
	}
}

// RequireRole 要求特定角色的中間件（簡化版本，直接使用 context 中的角色）
func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 獲取用戶角色（由 AuthMiddleware 設定）
		role, exists := c.Get("role")
		if !exists {
			abortUnauthenticated(c, apierror.CodeUnauthenticated)
			return
		}

		roleStr, ok := role.(string)
		if !ok || roleStr != requiredRole {
			apierror.Respond(c, http.StatusForbidden, apierror.CodeRoleRequired, map[string]any{"role": requiredRole})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole 要求「屬於清單中任一角色」的中間件（audit-checkpoint-chain O3）。
//
// **為何是中間件而非 handler 內檢查**：本專案的路由 golden 逐格記錄每條路由的
// 中間件鏈，授權寫在鏈上時「這條路由由誰守」是 golden 可觀察的事實；搬進
// handler 函式體後，golden 只會看到鏈短了一格，日後有人不慎移除檢查也不會有
// 任何守衛轉紅。既有 admin-or-auditor 的 handler 內檢查（asset_handler.go）
// 是既存形態，本函式不回頭改寫它們，但新面一律走這裡。
//
// 錯誤碼沿用 CodeRoleRequired，param 取清單首項（語義＝「至少需要這個層級」），
// 避免為多角色另立一碼而使前端需要處理兩種形狀
func RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			abortUnauthenticated(c, apierror.CodeUnauthenticated)
			return
		}
		roleStr, ok := role.(string)
		if ok {
			for _, allowed := range roles {
				if roleStr == allowed {
					c.Next()
					return
				}
			}
		}
		want := ""
		if len(roles) > 0 {
			want = roles[0]
		}
		apierror.Respond(c, http.StatusForbidden, apierror.CodeRoleRequired, map[string]any{"role": want})
		c.Abort()
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
