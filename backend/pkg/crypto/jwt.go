package crypto

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ScopeMFAPending MFA 兩階段登入的中繼 token scope：
// 僅 /auth/mfa/verify 接受，一般 API 的 AuthMiddleware 必須拒絕
const ScopeMFAPending = "mfa_pending"

// ScopePasswordChange 強制改密的中繼 token scope（auth-hardening D4）：
// 僅 /auth/change-password 接受。middleware 與 WS 連線端點對任何非空 scope
// 一律 deny-by-default，新增 scope 不需逐處放行
const ScopePasswordChange = "password_change"

// ScopeMFAEnrollment MFA 強制註冊的中繼 token scope（auth-hardening D5）：
// 受強制但未註冊 TOTP 者通過密碼驗證後取得，僅可打 TOTP setup/confirm 端點；
// 綁定完成後直接換發正式 token。同樣受 deny-by-default 保護
const ScopeMFAEnrollment = "mfa_enrollment"

// tokenIssuer 本系統簽發者標識。簽發（generateSessionToken/GenerateScopedToken）
// 與驗證（ValidateToken 的 WithIssuer）共用此常數——兩處若各寫各的字面值，
// 改動其一即讓全體既有 token 當場失效而無編譯訊號
// 不引用 internal/branding.Slug 的理由同 codec.go 的 aadNamespace。
const tokenIssuer = "custodexa"

// 認證方式（AuthContext.AuthMethod 值域，idp-oidc-integration D6）
const (
	// AuthMethodLocalPassword 以本地密碼認證；密碼類 gate 僅對此方式適用
	AuthMethodLocalPassword = "local_password"
	// AuthMethodLDAP 以目錄憑證認證
	AuthMethodLDAP = "ldap"
	// AuthMethodOIDC 經 OIDC 身分提供者認證
	AuthMethodOIDC = "oidc"
)

// AuthContext 本次認證的脈絡，隨憑證全鏈傳遞（access/scoped token、refresh 憑證、
// connect grant、login ticket、協議會話、唯讀訂閱）。
//
// 用途有三：(1) 決定密碼類 gate 是否適用——依「本次怎麼登入的」而非帳號屬性，
// 混合帳號（同時有本地密碼與外部身分）才能兩條路徑各依其性質判定；
// (2) provider 停用時精確界定撤銷範圍——以「該會話由哪個 provider 建立」判定，
// 僅看帳號供應來源會使事後綁定的本地帳號漏撤銷、綁多 provider 者被過度撤銷；
// (3) 審計標註。
//
// 世代兩維（AuthEpoch/CredEpoch）於每個驗證點並列比對，缺一即留下該類憑證的
// 復活窗口。零值語義：ProviderID=0 表本地/LDAP 登入（不受任何 provider 停用影響）；
// 世代 0 與 DB default 一致，故升級期既有 token 天然相容——切勿改用指標或哨兵值，
// 那會使全體既有 token 被判為不符而 401。
type AuthContext struct {
	AuthMethod string `json:"auth_method,omitempty"`
	ProviderID uint   `json:"provider_id,omitempty"`
	AuthEpoch  int    `json:"auth_epoch,omitempty"`
	CredEpoch  int    `json:"cred_epoch,omitempty"`
}

// EffectiveMethod 取本次認證方式；**缺值一律視為本地密碼**。
//
// 這是 fail-secure 的方向：缺值出現在升級期簽發的舊 token 與未顯式帶脈絡的
// 呼叫點，若視為「非本地密碼」，密碼類 gate（強制改密、政策合規、有效期）
// 會對這些 token 靜默失效。判定務必經此方法，不可直接比對 AuthMethod 欄位。
func (a AuthContext) EffectiveMethod() string {
	if a.AuthMethod == "" {
		return AuthMethodLocalPassword
	}
	return a.AuthMethod
}

// Claims JWT 聲明結構
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`            // 主要角色（admin/user/auditor）
	Scope    string `json:"scope,omitempty"` // 用途限定（空值 = 正式 session token）

	// AuthContext 認證脈絡；缺值（升級期舊 token）視為 local_password，
	// 與 IsExternal() 的雙條件判定合起來 fail-secure：密碼 gate 需
	// 「本次是本地密碼」且「帳號非外部」兩者皆成立才套用，任一訊號缺失都不會
	// 使 gate 靜默失效
	AuthContext
	jwt.RegisteredClaims
}

var (
	// ErrInvalidToken token 無效
	ErrInvalidToken = errors.New("無效的 token")
	// ErrExpiredToken token 已過期
	ErrExpiredToken = errors.New("token 已過期")
)

// JWTManager JWT 管理器
type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
}

// NewJWTManager 建立 JWT 管理器
func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		tokenDuration: tokenDuration,
	}
}

// GenerateToken 生成正式 session token。
//
// authCtx 為必要參數而非可選：漏帶脈絡的 token 對 provider 停用與使用者憑證世代
// 免疫（其 ProviderID=0 會被視為本地登入而放行），且不會有任何編譯或測試訊號。
// 以結構型別傳遞而非平鋪參數，可使傳錯位置成為編譯期錯誤。
func (m *JWTManager) GenerateToken(userID uint, username, email, role string, authCtx AuthContext) (string, error) {
	return m.generateSessionToken(userID, username, email, role, authCtx, time.Time{})
}

// GenerateTokenNotAfter 同 GenerateToken，但到期時間以 notAfter 為絕對上限
// （取 min(now+TTL, notAfter)）。refresh 換發必經此方法：access token 經 WS
// `?token=` 旁路足以開新協議連線，若到期可越過會話絕對期限，等於絕對壽命
// 可被「期限前最後一次刷新」繞過一個 TTL 窗口。notAfter 已過即拒發（fail-close，
// 呼叫端的有效性檢查先行，走到這裡代表狀態競走）。
func (m *JWTManager) GenerateTokenNotAfter(userID uint, username, email, role string, authCtx AuthContext, notAfter time.Time) (string, error) {
	if !notAfter.After(time.Now()) {
		return "", fmt.Errorf("會話絕對期限已過，不得換發 access token")
	}
	return m.generateSessionToken(userID, username, email, role, authCtx, notAfter)
}

func (m *JWTManager) generateSessionToken(userID uint, username, email, role string, authCtx AuthContext, notAfter time.Time) (string, error) {
	now := time.Now()
	expires := now.Add(m.tokenDuration)
	if !notAfter.IsZero() && notAfter.Before(expires) {
		expires = notAfter
	}
	claims := Claims{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Role:        role,
		AuthContext: authCtx,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

// GenerateScopedToken 生成帶用途限定 scope 與自訂存活時間的 token（如 MFA pending）。
// 為什麼獨立方法：正式 session token 永不攜帶 scope，分開可避免呼叫端誤發限定 token
func (m *JWTManager) GenerateScopedToken(userID uint, username, email, role, scope string, ttl time.Duration, authCtx AuthContext) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Role:        role,
		Scope:       scope,
		AuthContext: authCtx,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

// ValidateToken 驗證 JWT token。
//
// 解析器約束刻意收到最窄（對抗審查 G-A）：
//
//	WithValidMethods([]string{"HS256"})  只認演算法本身，不認 HMAC**族**。
//	  原本的 `token.Method.(*jwt.SigningMethodHMAC)` 型別判定同時放行
//	  HS384/HS512——三者共用同一把 []byte(secretKey)，簽章必然驗得過，
//	  故同一把 secret 若在他處以另一變體簽出任何用途的 token，那張 token 可
//	  原封不動當本系統登入憑證使用。演算法允許清單是唯一能擋住的位置。
//	WithIssuer(tokenIssuer)              issuer 是「誰簽的」的唯一宣告；不驗即
//	  等於接受任何共用該 secret 之元件簽出的 token。缺 issuer 與 issuer 錯誤同罰。
//	WithExpirationRequired()             jwt/v5 預設「沒有 exp 就不檢查過期」——
//	  一張無 exp 的 token 是永久憑證，世代閘以外的撤銷機制全都管不到它。
//
// 三條皆**不誤傷既有 token**：本專案全部簽發路徑均為 HS256 ＋ issuer
// "custodexa" ＋ 必帶 ExpiresAt（jwt_validation_hardening_test.go 逐條釘住）
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(m.secretKey), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// 註：舊版 RefreshToken（接受過期 token 後以 GenerateToken 重簽、且不帶 Scope）已移除。
// 它是 scope-stripping 逃逸的未爆彈——一旦接上任何 /auth/refresh 端點，持 scoped token
// 即可換出無 scope 的正式 session token 繞過 deny-by-default（對抗驗證 AUTH-2）。
// 輪 2 的會話刷新改走資料庫 refresh_tokens（rotation＋reuse detection，design D6），
// 不重用此 JWT 自刷新機制。
