package crypto

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 解析器約束的收緊（安全審查 G-A）。
//
// 原本 ValidateToken 只檢查 `token.Method.(*jwt.SigningMethodHMAC)`——那是**族**
// 判定而非**演算法**判定，等於同時接受 HS256/HS384/HS512。同一把 secret 若在他處
// 以另一個 HMAC 變體簽發任何用途的 token（匯出簽章、內部工單、第三方元件），
// 那張 token 就能原封不動當成本系統的登入憑證使用；且 issuer 與 exp 都不是必要欄，
// 一張沒有 exp 的 token 永不過期。
//
// 三條約束（WithValidMethods / WithIssuer / WithExpirationRequired）互相獨立，
// 故本檔逐條給一個攻擊型測試——只留一條而拿掉另兩條的實作必須被抓到。
//
// **不會誤傷既有 token**：本專案全部簽發路徑（generateSessionToken、
// GenerateScopedToken）皆為 HS256 ＋ Issuer "custodexa" ＋ 必帶 ExpiresAt，
// 由 TestValidateTokenAcceptsEveryProductionIssuePath 逐條釘住。

const hardeningSecret = "hardening-secret"

// signWith 以指定演算法與 secret 簽出一張 claims 完整（issuer/exp/iat 皆備）的 token。
// 只有演算法一項與生產路徑不同，故測試失敗時成因唯一
func signWith(t *testing.T, method jwt.SigningMethod, claims Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	s, err := tok.SignedString([]byte(hardeningSecret))
	require.NoError(t, err)
	return s
}

// productionShapedClaims 與生產簽發完全同形的 claims（issuer、exp、iat、nbf 齊備）
func productionShapedClaims() Claims {
	now := time.Now()
	return Claims{
		UserID:   1,
		Username: "victim",
		Email:    "victim@example.com",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "custodexa",
		},
	}
}

// TestValidateTokenRejectsOtherHMACVariants 正向攻擊：同一把 secret、僅換 HMAC 變體。
//
// 這正是「族判定」放行而「演算法判定」擋下的那一格：HS384/HS512 與 HS256 共用
// []byte(secret)，簽章一定驗得過，唯一能擋的位置是演算法允許清單
func TestValidateTokenRejectsOtherHMACVariants(t *testing.T) {
	m := NewJWTManager(hardeningSecret, 15*time.Minute)

	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
	}{
		{"HS384", jwt.SigningMethodHS384},
		{"HS512", jwt.SigningMethodHS512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signWith(t, tc.method, productionShapedClaims())

			claims, err := m.ValidateToken(token)

			assert.Nil(t, claims, "%s 簽的 token 不得被接受（同金鑰跨用途混用）", tc.name)
			assert.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

// TestValidateTokenStillAcceptsHS256 收緊不得把唯一的生產演算法一起擋掉
func TestValidateTokenStillAcceptsHS256(t *testing.T) {
	m := NewJWTManager(hardeningSecret, 15*time.Minute)

	claims, err := m.ValidateToken(signWith(t, jwt.SigningMethodHS256, productionShapedClaims()))

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, uint(1), claims.UserID)
}

// TestValidateTokenRejectsForeignIssuer 同金鑰但 issuer 不是本系統：拒。
//
// issuer 是「這張 token 是誰簽的」的唯一宣告；不驗它，任何共用該 secret 的
// 元件簽出的 token 都能當本系統憑證用
func TestValidateTokenRejectsForeignIssuer(t *testing.T) {
	m := NewJWTManager(hardeningSecret, 15*time.Minute)
	claims := productionShapedClaims()
	claims.Issuer = "some-other-service"

	got, err := m.ValidateToken(signWith(t, jwt.SigningMethodHS256, claims))

	assert.Nil(t, got, "非本系統簽發的 issuer 不得被接受")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestValidateTokenRejectsEmptyIssuer 缺 issuer 與 issuer 錯誤同等處置（fail-close）
func TestValidateTokenRejectsEmptyIssuer(t *testing.T) {
	m := NewJWTManager(hardeningSecret, 15*time.Minute)
	claims := productionShapedClaims()
	claims.Issuer = ""

	got, err := m.ValidateToken(signWith(t, jwt.SigningMethodHS256, claims))

	assert.Nil(t, got, "無 issuer 的 token 不得被接受")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestValidateTokenRejectsMissingExpiration 沒有 exp 的 token = 永久憑證。
//
// jwt/v5 預設「沒有 exp 就不檢查過期」，故缺此約束時這張 token 會永遠通過驗證，
// 而世代閘之外的任何撤銷機制都管不到它
func TestValidateTokenRejectsMissingExpiration(t *testing.T) {
	m := NewJWTManager(hardeningSecret, 15*time.Minute)
	claims := productionShapedClaims()
	claims.ExpiresAt = nil

	got, err := m.ValidateToken(signWith(t, jwt.SigningMethodHS256, claims))

	assert.Nil(t, got, "無 exp 的 token 不得被接受（等同永久憑證）")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestValidateTokenAcceptsEveryProductionIssuePath 誤傷防護：三條生產簽發路徑
// 產出的 token 在收緊後仍必須全數通過。
//
// 收緊解析器的風險是「連自己簽的都擋掉」——升級後全體使用者 401。故不以人工
// 構造的 claims 代表生產形狀，而是實際呼叫每一個對外簽發方法
func TestValidateTokenAcceptsEveryProductionIssuePath(t *testing.T) {
	m := NewJWTManager(hardeningSecret, 15*time.Minute)
	authCtx := AuthContext{AuthMethod: AuthMethodOIDC, ProviderID: 3, AuthEpoch: 2, CredEpoch: 5}

	sessionTok, err := m.GenerateToken(7, "u", "u@example.com", "user", authCtx)
	require.NoError(t, err)

	notAfterTok, err := m.GenerateTokenNotAfter(7, "u", "u@example.com", "user", authCtx,
		time.Now().Add(30*time.Minute))
	require.NoError(t, err)

	scopedTok, err := m.GenerateScopedToken(7, "u", "u@example.com", "user",
		ScopeMFAPending, 5*time.Minute, authCtx)
	require.NoError(t, err)

	for name, tok := range map[string]string{
		"GenerateToken":         sessionTok,
		"GenerateTokenNotAfter": notAfterTok,
		"GenerateScopedToken":   scopedTok,
	} {
		t.Run(name, func(t *testing.T) {
			claims, err := m.ValidateToken(tok)
			require.NoError(t, err, "%s 簽出的 token 被收緊後的解析器誤擋", name)
			require.NotNil(t, claims)
			assert.Equal(t, uint(7), claims.UserID)
			assert.Equal(t, "custodexa", claims.Issuer)
			assert.Equal(t, uint(3), claims.ProviderID)
		})
	}
}
