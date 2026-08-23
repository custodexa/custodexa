package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestNewJWTManager 測試創建 JWT 管理器
func TestNewJWTManager(t *testing.T) {
	secretKey := "test-secret-key"
	tokenDuration := 15 * time.Minute

	manager := NewJWTManager(secretKey, tokenDuration)

	assert.NotNil(t, manager)
	assert.Equal(t, secretKey, manager.secretKey)
	assert.Equal(t, tokenDuration, manager.tokenDuration)
}

// TestGenerateToken 測試生成 JWT token
func TestGenerateToken(t *testing.T) {
	manager := NewJWTManager("secret", 15*time.Minute)

	tests := []struct {
		name     string
		userID   uint
		username string
		email    string
		role     string
		wantErr  bool
	}{
		{
			name:     "Valid token generation",
			userID:   1,
			username: "testuser",
			email:    "test@example.com",
			role:     "admin",
			wantErr:  false,
		},
		{
			name:     "Valid token with user role",
			userID:   2,
			username: "normaluser",
			email:    "user@example.com",
			role:     "user",
			wantErr:  false,
		},
		{
			name:     "Valid token with auditor role",
			userID:   3,
			username: "auditor",
			email:    "audit@example.com",
			role:     "auditor",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := manager.GenerateToken(tt.userID, tt.username, tt.email, tt.role, AuthContext{})

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)

				// 驗證 token 包含正確的 claims
				claims, err := manager.ValidateToken(token)
				assert.NoError(t, err)
				assert.Equal(t, tt.userID, claims.UserID)
				assert.Equal(t, tt.username, claims.Username)
				assert.Equal(t, tt.email, claims.Email)
				assert.Equal(t, tt.role, claims.Role)
			}
		})
	}
}

// TestValidateToken 測試驗證 JWT token
func TestValidateToken(t *testing.T) {
	manager := NewJWTManager("secret-key-for-testing", 15*time.Minute)

	tests := []struct {
		name        string
		setupToken  func() string
		wantErr     bool
		expectedErr error
	}{
		{
			name: "Valid token",
			setupToken: func() string {
				token, _ := manager.GenerateToken(1, "testuser", "test@example.com", "admin", AuthContext{})
				return token
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "Invalid token format",
			setupToken: func() string {
				return "invalid.token.format"
			},
			wantErr:     true,
			expectedErr: ErrInvalidToken,
		},
		{
			name: "Empty token",
			setupToken: func() string {
				return ""
			},
			wantErr:     true,
			expectedErr: ErrInvalidToken,
		},
		{
			name: "Token with wrong secret",
			setupToken: func() string {
				wrongManager := NewJWTManager("wrong-secret", 15*time.Minute)
				token, _ := wrongManager.GenerateToken(1, "testuser", "test@example.com", "admin", AuthContext{})
				return token
			},
			wantErr:     true,
			expectedErr: ErrInvalidToken,
		},
		{
			name: "Expired token",
			setupToken: func() string {
				expiredManager := NewJWTManager("secret-key-for-testing", -1*time.Hour)
				token, _ := expiredManager.GenerateToken(1, "testuser", "test@example.com", "admin", AuthContext{})
				return token
			},
			wantErr:     true,
			expectedErr: ErrExpiredToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setupToken()
			claims, err := manager.ValidateToken(token)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, claims)
				if tt.expectedErr != nil {
					assert.Equal(t, tt.expectedErr, err)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

// TestValidateToken_Claims 測試驗證 token 並檢查 claims
func TestValidateToken_Claims(t *testing.T) {
	manager := NewJWTManager("secret", 15*time.Minute)

	userID := uint(123)
	username := "john.doe"
	email := "john@example.com"
	role := "admin"

	token, err := manager.GenerateToken(userID, username, email, role, AuthContext{})
	assert.NoError(t, err)

	claims, err := manager.ValidateToken(token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)

	// 驗證所有 claims
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, role, claims.Role)
	assert.Equal(t, "custodexa", claims.Issuer)
	assert.NotNil(t, claims.ExpiresAt)
	assert.NotNil(t, claims.IssuedAt)
	assert.NotNil(t, claims.NotBefore)
}

// TestTokenExpiration 測試 token 過期時間
func TestTokenExpiration(t *testing.T) {
	duration := 1 * time.Second
	manager := NewJWTManager("secret", duration)

	token, err := manager.GenerateToken(1, "testuser", "test@example.com", "admin", AuthContext{})
	assert.NoError(t, err)

	// 立即驗證應該成功
	claims, err := manager.ValidateToken(token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)

	// 等待 token 過期
	time.Sleep(2 * time.Second)

	// 驗證過期的 token 應該失敗
	claims, err = manager.ValidateToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
	assert.Nil(t, claims)
}

// TestTokenWithDifferentSigningMethod 測試使用不同簽名方法的 token
func TestTokenWithDifferentSigningMethod(t *testing.T) {
	manager := NewJWTManager("secret", 15*time.Minute)

	// 創建一個使用 RSA 簽名方法的 token (而不是 HMAC)
	claims := Claims{
		UserID:   1,
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "custodexa",
		},
	}

	// 使用 none 方法簽名（不安全的方法）
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	assert.NoError(t, err)

	// 驗證應該失敗，因為簽名方法不是 HMAC
	validatedClaims, err := manager.ValidateToken(tokenString)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
	assert.Nil(t, validatedClaims)
}

// TestMultipleTokensWithSameUser 測試同一用戶的多個 token
func TestMultipleTokensWithSameUser(t *testing.T) {
	manager := NewJWTManager("secret", 15*time.Minute)

	userID := uint(789)
	username := "multitoken"
	email := "multi@example.com"
	role := "user"

	// 生成多個 token
	token1, err := manager.GenerateToken(userID, username, email, role, AuthContext{})
	assert.NoError(t, err)

	time.Sleep(10 * time.Millisecond) // 確保時間戳不同

	token2, err := manager.GenerateToken(userID, username, email, role, AuthContext{})
	assert.NoError(t, err)

	// 兩個 token 應該不同（因為 IssuedAt 時間不同）
	// 注意：如果時間戳解析度不夠，token 可能相同，這是可以接受的
	// assert.NotEqual(t, token1, token2)

	// 但都應該有效
	claims1, err := manager.ValidateToken(token1)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims1.UserID)

	claims2, err := manager.ValidateToken(token2)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims2.UserID)
}

// 認證脈絡的零值 round-trip。
//
// **這組斷言守的是升級期相容**：既有 token 不帶脈絡欄位，解析後四欄皆為零值，
// 而 DB 的 epoch default 也是 0，故兩者比對相符、既有 token 仍有效。
// 若日後有人把 epoch 改成 `*int` 或引入哨兵值（如 -1 表示「未設定」），
// 零值與 default 不再相等，**全體既有 token 會在部署當下集體 401**。

func TestAuthContextZeroValueRoundTrip(t *testing.T) {
	m := NewJWTManager("test-secret", time.Hour)

	// 完全不帶脈絡簽發（等同升級期的舊呼叫點）
	tok, err := m.GenerateToken(1, "alice", "a@x", "user", AuthContext{})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := m.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if claims.AuthMethod != "" {
		t.Errorf("AuthMethod = %q, want 空字串（omitempty 不序列化）", claims.AuthMethod)
	}
	if claims.ProviderID != 0 || claims.AuthEpoch != 0 || claims.CredEpoch != 0 {
		t.Errorf("零值脈絡解析後應仍為零：provider=%d auth=%d cred=%d",
			claims.ProviderID, claims.AuthEpoch, claims.CredEpoch)
	}
	// 缺值一律視為本地密碼——密碼類 gate 才不會對舊 token 靜默失效
	if claims.EffectiveMethod() != AuthMethodLocalPassword {
		t.Errorf("EffectiveMethod() = %q, want %q", claims.EffectiveMethod(), AuthMethodLocalPassword)
	}
}

func TestAuthContextZeroValueOmittedFromPayload(t *testing.T) {
	m := NewJWTManager("test-secret", time.Hour)
	tok, err := m.GenerateToken(1, "alice", "a@x", "user", AuthContext{})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// 直接檢視 payload：零值欄位不得出現。
	// 出現即代表 omitempty 被拿掉，日後改型別的破壞性會被這一層掩蓋
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token 應為三段，實得 %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("解碼 payload: %v", err)
	}
	for _, field := range []string{"auth_method", "provider_id", "auth_epoch", "cred_epoch"} {
		if strings.Contains(string(payload), field) {
			t.Errorf("零值脈絡不應序列化欄位 %q，payload: %s", field, payload)
		}
	}
}

func TestAuthContextNonZeroSurvivesRoundTrip(t *testing.T) {
	m := NewJWTManager("test-secret", time.Hour)
	want := AuthContext{
		AuthMethod: AuthMethodOIDC, ProviderID: 7, AuthEpoch: 3, CredEpoch: 5,
	}
	tok, err := m.GenerateToken(1, "alice", "a@x", "user", want)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := m.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.AuthContext != want {
		t.Errorf("脈絡 round-trip 失真：%+v, want %+v", claims.AuthContext, want)
	}
}
