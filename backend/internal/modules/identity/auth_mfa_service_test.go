package identity

import (
	"context"
	"github.com/custodexa/backend/pkg/crypto"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// 測試用 AES-256 金鑰（32 bytes）
var testMFAKey = []byte("0123456789abcdef0123456789abcdef")

// testTOTPSecret 固定 base32 secret，便於產生可預期的驗證碼
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// newMFAAuthService 建立含 MFA 加密能力的測試服務
func newMFAAuthService(t *testing.T) *AuthService {
	svc, err := NewAuthServiceWithMFA("secret", 15*time.Minute, aesColumnCodec(t, testMFAKey))
	if err != nil {
		t.Fatalf("Failed to create auth service with MFA: %v", err)
	}
	return svc
}

// encryptTestSecret 以測試金鑰加密 secret（模擬 setup 後的 DB 狀態）
func encryptTestSecret(t *testing.T, svc *AuthService) string {
	enc, err := svc.mfaCrypto.EncryptFor(context.Background(), keyvault.RefUserTOTPSecret, testTOTPSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt test secret: %v", err)
	}
	return enc
}

// validTestCode 產生目前時間窗的有效 TOTP 碼
func validTestCode(t *testing.T) string {
	code, err := totp.GenerateCode(testTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}
	return code
}

// wrongTestCode 產生必然錯誤的驗證碼（避開與有效碼碰撞）
func wrongTestCode(t *testing.T) string {
	if validTestCode(t) == "000000" {
		return "111111"
	}
	return "000000"
}

// mockUserWithTOTP 回傳含 TOTP 欄位的使用者查詢結果
func mockUserWithTOTP(id uint, username, hashedPassword, secretEnc string, enabled bool) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active", "totp_secret_enc", "totp_enabled"}).
		AddRow(id, username, username+"@example.com", hashedPassword, "Test User", true, secretEnc, enabled)
}

// TestGenerateMFASetup_Success 測試產生 MFA 設定（密文暫存、enabled 維持 false）
func TestGenerateMFASetup_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", "", false))

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	resp, err := svc.GenerateMFASetup(1)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Secret)
	assert.True(t, strings.HasPrefix(resp.OTPAuthURL, "otpauth://totp/"))
	assert.Contains(t, resp.OTPAuthURL, "issuer=Custodexa")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGenerateMFASetup_NoCrypto 測試未注入加密服務時拒絕
func TestGenerateMFASetup_NoCrypto(t *testing.T) {
	svc := NewAuthService("secret", 15*time.Minute)

	resp, err := svc.GenerateMFASetup(1)

	assert.ErrorIs(t, err, ErrMFACryptoUnavailable)
	assert.Nil(t, resp)
}

// TestEnableMFA_Success 測試正確驗證碼啟用 MFA
func TestEnableMFA_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, false))

	// consumeTOTP 的 CAS UPDATE（推進 totp_last_step，8.5.1 防重放）
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	// 再 UPDATE totp_enabled=true
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := svc.EnableMFA(1, validTestCode(t))

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestEnableMFA_WrongCode 測試錯誤驗證碼拒絕啟用（不應有任何 UPDATE）
func TestEnableMFA_WrongCode(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, false))

	err := svc.EnableMFA(1, wrongTestCode(t))

	assert.ErrorIs(t, err, ErrMFAInvalidCode)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestEnableMFA_WithoutSetup 測試未先 setup 即啟用被拒
func TestEnableMFA_WithoutSetup(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", "", false))

	err := svc.EnableMFA(1, "123456")

	assert.ErrorIs(t, err, ErrMFASetupRequired)
}

// TestVerifyMFACode_Success 測試已啟用用戶驗證正確碼
func TestVerifyMFACode_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, true))

	// consumeTOTP 的 CAS UPDATE（8.5.1 防重放）
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := svc.VerifyMFACode(1, validTestCode(t))

	assert.NoError(t, err)
}

// TestVerifyMFACode_WrongCode 測試錯誤驗證碼被拒
func TestVerifyMFACode_WrongCode(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, true))

	err := svc.VerifyMFACode(1, wrongTestCode(t))

	assert.ErrorIs(t, err, ErrMFAInvalidCode)
}

// TestVerifyMFACode_NotEnabled 測試未啟用 MFA 用戶被拒
func TestVerifyMFACode_NotEnabled(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, false))

	err := svc.VerifyMFACode(1, validTestCode(t))

	assert.ErrorIs(t, err, ErrMFANotEnabled)
}

// TestDisableMFA_Success 測試正確密碼停用 MFA
func TestDisableMFA_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", string(hashed), secretEnc, true))

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := svc.DisableMFA(1, "password123")

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestDisableMFA_WrongPassword 測試錯誤密碼拒絕停用（不應有任何 UPDATE）
func TestDisableMFA_WrongPassword(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", string(hashed), secretEnc, true))

	err := svc.DisableMFA(1, "wrongpassword")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAdminDisableMFA_Success 測試管理員救援停用
func TestAdminDisableMFA_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(2, "lockedout", "", secretEnc, true))

	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := svc.AdminDisableMFA(2)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogin_MFARequired 測試 MFA 用戶登入回 pending token（不發正式 token）
func TestLogin_MFARequired(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)

	password := "password123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", string(hashed), "enc", true))
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(1, 1))
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "user"))

	resp, err := svc.Login(&LoginRequest{Username: "mfauser", Password: password})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.MFARequired)
	assert.NotEmpty(t, resp.PendingToken)
	assert.Empty(t, resp.Token)
	assert.Nil(t, resp.User)

	// pending token 必須帶 mfa_pending scope
	claims, err := svc.ValidateToken(resp.PendingToken)
	assert.NoError(t, err)
	assert.Equal(t, "mfa_pending", claims.Scope)
	assert.Equal(t, uint(1), claims.UserID)
}

// TestVerifyMFALogin_Success 測試 pending token + 正確碼換取正式 JWT
func TestVerifyMFALogin_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	pendingToken, err := svc.jwtManager.GenerateScopedToken(1, "mfauser", "mfauser@example.com", "user", "mfa_pending", time.Minute, crypto.AuthContext{})
	assert.NoError(t, err)

	// 先重新載入用戶（含角色）——鎖定 gate 需要最新狀態
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, true))
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(1, 1))
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "user"))
	// VerifyMFACode 的用戶查詢
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, true))
	// consumeTOTP 的 CAS UPDATE（8.5.1 防重放）
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users" SET`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	expectFinishLoginUpdate(mock)

	resp, err := svc.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: pendingToken,
		Code:         validTestCode(t),
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.False(t, resp.MFARequired)
	assert.Equal(t, "mfauser", resp.User.Username)

	// 正式 token 不得帶 scope
	claims, err := svc.ValidateToken(resp.Token)
	assert.NoError(t, err)
	assert.Empty(t, claims.Scope)
}

// TestVerifyMFALogin_WrongCode 測試錯誤碼不發 token
func TestVerifyMFALogin_WrongCode(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	svc := newMFAAuthService(t)
	secretEnc := encryptTestSecret(t, svc)

	pendingToken, err := svc.jwtManager.GenerateScopedToken(1, "mfauser", "mfauser@example.com", "user", "mfa_pending", time.Minute, crypto.AuthContext{})
	assert.NoError(t, err)

	// 先重新載入用戶（鎖定 gate），再查 TOTP secret
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, true))
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}))
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(mockUserWithTOTP(1, "mfauser", "", secretEnc, true))

	resp, err := svc.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: pendingToken,
		Code:         wrongTestCode(t),
	})

	assert.ErrorIs(t, err, ErrMFAInvalidCode)
	assert.Nil(t, resp)
}

// TestVerifyMFALogin_RejectsNormalToken 測試正式 token 不能走 MFA 交換通道
func TestVerifyMFALogin_RejectsNormalToken(t *testing.T) {
	svc := newMFAAuthService(t)

	// 無 scope 的正式 token
	normalToken, err := svc.jwtManager.GenerateToken(1, "mfauser", "mfauser@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	resp, err := svc.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: normalToken,
		Code:         "123456",
	})

	assert.ErrorIs(t, err, ErrMFAPendingTokenInvalid)
	assert.Nil(t, resp)
}

// TestVerifyMFALogin_ExpiredPendingToken 測試過期 pending token 被拒
func TestVerifyMFALogin_ExpiredPendingToken(t *testing.T) {
	svc := newMFAAuthService(t)

	expiredToken, err := svc.jwtManager.GenerateScopedToken(1, "mfauser", "mfauser@example.com", "user", "mfa_pending", -time.Minute, crypto.AuthContext{})
	assert.NoError(t, err)

	resp, err := svc.VerifyMFALogin(&MFAVerifyRequest{
		PendingToken: expiredToken,
		Code:         "123456",
	})

	assert.ErrorIs(t, err, ErrMFAPendingTokenInvalid)
	assert.Nil(t, resp)
}
