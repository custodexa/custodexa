package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// fakeLDAPAuthenticator 測試替身：可控成功/失敗並記錄呼叫次數，
// 用於驗證分流邏輯「何時該打目錄、何時不該」
type fakeLDAPAuthenticator struct {
	info  *LDAPUserInfo
	err   error
	calls int
}

func (f *fakeLDAPAuthenticator) Authenticate(username, password string) (*LDAPUserInfo, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.info, nil
}

// staticLDAPResolver 測試用的登入解析器：
// 固定回「可撥號、無傳輸風險」的解析結果，交出指定的 fake 認證器。
//
// **既有格點只換注入形狀、不改行為斷言**——改動前是注入 authenticator 且
// 風險由 TransmissionPolicyService 判定，對這些不含風險設定的格點兩者等價
func staticLDAPResolver(auth LDAPAuthenticator) LDAPLoginResolver {
	return func() LDAPLoginResolution {
		return LDAPLoginResolution{State: LDAPLoginReady, Auth: auth}
	}
}

// riskyLDAPResolver 帶傳輸風險視圖的解析器：Risks 與 Auth 出自同一份視圖，
// 與生產 resolver 的不變式同形
func riskyLDAPResolver(auth LDAPAuthenticator, view policy.LDAPRiskView) LDAPLoginResolver {
	return func() LDAPLoginResolution {
		return LDAPLoginResolution{State: LDAPLoginReady, Auth: auth, Risks: policy.LDAPRisksOf(view)}
	}
}

// ldapUserColumns 含 is_ldap/totp_enabled 的查詢欄位集合
func ldapUserRows(id int, username, email string, active, isLDAP, totpEnabled bool, password string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active", "is_ldap", "totp_enabled"}).
		AddRow(id, username, email, password, "LDAP User", active, isLDAP, totpEnabled)
}

// expectEmptyRolesPreload mock Preload("Roles") 無角色的情境。
// 為什麼只 mock user_roles：關聯表無命中時 GORM 會略過 roles 查詢
func expectEmptyRolesPreload(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}))
}

// TestLoginLDAP_FirstLoginProvisionsShadowUser 首次 LDAP 登入：
// 驗證通過後供應影子用戶（is_ldap=true、user 角色）並核發 token
func TestLoginLDAP_FirstLoginProvisionsShadowUser(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{
		Username: "testldap",
		Email:    "testldap@example.org",
		FullName: "Test LDAP",
	}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	// 本地查無用戶
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnError(gorm.ErrRecordNotFound)

	// email 衝突檢查：無衝突
	mock.ExpectQuery(`SELECT count\(\*\) FROM "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// 影子供應事務：建用戶 + 查角色 + 綁角色
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "users"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectQuery(`SELECT .+ FROM "roles" WHERE name`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(2, "user"))
	mock.ExpectExec(`INSERT INTO user_roles`).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	expectFinishLoginUpdate(mock)

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "ldappass123"})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.NotEmpty(t, resp.Token)
		assert.Equal(t, "ldap", resp.AuthSource)
		assert.Equal(t, "testldap", resp.User.Username)
		assert.Contains(t, resp.User.Roles, "user")
	}
	assert.Equal(t, 1, fake.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLoginLDAP_SecondLoginDoesNotReprovision 二次登入：
// 已存在的 is_ldap 用戶直接複用，不得再 INSERT
func TestLoginLDAP_SecondLoginDoesNotReprovision(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "testldap"}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	// 查到既有影子用戶（is_ldap=true）；未 mock 任何 INSERT，
	// 若程式碼誤走供應路徑，ExpectationsWereMet 會失敗
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(ldapUserRows(42, "testldap", "testldap@example.org", true, true, false, "random-bcrypt"))
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(42, 2))
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(2, "user"))

	expectFinishLoginUpdate(mock)

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "ldappass123"})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.NotEmpty(t, resp.Token)
		assert.Equal(t, "ldap", resp.AuthSource)
		assert.Equal(t, uint(42), resp.User.ID)
	}
	assert.Equal(t, 1, fake.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLoginLDAP_WrongPassword 目錄驗證失敗：對外回與本地相同的憑證錯誤
func TestLoginLDAP_WrongPassword(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{err: ErrLDAPAuthFailed}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnError(gorm.ErrRecordNotFound)

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "wrongpass"})

	assert.Nil(t, resp)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Equal(t, 1, fake.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLoginLDAP_DisabledFallsBackToOriginalError LDAP 未啟用時，
// 查無用戶必須維持原本的憑證錯誤語義（部署零影響）
func TestLoginLDAP_DisabledFallsBackToOriginalError(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	// 不注入 ldapAuth：即 LDAP_ENABLED=false 的執行型態

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnError(gorm.ErrRecordNotFound)

	resp, err := authService.Login(&LoginRequest{Username: "nobody", Password: "whatever"})

	assert.Nil(t, resp)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLoginLDAP_DirectoryDownLocalUnaffected 目錄掛掉時，
// 本地（非 is_ldap）用戶登入完全不受影響，且不應觸碰目錄
func TestLoginLDAP_DirectoryDownLocalUnaffected(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{err: errors.New("LDAP 連線失敗: connection refused")}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	password := "localpass123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(ldapUserRows(7, "localuser", "local@example.com", true, false, false, string(hashed)))
	expectEmptyRolesPreload(mock)

	expectFinishLoginUpdate(mock)

	resp, err := authService.Login(&LoginRequest{Username: "localuser", Password: password})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.NotEmpty(t, resp.Token)
		assert.Empty(t, resp.AuthSource, "本地登入不標註 LDAP 來源")
	}
	assert.Equal(t, 0, fake.calls, "本地用戶登入不得呼叫 LDAP")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLoginLDAP_MFARequired is_ldap 且啟用 TOTP 的用戶：
// 目錄驗證成功後仍須走 MFA 兩階段，回 mfa_required + pending token
func TestLoginLDAP_MFARequired(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "testldap"}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(ldapUserRows(42, "testldap", "testldap@example.org", true, true, true, "random-bcrypt"))
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(42, 2))
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(2, "user"))

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "ldappass123"})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.True(t, resp.MFARequired)
		assert.NotEmpty(t, resp.PendingToken)
		assert.Empty(t, resp.Token, "MFA 第一階段不得核發正式 token")
		assert.Equal(t, "ldap", resp.AuthSource)
	}
	assert.Equal(t, 1, fake.calls)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLoginLDAP_InactiveShadowUserRejectedAfterDirectoryAuth 已停用的影子用戶被拒絕，
// 但**判定發生在目錄認證之後**（塊 4）。
//
// 原行為是「不打目錄直接拒絕」，省下一次目錄請求；代價是未認證者送任意密碼即可
// 分辨「此帳號存在但已停用」與「此帳號不存在」——帳號存在性預言機的 LDAP 側。
// 一次目錄請求換掉存在性洩漏，值得。
//
// **`fake.calls == 1` 是本測試的核心斷言**：它證明順序真的變了。若有人把檢查移
// 回目錄認證之前，此處會變回 0 而轉紅。
func TestLoginLDAP_InactiveShadowUserRejectedAfterDirectoryAuth(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	authService := NewAuthService("secret", 15*time.Minute)
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "testldap"}}
	authService.SetLDAPResolver(staticLDAPResolver(fake))

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(ldapUserRows(42, "testldap", "", false, true, false, "random-bcrypt"))
	expectEmptyRolesPreload(mock)

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "ldappass123"})

	assert.Nil(t, resp)
	assert.Equal(t, ErrUserInactive, err,
		"目錄認證通過後才揭露停用事實——此時對方已證明持有憑證，告知不構成洩漏")
	assert.Equal(t, 1, fake.calls,
		"停用判定須在目錄認證之後：提前返回會使停用帳號與不存在帳號的回應可辨")
}

// TestChangePassword_LDAPUserRejected 改密路徑必須拒絕 is_ldap 用戶
func TestChangePassword_LDAPUserRejected(t *testing.T) {
	db, mock, gormDB := setupAuthMockDB(t)
	_ = db
	userService := NewUserService(gormDB, authz.NewAssetAuthorizationService(gormDB))

	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE`).
		WillReturnRows(ldapUserRows(42, "testldap", "", true, true, false, "random-bcrypt"))

	err := userService.ChangePassword(42, "newpassword123")

	assert.Equal(t, ErrExternalUserPassword, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
