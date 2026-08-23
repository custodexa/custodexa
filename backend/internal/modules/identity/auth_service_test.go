package identity

import (
	"database/sql"
	"github.com/custodexa/backend/pkg/crypto"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/database"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupAuthMockDB 建立測試用的 mock 資料庫
func setupAuthMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *gorm.DB) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create gorm DB: %v", err)
	}

	// 保存原始的 DB
	oldDB := database.DB
	database.DB = gormDB

	// 清理函數會在測試結束時還原
	t.Cleanup(func() {
		database.DB = oldDB
		db.Close()
	})

	return db, mock, gormDB
}

// expectFinishLoginUpdate mock finishLogin：先 SELECT locked_until 複查（LOCK-2），
// 再計數歸零＋last_login_at 更新（認證全過後的固定寫入），
// 最後 buildLoginResponse 發放 refresh 憑證——本套 sqlmock 測試皆無
// must_change 分支，finishLogin 一律走到發放
func expectFinishLoginUpdate(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "locked_until"}).AddRow(1, nil))
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE "users"`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectQuery(`INSERT INTO "refresh_tokens"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectCommit()
}

// TestNewAuthService 測試創建認證服務
func TestNewAuthService(t *testing.T) {
	jwtSecret := "test-secret"
	tokenDuration := 15 * time.Minute

	service := NewAuthService(jwtSecret, tokenDuration)

	assert.NotNil(t, service)
	assert.NotNil(t, service.jwtManager)
}

// TestLogin_Success 測試成功登入
func TestLogin_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	// 準備測試資料
	username := "testuser"
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Mock 查詢使用者
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
		AddRow(1, username, "test@example.com", string(hashedPassword), "Test User", true)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(userRows)

	// Mock Preload("Roles") - GORM 使用 user_roles 中間表查詢
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(1, 1))

	// Mock 查詢 roles 表
	roleRows := sqlmock.NewRows([]string{"id", "name"}).
		AddRow(1, "admin")
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(roleRows)

	expectFinishLoginUpdate(mock)

	// 執行登入
	req := &LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := service.Login(req)

	// 驗證結果
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, username, resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)
	assert.True(t, resp.User.Active)
	assert.Contains(t, resp.User.Roles, "admin")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogin_UserNotFound 測試使用者不存在
func TestLogin_UserNotFound(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	// Mock 查詢使用者 - 不存在
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnError(gorm.ErrRecordNotFound)

	req := &LoginRequest{
		Username: "nonexistent",
		Password: "password123",
	}

	resp, err := service.Login(req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogin_WrongPassword 測試密碼錯誤
func TestLogin_WrongPassword(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	username := "testuser"
	correctPassword := "correct123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)

	// Mock 查詢使用者
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
		AddRow(1, username, "test@example.com", string(hashedPassword), "Test User", true)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(userRows)

	// Mock Preload("Roles")
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}))
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

	req := &LoginRequest{
		Username: username,
		Password: "wrongpassword",
	}

	resp, err := service.Login(req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)

	// 注意：密碼錯誤時，Roles 已經被 preload，但不會使用
	// 不檢查 ExpectationsWereMet，因為 roles mock 可能未被使用
}

// TestLogin_UserInactive 測試使用者未啟用
func TestLogin_UserInactive(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	username := "inactiveuser"
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Mock 查詢使用者 - 未啟用
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
		AddRow(1, username, "inactive@example.com", string(hashedPassword), "Inactive User", false)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(userRows)

	// Mock Preload("Roles")
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}))
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

	req := &LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := service.Login(req)

	assert.Error(t, err)
	assert.Equal(t, ErrUserInactive, err)
	assert.Nil(t, resp)

	// 注意：使用者未啟用時，Roles 已經被 preload，但不會使用
	// 不檢查 ExpectationsWereMet，因為 roles mock 可能未被使用
}

// TestLogin_MultipleRoles 測試使用者有多個角色
func TestLogin_MultipleRoles(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	username := "multiuser"
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Mock 查詢使用者
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
		AddRow(1, username, "multi@example.com", string(hashedPassword), "Multi Role User", true)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(userRows)

	// Mock Preload("Roles") - 多個角色，包含 admin
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).
			AddRow(1, 1).
			AddRow(1, 2).
			AddRow(1, 3))
	roleRows := sqlmock.NewRows([]string{"id", "name"}).
		AddRow(1, "user").
		AddRow(2, "auditor").
		AddRow(3, "admin")
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(roleRows)

	expectFinishLoginUpdate(mock)

	req := &LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := service.Login(req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.User.Roles, 3)
	assert.Contains(t, resp.User.Roles, "admin")
	assert.Contains(t, resp.User.Roles, "user")
	assert.Contains(t, resp.User.Roles, "auditor")

	// 驗證 token 中的主要角色是 admin（優先）
	claims, err := service.ValidateToken(resp.Token)
	assert.NoError(t, err)
	assert.Equal(t, "admin", claims.Role)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogin_NoRoles 測試使用者沒有角色
func TestLogin_NoRoles(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	username := "noroleuser"
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Mock 查詢使用者
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
		AddRow(1, username, "norole@example.com", string(hashedPassword), "No Role User", true)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(userRows)

	// Mock Preload("Roles") - 沒有角色（關聯表無命中時 GORM 會略過 roles 查詢）
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}))

	expectFinishLoginUpdate(mock)

	req := &LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := service.Login(req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Empty(t, resp.User.Roles)

	// 驗證 token 中的主要角色是預設的 "user"
	claims, err := service.ValidateToken(resp.Token)
	assert.NoError(t, err)
	assert.Equal(t, "user", claims.Role)
}

// TestValidateToken_Success 測試驗證有效 token
func TestValidateToken_Success(t *testing.T) {
	service := NewAuthService("secret", 15*time.Minute)

	// 生成一個有效的 token
	token, err := service.jwtManager.GenerateToken(1, "testuser", "test@example.com", "admin", crypto.AuthContext{})
	assert.NoError(t, err)

	// 驗證 token
	claims, err := service.ValidateToken(token)

	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, uint(1), claims.UserID)
	assert.Equal(t, "testuser", claims.Username)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "admin", claims.Role)
}

// TestValidateToken_InvalidToken 測試驗證無效 token
func TestValidateToken_InvalidToken(t *testing.T) {
	service := NewAuthService("secret", 15*time.Minute)

	tests := []struct {
		name  string
		token string
	}{
		{"Empty token", ""},
		{"Invalid format", "invalid.token"},
		{"Random string", "random-string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := service.ValidateToken(tt.token)

			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}
}

// TestGetUserByID_Success 測試根據 ID 查詢使用者
func TestGetUserByID_Success(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	userID := uint(123)

	// Mock 查詢使用者（含 is_ldap：前端據此隱藏自助改密）
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "full_name", "active", "is_ldap"}).
		AddRow(userID, "john.doe", "john@example.com", "John Doe", true, true)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnRows(userRows)

	// Mock Preload("Roles")
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(userID, 1))
	roleRows := sqlmock.NewRows([]string{"id", "name"}).
		AddRow(1, "user")
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(roleRows)

	userInfo, err := service.GetUserByID(userID)

	assert.NoError(t, err)
	assert.NotNil(t, userInfo)
	assert.Equal(t, userID, userInfo.ID)
	assert.Equal(t, "john.doe", userInfo.Username)
	assert.Equal(t, "john@example.com", userInfo.Email)
	assert.Equal(t, "John Doe", userInfo.FullName)
	assert.True(t, userInfo.Active)
	assert.Contains(t, userInfo.Roles, "user")
	assert.True(t, userInfo.IsLDAP)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestGetUserByID_NotFound 測試查詢不存在的使用者
func TestGetUserByID_NotFound(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret", 15*time.Minute)

	userID := uint(999)

	// Mock 查詢使用者 - 不存在
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE .+ LIMIT`).
		WillReturnError(gorm.ErrRecordNotFound)

	userInfo, err := service.GetUserByID(userID)

	assert.Error(t, err)
	assert.Equal(t, ErrUserNotFound, err)
	assert.Nil(t, userInfo)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogin_TokenValidation 測試登入後的 token 可以正確驗證
func TestLogin_TokenValidation(t *testing.T) {
	_, mock, _ := setupAuthMockDB(t)
	service := NewAuthService("secret-key-123", 15*time.Minute)

	username := "tokenuser"
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Mock 查詢使用者
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
		AddRow(42, username, "token@example.com", string(hashedPassword), "Token User", true)
	mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
		WillReturnRows(userRows)

	// Mock Preload("Roles")
	mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "role_id"}).AddRow(42, 1))
	roleRows := sqlmock.NewRows([]string{"id", "name"}).
		AddRow(1, "auditor")
	mock.ExpectQuery(`SELECT .+ FROM "roles"`).
		WillReturnRows(roleRows)

	expectFinishLoginUpdate(mock)

	// 執行登入
	req := &LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := service.Login(req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// 驗證 token 包含正確的使用者資訊
	claims, err := service.ValidateToken(resp.Token)
	assert.NoError(t, err)
	assert.Equal(t, uint(42), claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.Equal(t, "token@example.com", claims.Email)
	assert.Equal(t, "auditor", claims.Role)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogin_PrimaryRoleSelection 測試主要角色選擇邏輯
func TestLogin_PrimaryRoleSelection(t *testing.T) {
	tests := []struct {
		name         string
		roles        []string
		expectedRole string
	}{
		{
			name:         "Admin takes priority",
			roles:        []string{"user", "admin", "auditor"},
			expectedRole: "admin",
		},
		{
			name:         "Auditor over user regardless of order (auditor first)",
			roles:        []string{"auditor", "user"},
			expectedRole: "auditor",
		},
		{
			name:         "Auditor over user regardless of order (user first)",
			roles:        []string{"user", "auditor"},
			expectedRole: "auditor",
		},
		{
			name:         "Single role",
			roles:        []string{"user"},
			expectedRole: "user",
		},
		{
			name:         "No roles defaults to user",
			roles:        []string{},
			expectedRole: "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, _ := setupAuthMockDB(t)
			service := NewAuthService("secret", 15*time.Minute)

			username := "roletest"
			password := "password123"
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			// Mock 查詢使用者
			userRows := sqlmock.NewRows([]string{"id", "username", "email", "password", "full_name", "active"}).
				AddRow(1, username, "role@example.com", string(hashedPassword), "Role Test", true)
			mock.ExpectQuery(`SELECT .+ FROM "users" WHERE username`).
				WillReturnRows(userRows)

			// Mock Preload("Roles")
			userRolesRows := sqlmock.NewRows([]string{"user_id", "role_id"})
			for i := range tt.roles {
				userRolesRows.AddRow(1, i+1)
			}
			mock.ExpectQuery(`SELECT .+ FROM "user_roles"`).
				WillReturnRows(userRolesRows)

			// 關聯表無命中時 GORM 會略過 roles 查詢，僅有角色時 mock
			if len(tt.roles) > 0 {
				roleRows := sqlmock.NewRows([]string{"id", "name"})
				for i, roleName := range tt.roles {
					roleRows.AddRow(i+1, roleName)
				}
				mock.ExpectQuery(`SELECT .+ FROM "roles"`).
					WillReturnRows(roleRows)
			}

			expectFinishLoginUpdate(mock)

			req := &LoginRequest{
				Username: username,
				Password: password,
			}

			resp, err := service.Login(req)
			assert.NoError(t, err)
			if assert.NotNil(t, resp, "Login response should not be nil") {
				// 驗證 token 中的角色
				claims, err := service.ValidateToken(resp.Token)
				assert.NoError(t, err)
				if assert.NotNil(t, claims) {
					assert.Equal(t, tt.expectedRole, claims.Role)
				}
			}
		})
	}
}
