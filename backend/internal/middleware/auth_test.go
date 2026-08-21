package middleware

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// installEpochGateDB 裝一個最小的 database.DB 並建出 token 宣稱的使用者列。
//
// AuthMiddleware 的憑證世代閘現查 users.credential_epoch，且 **DB 未注入時一律拒**
// （批 14 對抗審查 M6：原本回 nil 放行，等於整套撤銷機制可被一條漏接的組裝路徑
// 靜默關掉）。本檔的正向案例因此需要一個真的查得到使用者的 DB
func installEpochGateDB(t *testing.T, userIDs ...uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("migrate users: %v", err)
	}
	for _, id := range userIDs {
		u := &model.User{Username: "gate-user", Password: "x", Active: true}
		u.ID = id
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("seed user %d: %v", id, err)
		}
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
}

// setupAuthTestRouter 建立掛載 AuthMiddleware 的測試路由
func setupAuthTestRouter(jwtSecret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	authService := identity.NewAuthService(jwtSecret, time.Minute)

	r := gin.New()
	r.GET("/protected", AuthMiddleware(authService), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})
	return r
}

// TestAuthMiddleware_RejectsMFAPendingScope 測試 pending token 不得存取一般 API
func TestAuthMiddleware_RejectsMFAPendingScope(t *testing.T) {
	jwtSecret := "test-secret"
	r := setupAuthTestRouter(jwtSecret)

	// 產生 mfa_pending scope 的 token（與 Login 第一階段相同方式）
	mgr := crypto.NewJWTManager(jwtSecret, time.Minute)
	pendingToken, err := mgr.GenerateScopedToken(1, "mfauser", "mfa@example.com", "user", crypto.ScopeMFAPending, 5*time.Minute, crypto.AuthContext{})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pendingToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "MFA")
}

// TestAuthMiddleware_AllowsNormalToken 測試正式 token 行為不變
func TestAuthMiddleware_AllowsNormalToken(t *testing.T) {
	jwtSecret := "test-secret"
	installEpochGateDB(t, 1)
	r := setupAuthTestRouter(jwtSecret)

	mgr := crypto.NewJWTManager(jwtSecret, time.Minute)
	token, err := mgr.GenerateToken(1, "normaluser", "normal@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestAuthMiddleware_RejectsMissingToken 測試未帶 token 被拒
func TestAuthMiddleware_RejectsMissingToken(t *testing.T) {
	r := setupAuthTestRouter("test-secret")

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestAuthMiddleware_RejectsQueryToken JWT 僅經 Authorization header 接受
// （transmission-security-policy M8）：有效 JWT 走 ?token= 一律 401，
// 防長效權杖落 access log／proxy 日誌
func TestAuthMiddleware_RejectsQueryToken(t *testing.T) {
	jwtSecret := "test-secret"
	r := setupAuthTestRouter(jwtSecret)

	mgr := crypto.NewJWTManager(jwtSecret, time.Minute)
	token, err := mgr.GenerateToken(1, "queryuser", "q@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/protected?token="+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "未提供認證 token")
}
