package api

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// setupSessionGateEnv 建立經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT）的測試環境，
// 用於鎖定 session-access-scoping 的無條件守門：敏感讀取端點一律要求 session:view。
// 原以 FEATURE_PERMISSION_CHECK_ENABLED 為維度，該旗標已於 security-backlog-settlement 退場
func setupSessionGateEnv(t *testing.T) (*gin.Engine, *crypto.JWTManager) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// 世代閘現查 users（M6 起 DB 未注入即 fail-close）：token 宣稱的 1／2 兩個 ID 須存在
	installEpochGateDB(t, 1, 2)

	jwtSecret := "gate-test-secret"
	authService := identity.NewAuthService(jwtSecret, time.Minute)

	sessionMock := new(MockSessionService)
	sessionMock.On("List", mock.Anything).Return(&session.SessionListResponse{}, nil).Maybe()
	sessionMock.On("GetByID", mock.Anything).Return(&model.Session{ID: 1}, nil).Maybe()
	sessionMock.On("GetActiveSessions").Return([]model.Session{}, nil).Maybe()
	sessionMock.On("GetStatistics").Return(map[string]interface{}{}, nil).Maybe()

	commandMock := new(MockSessionCommandService)
	commandMock.On("ListBySession", mock.Anything).Return([]model.SessionCommand{}, nil).Maybe()

	r := gin.New()
	group := r.Group("/api/v1")
	NewSessionHandler(sessionMock).RegisterRoutes(group, authService)
	NewSessionCommandHandler(commandMock).RegisterRoutes(group, authService)

	return r, crypto.NewJWTManager(jwtSecret, time.Minute)
}

func getWithToken(t *testing.T, r *gin.Engine, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// 五個敏感讀取端點（列表/活動/統計/詳情/per-session 指令）
var sensitiveReadPaths = []string{
	"/api/v1/sessions",
	"/api/v1/sessions/active",
	"/api/v1/sessions/statistics",
	"/api/v1/sessions/1",
	"/api/v1/sessions/1/commands",
}

// TestSessionReadGate_UserDenied user 角色對敏感讀取端點一律 403
// （session:view 已自 user 角色移除；權限檢查無條件生效，無旗標可旁路）
func TestSessionReadGate_UserDenied(t *testing.T) {
	r, mgr := setupSessionGateEnv(t)

	userToken, err := mgr.GenerateToken(2, "normaluser", "u@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	for _, path := range sensitiveReadPaths {
		w := getWithToken(t, r, path, userToken)
		assert.Equal(t, http.StatusForbidden, w.Code,
			"user 對 %s 應 403，實得 %d", path, w.Code)
	}
}

// TestSessionReadGate_AuditorAdminStillAllowed 收權不影響稽核職能
func TestSessionReadGate_AuditorAdminStillAllowed(t *testing.T) {
	r, mgr := setupSessionGateEnv(t)

	for _, role := range []string{"auditor", "admin"} {
		token, err := mgr.GenerateToken(1, role, role+"@example.com", role, crypto.AuthContext{})
		assert.NoError(t, err)

		for _, path := range sensitiveReadPaths {
			w := getWithToken(t, r, path, token)
			assert.Equal(t, http.StatusOK, w.Code,
				"%s 對 %s 應 200，實得 %d", role, path, w.Code)
		}
	}
}

// TestSessionReadGate_UnauthenticatedRejected 無 token 一律 401（守門在 auth 之後）
func TestSessionReadGate_UnauthenticatedRejected(t *testing.T) {
	r, _ := setupSessionGateEnv(t)

	for _, path := range sensitiveReadPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"無 token 對 %s 應 401，實得 %d", path, w.Code)
	}
}
