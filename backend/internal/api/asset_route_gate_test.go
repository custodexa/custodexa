package api

import (
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockHostKeyService - HostKeyServiceInterface 的 mock
type MockHostKeyService struct {
	mock.Mock
}

func (m *MockHostKeyService) Get(assetID uint) (*model.AssetHostKey, error) {
	args := m.Called(assetID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetHostKey), args.Error(1)
}

func (m *MockHostKeyService) Reset(assetID uint) (bool, error) {
	args := m.Called(assetID)
	return args.Bool(0), args.Error(1)
}

// setupAssetGateEnv 經完整 RegisterRoutes（真 AuthMiddleware＋真 JWT）建立測試環境，
// 鎖定 asset-access-scoping 的逐資產守門：/assets/:id、/:id/k8s/pods、/:id/host-key
// 三端點掛 RequireAssetVisible。原以 FEATURE_PERMISSION_CHECK_ENABLED 為維度，
// 該旗標已於 security-backlog-settlement 退場，逐資產守門本就無條件生效
func setupAssetGateEnv(t *testing.T, allow bool) (*gin.Engine, *crypto.JWTManager, *MockAssetAuthorizationService) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// 世代閘現查 users（M6 起 DB 未注入即 fail-close）：token 宣稱的 1／7 兩個 ID 須存在
	installEpochGateDB(t, 1, 7)

	jwtSecret := "asset-gate-test-secret"
	authService := identity.NewAuthService(jwtSecret, time.Minute)

	assetMock := new(MockAssetService)
	assetMock.On("GetByID", mock.Anything).Return(&model.Asset{ID: 1, Name: "gate-asset"}, nil).Maybe()
	assetMock.On("ListK8sPods", mock.Anything, mock.Anything).Return([]k8sproxy.PodInfo{}, nil).Maybe()

	authzMock := new(MockAssetAuthorizationService)
	authzMock.On("CheckPermission", mock.Anything, mock.Anything, mock.Anything, model.PermissionView).
		Return(allow, nil).Maybe()

	hostKeyMock := new(MockHostKeyService)
	hostKeyMock.On("Get", mock.Anything).Return(&model.AssetHostKey{AssetID: 1}, nil).Maybe()

	r := gin.New()
	group := r.Group("/api/v1")
	NewAssetHandler(assetMock, authzMock, nil).RegisterRoutes(group, authService)
	NewHostKeyHandler(hostKeyMock, authzMock).RegisterRoutes(group, authService)

	return r, crypto.NewJWTManager(jwtSecret, time.Minute), authzMock
}

// 三個逐資產讀取端點（詳情/k8s pods/host key）
var perAssetReadPaths = []string{
	"/api/v1/assets/1",
	"/api/v1/assets/1/k8s/pods",
	"/api/v1/assets/1/host-key",
}

// TestAssetReadGate_UnauthorizedUser404BothFlags 未授權 user 於兩種旗標狀態
// 皆 404「資產不存在」——守門無條件生效、不洩漏存在性
func TestAssetReadGate_UnauthorizedUser404(t *testing.T) {
	r, mgr, _ := setupAssetGateEnv(t, false)

	userToken, err := mgr.GenerateToken(7, "normaluser", "u@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	for _, path := range perAssetReadPaths {
		w := getWithToken(t, r, path, userToken)
		assert.Equal(t, http.StatusNotFound, w.Code,
			"未授權 user 對 %s 應 404，實得 %d", path, w.Code)
		assert.Contains(t, w.Body.String(), "資產不存在",
			"%s 回應應為統一的「資產不存在」", path)
	}
}

// TestAssetReadGate_AuthorizedUserAllowed 有 view 授權的 user 於兩種旗標狀態皆放行
func TestAssetReadGate_AuthorizedUserAllowed(t *testing.T) {
	r, mgr, _ := setupAssetGateEnv(t, true)

	userToken, err := mgr.GenerateToken(7, "normaluser", "u@example.com", "user", crypto.AuthContext{})
	assert.NoError(t, err)

	for _, path := range perAssetReadPaths {
		w := getWithToken(t, r, path, userToken)
		assert.Equal(t, http.StatusOK, w.Code,
			"已授權 user 對 %s 應 200，實得 %d", path, w.Code)
	}
}

// TestAssetReadGate_AdminAuditorBypass admin/auditor 直通逐資產守門
// （checker 設拒絕仍 200，證明特權不觸發逐資產授權查詢）
func TestAssetReadGate_AdminAuditorBypass(t *testing.T) {
	for _, role := range []string{"admin", "auditor"} {
		r, mgr, authzMock := setupAssetGateEnv(t, false)

		token, err := mgr.GenerateToken(1, role, role+"@example.com", role, crypto.AuthContext{})
		assert.NoError(t, err)

		for _, path := range perAssetReadPaths {
			w := getWithToken(t, r, path, token)
			assert.Equal(t, http.StatusOK, w.Code,
				"%s 對 %s 應 200，實得 %d", role, path, w.Code)
		}
		authzMock.AssertNotCalled(t, "CheckPermission",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	}
}

// TestAssetReadGate_UnauthenticatedRejected 無 token 一律 401
func TestAssetReadGate_UnauthenticatedRejected(t *testing.T) {
	r, _, _ := setupAssetGateEnv(t, true)

	for _, path := range perAssetReadPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code,
			"無 token 對 %s 應 401，實得 %d", path, w.Code)
	}
}
