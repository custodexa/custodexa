package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAssetService - AssetService 的 mock
type MockAssetService struct {
	mock.Mock
}

func (m *MockAssetService) List(filter *asset.AssetFilter) (*asset.AssetListResponse, error) {
	args := m.Called(filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*asset.AssetListResponse), args.Error(1)
}

func (m *MockAssetService) GetByID(id uint) (*model.Asset, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Asset), args.Error(1)
}

func (m *MockAssetService) Create(req *asset.CreateAssetRequest) (*model.Asset, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Asset), args.Error(1)
}

func (m *MockAssetService) Update(ctx context.Context, id uint, req *asset.UpdateAssetRequest) (*model.Asset, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Asset), args.Error(1)
}

func (m *MockAssetService) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockAssetService) TestConnection(ctx context.Context, id uint, timeout int) (*asset.ConnectionTestResult, error) {
	args := m.Called(ctx, id, timeout)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*asset.ConnectionTestResult), args.Error(1)
}

func (m *MockAssetService) ListK8sPods(ctx context.Context, id uint) ([]k8sproxy.PodInfo, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]k8sproxy.PodInfo), args.Error(1)
}

func (m *MockAssetService) K8sCopyToPod(ctx context.Context, id uint, pod, container, destPath, localPath string) error {
	return m.Called(ctx, id, pod, container, destPath, localPath).Error(0)
}

func (m *MockAssetService) K8sCopyFromPod(ctx context.Context, id uint, pod, container, srcPath, localPath string) error {
	return m.Called(ctx, id, pod, container, srcPath, localPath).Error(0)
}

// 節點過濾/資訊填充：未顯式設定期望時回無過濾/no-op，
// 讓既有測試不需逐一補 On 設定
func (m *MockAssetService) AssetIDsForNodeFilter(nodeID *uint, includeSubtree, ungrouped bool) (map[uint]bool, error) {
	args := m.Called(nodeID, includeSubtree, ungrouped)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]bool), args.Error(1)
}

func (m *MockAssetService) ListTags() ([]asset.TagCount, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]asset.TagCount), args.Error(1)
}

func (m *MockAssetService) RenameTag(ctx context.Context, from, to string) (int64, error) {
	args := m.Called(from, to)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAssetService) DeleteTag(ctx context.Context, name string) (int64, error) {
	args := m.Called(name)
	return args.Get(0).(int64), args.Error(1)
}

// MockAssetAuthorizationService - AssetAuthorizationService 的 mock
type MockAssetAuthorizationService struct {
	mock.Mock
}

// FillNodeInfoForDTOs 為 best-effort 填充（handler 失敗僅 log 不擋列表），
// mock 固定 no-op——授權分支既有測試免逐一補期望；填充語義由 service 測試驗
func (m *MockAssetAuthorizationService) FillNodeInfoForDTOs(dtos []*authz.AuthorizedAssetDTO) error {
	return nil
}

func (m *MockAssetAuthorizationService) CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error) {
	args := m.Called(ctx, userID, assetID, perm)
	return args.Bool(0), args.Error(1)
}

func (m *MockAssetAuthorizationService) GetAuthorizedAssets(ctx context.Context, userID uint, perm model.PermissionType) ([]*authz.AuthorizedAssetDTO, error) {
	args := m.Called(ctx, userID, perm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*authz.AuthorizedAssetDTO), args.Error(1)
}

func (m *MockAssetAuthorizationService) ExplicitAuthorizedAssetIDs(userID uint, perm model.PermissionType) (map[uint]bool, error) {
	args := m.Called(userID, perm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]bool), args.Error(1)
}

func (m *MockAssetAuthorizationService) GrantPermission(ctx context.Context, userID, assetID uint, permission model.PermissionType, grantedBy uint) (*model.AssetAuthorization, error) {
	args := m.Called(ctx, userID, assetID, permission, grantedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetAuthorization), args.Error(1)
}

func (m *MockAssetAuthorizationService) RevokePermission(ctx context.Context, authorizationID uint) error {
	args := m.Called(ctx, authorizationID)
	return args.Error(0)
}

func (m *MockAssetAuthorizationService) ListUserAuthorizations(userID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error) {
	args := m.Called(userID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Get(1).(int64), args.Error(2)
}

func (m *MockAssetAuthorizationService) ListAssetAuthorizations(assetID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error) {
	args := m.Called(assetID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Get(1).(int64), args.Error(2)
}

// setupTestRouter 創建測試用的路由器
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	return router
}

// TestAssetHandler_List 測試資產列表
func TestAssetHandler_List(t *testing.T) {
	t.Run("成功獲取資產列表", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		expectedResponse := &asset.AssetListResponse{
			Data: []model.Asset{
				{ID: 1, Name: "test-asset-1", Protocol: "ssh"},
				{ID: 2, Name: "test-asset-2", Protocol: "rdp"},
			},
			Total:    2,
			Page:     1,
			PageSize: 20,
		}
		mockAssetService.On("List", mock.AnythingOfType("*asset.AssetFilter")).Return(expectedResponse, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		// 收斂後全量分支僅 admin/auditor 可達
		router.GET("/assets", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response asset.AssetListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(response.Data))
		assert.Equal(t, int64(2), response.Total)

		mockAssetService.AssertExpectations(t)
	})

	t.Run("成功獲取資產列表（帶搜尋）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		expectedResponse := &asset.AssetListResponse{
			Data: []model.Asset{
				{ID: 1, Name: "prod-server", Protocol: "ssh"},
			},
			Total:    1,
			Page:     1,
			PageSize: 20,
		}
		mockAssetService.On("List", mock.MatchedBy(func(filter *asset.AssetFilter) bool {
			return filter.Search == "prod"
		})).Return(expectedResponse, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets?search=prod", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response asset.AssetListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(response.Data))

		mockAssetService.AssertExpectations(t)
	})

	t.Run("成功獲取資產列表（帶協議篩選）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		expectedResponse := &asset.AssetListResponse{
			Data: []model.Asset{
				{ID: 1, Name: "ssh-server", Protocol: "ssh"},
			},
			Total:    1,
			Page:     1,
			PageSize: 20,
		}
		mockAssetService.On("List", mock.MatchedBy(func(filter *asset.AssetFilter) bool {
			return filter.Protocol == model.ProtocolSSH
		})).Return(expectedResponse, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets?protocol=ssh", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response asset.AssetListResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(response.Data))

		mockAssetService.AssertExpectations(t)
	})

	t.Run("成功獲取資產列表（帶 authorized_only）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		authorizedAssets := []*authz.AuthorizedAssetDTO{
			{Asset: model.Asset{ID: 1, Name: "authorized-server", Protocol: "ssh"}, Permission: model.PermissionConnect},
		}
		mockAuthService.On("GetAuthorizedAssets", mock.Anything, uint(1), model.PermissionView).
			Return(authorizedAssets, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			// 模擬認證中間件設定 userID
			c.Set("userID", uint(1))
			c.Set("role", "user")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets?authorized_only=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(1), response["total"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("authorized_only 但未認證", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", handler.List)

		req := httptest.NewRequest("GET", "/assets?authorized_only=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "未認證")
	})

	t.Run("Service 層錯誤處理", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("List", mock.AnythingOfType("*asset.AssetFilter")).
			Return(nil, errors.New("database error"))

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "查詢資產失敗")

		mockAssetService.AssertExpectations(t)
	})

	t.Run("分頁參數驗證", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		expectedResponse := &asset.AssetListResponse{
			Data:     []model.Asset{},
			Total:    0,
			Page:     2,
			PageSize: 10,
		}
		mockAssetService.On("List", mock.MatchedBy(func(filter *asset.AssetFilter) bool {
			return filter.Page == 2 && filter.PageSize == 10
		})).Return(expectedResponse, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets?page=2&page_size=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockAssetService.AssertExpectations(t)
	})
}

// TestAssetHandler_Create 測試創建資產
func TestAssetHandler_Create(t *testing.T) {
	t.Run("成功創建資產", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		createdAsset := &model.Asset{
			ID:       1,
			Name:     "new-server",
			Protocol: "ssh",
			Host:     "192.168.1.100",
			Port:     22,
			Username: "admin",
		}
		mockAssetService.On("Create", mock.MatchedBy(func(req *asset.CreateAssetRequest) bool {
			return req.Name == "new-server" && req.CreatedBy == uint(1)
		})).Return(createdAsset, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets", func(c *gin.Context) {
			// 模擬認證中間件設定 userID
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"name":     "new-server",
			"protocol": "ssh",
			"host":     "192.168.1.100",
			"port":     22,
			"username": "admin",
			"password": "secret",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response model.Asset
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "new-server", response.Name)

		mockAssetService.AssertExpectations(t)
	})

	t.Run("請求格式錯誤（缺少必填欄位）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"name": "incomplete-server",
			// 缺少 protocol, host, port, username
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求格式錯誤")
	})

	t.Run("未認證（無 userID）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets", handler.Create)

		requestBody := map[string]interface{}{
			"name":     "test-server",
			"protocol": "ssh",
			"host":     "192.168.1.100",
			"port":     22,
			"username": "admin",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "未認證")
	})

	t.Run("Service 層錯誤（資產名稱重複）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("Create", mock.AnythingOfType("*asset.CreateAssetRequest")).
			Return(nil, asset.ErrAssetNameExists)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"name":     "duplicate-server",
			"protocol": "ssh",
			"host":     "192.168.1.100",
			"port":     22,
			"username": "admin",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/assets", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "資產名稱已存在")

		mockAssetService.AssertExpectations(t)
	})
}

// TestAssetHandler_Get 測試獲取資產詳情
func TestAssetHandler_Get(t *testing.T) {
	t.Run("成功獲取資產詳情", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		asset := &model.Asset{
			ID:       1,
			Name:     "test-server",
			Protocol: "ssh",
			Host:     "192.168.1.100",
			Port:     22,
			Username: "admin",
		}
		mockAssetService.On("GetByID", uint(1)).Return(asset, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		// admin 不做逐資產授權檢查
		router.GET("/assets/:id", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Get(c)
		})

		req := httptest.NewRequest("GET", "/assets/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response model.Asset
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "test-server", response.Name)

		mockAssetService.AssertExpectations(t)
	})

	t.Run("無效的資產 ID", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets/:id", handler.Get)

		req := httptest.NewRequest("GET", "/assets/invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// 碼化後封套帶 params（VALIDATION_INVALID_ID 的 resource），改用 any 解
		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的資產 ID")
		assert.Equal(t, "VALIDATION_INVALID_ID", response["code"])
	})

	t.Run("資產不存在（404）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("GetByID", uint(999)).Return(nil, asset.ErrAssetNotFound)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets/:id", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Get(c)
		})

		req := httptest.NewRequest("GET", "/assets/999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "資產不存在")

		mockAssetService.AssertExpectations(t)
	})
}

// TestAssetHandler_ServerSideScoping 伺服端授權收斂：
// 非 admin/auditor 的讀取可視面一律由伺服端裁決
func TestAssetHandler_ServerSideScoping(t *testing.T) {
	t.Run("一般 user 不帶參數也強制走授權分支", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		authorizedAssets := []*authz.AuthorizedAssetDTO{
			{Asset: model.Asset{ID: 1, Name: "granted-server", Protocol: "ssh"}, Permission: model.PermissionConnect},
			{Asset: model.Asset{ID: 2, Name: "granted-view", Protocol: "rdp"}, Permission: model.PermissionView},
		}
		mockAuthService.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return(authorizedAssets, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			c.Set("role", "user")
			handler.List(c)
		})

		// 不帶 authorized_only——伺服端仍須強制授權集合
		req := httptest.NewRequest("GET", "/assets", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Data  []map[string]interface{} `json:"data"`
			Total int                      `json:"total"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, response.Total)
		assert.Equal(t, "connect", response.Data[0]["permission"])
		assert.Equal(t, "view", response.Data[1]["permission"])

		// 全量分支不可被觸及
		mockAssetService.AssertNotCalled(t, "List", mock.Anything)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("一般 user 帶 authorized_only=false 仍強制授權分支", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAuthService.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return([]*authz.AuthorizedAssetDTO{}, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			c.Set("role", "user")
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets?authorized_only=false", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAssetService.AssertNotCalled(t, "List", mock.Anything)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("角色缺失視為非特權", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAuthService.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return([]*authz.AuthorizedAssetDTO{}, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			// 不設 role
			handler.List(c)
		})

		req := httptest.NewRequest("GET", "/assets", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAssetService.AssertNotCalled(t, "List", mock.Anything)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("授權集合內套用搜尋與分頁", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		authorizedAssets := []*authz.AuthorizedAssetDTO{
			{Asset: model.Asset{ID: 1, Name: "prod-web", Host: "10.0.0.1", Protocol: "ssh", Active: true}, Permission: model.PermissionConnect},
			{Asset: model.Asset{ID: 2, Name: "prod-db", Host: "10.0.0.2", Protocol: "postgres", Active: true}, Permission: model.PermissionView},
			{Asset: model.Asset{ID: 3, Name: "staging-web", Host: "10.0.1.1", Protocol: "ssh", Active: true}, Permission: model.PermissionConnect},
		}
		mockAuthService.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return(authorizedAssets, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			c.Set("role", "user")
			handler.List(c)
		})

		// search=prod 命中 2 筆；page_size=1 只回第一頁一筆但 total=2
		req := httptest.NewRequest("GET", "/assets?search=prod&page=1&page_size=1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Data  []map[string]interface{} `json:"data"`
			Total int                      `json:"total"`
		}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, response.Total)     // 篩選後總數
		assert.Equal(t, 1, len(response.Data)) // 當頁切片
		mockAuthService.AssertExpectations(t)
	})

	// 逐資產授權由 RequireAssetVisible 中介層守門——以下為 handler+中介層整合路由
	t.Run("user 未授權資產詳情經中介層回 404 且不觸 DB", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAuthService.On("CheckPermission", mock.Anything, uint(7), uint(42), model.PermissionView).
			Return(false, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets/:id",
			func(c *gin.Context) { c.Set("userID", uint(7)); c.Set("role", "user") },
			middleware.RequireAssetVisible(mockAuthService), handler.Get)

		req := httptest.NewRequest("GET", "/assets/42", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		var response map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "資產不存在")
		mockAssetService.AssertNotCalled(t, "GetByID", mock.Anything)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("user 已授權資產詳情經中介層 200", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		asset := &model.Asset{ID: 42, Name: "granted-server", Protocol: "ssh"}
		mockAuthService.On("CheckPermission", mock.Anything, uint(7), uint(42), model.PermissionView).
			Return(true, nil)
		mockAssetService.On("GetByID", uint(42)).Return(asset, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets/:id",
			func(c *gin.Context) { c.Set("userID", uint(7)); c.Set("role", "user") },
			middleware.RequireAssetVisible(mockAuthService), handler.Get)

		req := httptest.NewRequest("GET", "/assets/42", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAssetService.AssertExpectations(t)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("user 未授權 k8s pods 經中介層回 404", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAuthService.On("CheckPermission", mock.Anything, uint(7), uint(42), model.PermissionView).
			Return(false, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets/:id/k8s/pods",
			func(c *gin.Context) { c.Set("userID", uint(7)); c.Set("role", "user") },
			middleware.RequireAssetVisible(mockAuthService), handler.ListK8sPods)

		req := httptest.NewRequest("GET", "/assets/42/k8s/pods", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockAssetService.AssertNotCalled(t, "ListK8sPods", mock.Anything, mock.Anything)
		mockAuthService.AssertExpectations(t)
	})
}

// TestAssetHandler_Update 測試更新資產
func TestAssetHandler_Update(t *testing.T) {
	t.Run("成功更新資產", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		updatedAsset := &model.Asset{
			ID:       1,
			Name:     "updated-server",
			Protocol: "ssh",
			Host:     "192.168.1.101",
			Port:     22,
			Username: "admin",
		}
		mockAssetService.On("Update", mock.Anything, uint(1), mock.AnythingOfType("*asset.UpdateAssetRequest")).
			Return(updatedAsset, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.PUT("/assets/:id", func(c *gin.Context) {
			c.Set("userID", uint(1))
			c.Set("username", "testuser")
			handler.Update(c)
		})

		requestBody := map[string]interface{}{
			"name": "updated-server",
			"host": "192.168.1.101",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/assets/1", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response model.Asset
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "updated-server", response.Name)

		mockAssetService.AssertExpectations(t)
	})

	t.Run("無效的資產 ID", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.PUT("/assets/:id", handler.Update)

		requestBody := map[string]interface{}{
			"name": "test",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/assets/invalid", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// 碼化後封套帶 params（VALIDATION_INVALID_ID 的 resource），改用 any 解
		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的資產 ID")
		assert.Equal(t, "VALIDATION_INVALID_ID", response["code"])
	})

	t.Run("請求格式錯誤", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.PUT("/assets/:id", handler.Update)

		req := httptest.NewRequest("PUT", "/assets/1", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求格式錯誤")
	})

	t.Run("資產不存在", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("Update", mock.Anything, uint(999), mock.AnythingOfType("*asset.UpdateAssetRequest")).
			Return(nil, asset.ErrAssetNotFound)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.PUT("/assets/:id", handler.Update)

		requestBody := map[string]interface{}{
			"name": "test",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/assets/999", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		mockAssetService.AssertExpectations(t)
	})
}

// TestAssetHandler_Delete 測試刪除資產
func TestAssetHandler_Delete(t *testing.T) {
	t.Run("成功刪除資產", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("Delete", uint(1)).Return(nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/assets/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/assets/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// 成功回應不再攜帶 UI 文案（前端以 $t 提示）
		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotContains(t, response, "message")

		mockAssetService.AssertExpectations(t)
	})

	t.Run("無效的資產 ID", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/assets/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/assets/invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// 碼化後封套帶 params（VALIDATION_INVALID_ID 的 resource），改用 any 解
		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的資產 ID")
		assert.Equal(t, "VALIDATION_INVALID_ID", response["code"])
	})

	t.Run("資產不存在", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("Delete", uint(999)).Return(asset.ErrAssetNotFound)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/assets/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/assets/999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "資產不存在")

		mockAssetService.AssertExpectations(t)
	})
}

// TestAssetHandler_TestConnection 測試連線測試
func TestAssetHandler_TestConnection(t *testing.T) {
	t.Run("成功測試連線", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		testResult := &asset.ConnectionTestResult{
			Success:  true,
			Message:  "連線成功",
			Protocol: "ssh",
		}
		mockAssetService.On("TestConnection", mock.Anything, uint(1), 10).
			Return(testResult, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets/:id/test-connection", handler.TestConnection)

		requestBody := map[string]interface{}{
			"timeout": 10,
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/assets/1/test-connection", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response asset.ConnectionTestResult
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response.Success)
		assert.Equal(t, "連線成功", response.Message)

		mockAssetService.AssertExpectations(t)
	})

	t.Run("使用預設超時時間", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		testResult := &asset.ConnectionTestResult{
			Success: true,
			Message: "連線成功",
		}
		mockAssetService.On("TestConnection", mock.Anything, uint(1), 10).
			Return(testResult, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets/:id/test-connection", handler.TestConnection)

		// 不傳遞 timeout，應使用預設值 10
		req := httptest.NewRequest("POST", "/assets/1/test-connection", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockAssetService.AssertExpectations(t)
	})

	t.Run("無效的資產 ID", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets/:id/test-connection", handler.TestConnection)

		req := httptest.NewRequest("POST", "/assets/invalid/test-connection", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// 碼化後封套帶 params（VALIDATION_INVALID_ID 的 resource），改用 any 解
		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的資產 ID")
		assert.Equal(t, "VALIDATION_INVALID_ID", response["code"])
	})

	t.Run("資產不存在", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("TestConnection", mock.Anything, uint(999), 10).
			Return(nil, asset.ErrAssetNotFound)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets/:id/test-connection", handler.TestConnection)

		req := httptest.NewRequest("POST", "/assets/999/test-connection", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "資產不存在")

		mockAssetService.AssertExpectations(t)
	})

	t.Run("Service 層連線失敗", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("TestConnection", mock.Anything, uint(1), 10).
			Return(nil, errors.New("connection refused"))

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/assets/:id/test-connection", handler.TestConnection)

		req := httptest.NewRequest("POST", "/assets/1/test-connection", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "連線測試失敗")

		mockAssetService.AssertExpectations(t)
	})
}

// TestAssetHandler_DownloadK8sFile_NoLeak pins the error-code
// security fix: a failing K8s copy must not leak the raw error (kubectl
// stderr / container paths) into the response body; it returns a generalized
// message + code at 502.
func TestAssetHandler_DownloadK8sFile_NoLeak(t *testing.T) {
	mockAssetService := new(MockAssetService)
	mockAuthService := new(MockAssetAuthorizationService)

	secret := "kubectl stderr: cp /var/secret/token failed at 10.9.9.9"
	mockAssetService.On("K8sCopyFromPod", mock.Anything, uint(7), "mypod", "myctr", "/etc/passwd", mock.AnythingOfType("string")).
		Return(errors.New(secret))

	handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
	router := setupTestRouter()
	router.GET("/assets/:id/k8s/download", func(c *gin.Context) {
		c.Set("userID", uint(7))
		handler.DownloadK8sFile(c)
	})

	req := httptest.NewRequest("GET", "/assets/7/k8s/download?pod=mypod&container=myctr&path=/etc/passwd", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code) // 保留 502
	body := w.Body.String()
	assert.NotContains(t, body, "secret", "response leaks internal error")
	assert.NotContains(t, body, "10.9.9.9")
	assert.NotContains(t, body, "kubectl")

	var resp map[string]any
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "檔案傳輸失敗", resp["error"])
	assert.Equal(t, "INTERNAL_K8S_COPY", resp["code"])
	mockAssetService.AssertExpectations(t)
}

// TestAssetHandler_AuditorEntryPermission auditor 連線入口判定欄
// 全量分支對 auditor 當頁標 permission
// （顯式 connect grant 命中 connect、餘 view）；admin 回應形狀凍結不帶欄；
// 集合查詢失敗降級全 view 不擋列表
func TestAssetHandler_AuditorEntryPermission(t *testing.T) {
	fullList := &asset.AssetListResponse{
		Data: []model.Asset{
			{ID: 1, Name: "granted-connect", Protocol: "ssh"},
			{ID: 2, Name: "view-only", Protocol: "rdp"},
		},
		Total:    2,
		Page:     1,
		PageSize: 20,
	}

	mountList := func(handler *AssetHandler, role string, userID uint) *gin.Engine {
		router := setupTestRouter()
		router.GET("/assets", func(c *gin.Context) {
			c.Set("userID", userID)
			c.Set("role", role)
			handler.List(c)
		})
		return router
	}

	t.Run("auditor 列表帶 permission：顯式 grant 命中 connect、餘 view", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)
		mockAssetService.On("List", mock.AnythingOfType("*asset.AssetFilter")).Return(fullList, nil)
		mockAuthService.On("ExplicitAuthorizedAssetIDs", uint(82), model.PermissionConnect).
			Return(map[uint]bool{1: true}, nil)

		router := mountList(NewAssetHandler(mockAssetService, mockAuthService, nil), "auditor", 82)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/assets", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Data  []map[string]interface{} `json:"data"`
			Total int                      `json:"total"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 2, response.Total)
		assert.Equal(t, "connect", response.Data[0]["permission"])
		assert.Equal(t, "view", response.Data[1]["permission"])
		mockAuthService.AssertExpectations(t)
	})

	t.Run("admin 回應形狀凍結：不帶 permission 欄", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)
		mockAssetService.On("List", mock.AnythingOfType("*asset.AssetFilter")).Return(fullList, nil)

		router := mountList(NewAssetHandler(mockAssetService, mockAuthService, nil), "admin", 1)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/assets", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Data []map[string]interface{} `json:"data"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		for _, row := range response.Data {
			_, has := row["permission"]
			assert.False(t, has, "admin 列表回應不得帶 permission 欄")
		}
		mockAuthService.AssertNotCalled(t, "ExplicitAuthorizedAssetIDs", mock.Anything, mock.Anything)
	})

	t.Run("auditor 集合查詢失敗：降級全 view、列表照常回傳", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)
		mockAssetService.On("List", mock.AnythingOfType("*asset.AssetFilter")).Return(fullList, nil)
		mockAuthService.On("ExplicitAuthorizedAssetIDs", uint(82), model.PermissionConnect).
			Return(nil, assert.AnError)

		router := mountList(NewAssetHandler(mockAssetService, mockAuthService, nil), "auditor", 82)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/assets", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Data []map[string]interface{} `json:"data"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 2, len(response.Data))
		for _, row := range response.Data {
			assert.Equal(t, "view", row["permission"])
		}
	})
}

// TestAssetHandler_ErrorEnvelope 資產端點的機器碼封套：
// 已知 sentinel 依 errors.Is 映射到碼、狀態碼與遷移前一致；未知錯誤走 INTERNAL_*
// 且成因不外洩；角色閘與參數驗證同樣帶碼。
func TestAssetHandler_ErrorEnvelope(t *testing.T) {
	decode := func(w *httptest.ResponseRecorder) map[string]any {
		var body map[string]any
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return body
	}

	t.Run("資產名稱衝突回 409 CONFLICT_ASSET_NAME", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("Create", mock.Anything).Return(nil, asset.ErrAssetNameExists)

		handler := NewAssetHandler(mockAssetService, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.POST("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Create(c)
		})

		req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString(`{"name":"a","host":"h","port":22,"protocol":"ssh","username":"u","password":"p"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		body := decode(w)
		assert.Equal(t, "CONFLICT_ASSET_NAME", body["code"])
		assert.Equal(t, "資產名稱已存在", body["error"])
	})

	t.Run("建立資產未知錯誤走 INTERNAL_ASSET_CREATE 不外洩成因", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("Create", mock.Anything).Return(nil, errors.New("dsn=postgres://secret@10.9.9.9"))

		handler := NewAssetHandler(mockAssetService, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.POST("/assets", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Create(c)
		})

		req := httptest.NewRequest("POST", "/assets", bytes.NewBufferString(`{"name":"a","host":"h","port":22,"protocol":"ssh","username":"u","password":"p"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "INTERNAL_ASSET_CREATE", decode(w)["code"])
		assert.NotContains(t, w.Body.String(), "10.9.9.9")
	})

	t.Run("無效資產 ID 回 400 VALIDATION_INVALID_ID 帶 resource param", func(t *testing.T) {
		handler := NewAssetHandler(new(MockAssetService), new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.GET("/assets/:id", handler.Get)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/assets/abc", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		body := decode(w)
		assert.Equal(t, "VALIDATION_INVALID_ID", body["code"])
		assert.Equal(t, "無效的資產 ID", body["error"])
		params, _ := body["params"].(map[string]any)
		assert.Equal(t, "asset", params["resource"])
	})

	t.Run("標籤清單角色閘回 403 AUTH_TAG_LIST_PRIVILEGED_ONLY", func(t *testing.T) {
		handler := NewAssetHandler(new(MockAssetService), new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.GET("/assets/tags", func(c *gin.Context) {
			c.Set("role", "user")
			handler.ListTags(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/assets/tags", nil))

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, "AUTH_TAG_LIST_PRIVILEGED_ONLY", decode(w)["code"])
	})

	t.Run("標籤改名驗證錯誤回 400 VALIDATION_TAG_TOO_LONG", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("RenameTag", "a", "b").Return(int64(0), asset.ErrTagTooLong)

		handler := NewAssetHandler(mockAssetService, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.POST("/assets/tags/rename", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.RenameTag(c)
		})

		req := httptest.NewRequest("POST", "/assets/tags/rename", bytes.NewBufferString(`{"from":"a","to":"b"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "VALIDATION_TAG_TOO_LONG", decode(w)["code"])
	})
}
