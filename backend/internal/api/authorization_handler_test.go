package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// uptr 便捷取址（AssetAuthorization.UserID 為 *uint）
func uptr(v uint) *uint { return &v }

// MockAuthorizationService - AuthorizationServiceInterface 的 mock
type MockAuthorizationService struct {
	mock.Mock
}

func (m *MockAuthorizationService) Grant(ctx context.Context, spec authz.GrantSpec) (*model.AssetAuthorization, error) {
	args := m.Called(ctx, spec)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetAuthorization), args.Error(1)
}

func (m *MockAuthorizationService) GrantBatch(ctx context.Context, userIDs, userGroupIDs, assetIDs, assetGroupIDs []uint, permission model.PermissionType, grantedBy uint, accounts *[]string) (*authz.BatchGrantResult, error) {
	args := m.Called(ctx, userIDs, userGroupIDs, assetIDs, assetGroupIDs, permission, grantedBy, accounts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authz.BatchGrantResult), args.Error(1)
}

func (m *MockAuthorizationService) UpdateAccountScope(ctx context.Context, authorizationID uint, accounts *[]string) (*model.AssetAuthorization, error) {
	args := m.Called(ctx, authorizationID, accounts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetAuthorization), args.Error(1)
}

func (m *MockAuthorizationService) ListAuthorizations(filters map[string]interface{}, page, pageSize int) ([]*model.AssetAuthorization, int64, error) {
	args := m.Called(filters, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuthorizationService) ListUserGroupAuthorizations(userGroupID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error) {
	args := m.Called(userGroupID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuthorizationService) RevokePermission(ctx context.Context, authorizationID uint) error {
	args := m.Called(ctx, authorizationID)
	return args.Error(0)
}

func (m *MockAuthorizationService) ListUserAuthorizations(userID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error) {
	args := m.Called(userID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuthorizationService) ListAssetAuthorizations(assetID uint, page, pageSize int) ([]*model.AssetAuthorization, int64, error) {
	args := m.Called(assetID, page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.AssetAuthorization), args.Get(1).(int64), args.Error(2)
}

// TestAuthorizationHandler_Create 測試創建授權
func TestAuthorizationHandler_Create(t *testing.T) {
	t.Run("成功創建授權", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		// 準備測試數據
		assetID := uint(10)
		createdAuth := &model.AssetAuthorization{
			ID:         1,
			UserID:     uptr(2),
			AssetID:    &assetID,
			Permission: model.PermissionConnect,
			GrantedBy:  1,
			CreatedAt:  time.Now(),
			User: model.User{
				ID:       2,
				Username: "testuser",
			},
			Asset: &model.Asset{
				ID:   10,
				Name: "test-server",
			},
		}

		mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
			return spec.UserID != nil && *spec.UserID == 2 && spec.AssetID != nil && *spec.AssetID == 10 &&
				spec.Permission == model.PermissionConnect && spec.GrantedBy == 1
		})).
			Return(createdAuth, nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			// 模擬認證中間件設定 userID
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   10,
			"permission": "connect",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(1), response["id"])
		assert.Equal(t, float64(2), response["user_id"])
		assert.Equal(t, "testuser", response["username"])
		assert.Equal(t, float64(10), response["asset_id"])
		assert.Equal(t, "test-server", response["asset_name"])
		assert.Equal(t, "connect", response["permission"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("請求格式錯誤（缺少必填欄位）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id": 2,
			// 缺少 asset_id 和 permission
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求格式錯誤")
	})

	t.Run("無效的權限類型", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   10,
			"permission": "invalid_permission",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求格式錯誤")
	})

	t.Run("manage 等級已移除應拒收（J 兩階收斂）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   10,
			"permission": "manage",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		// binding oneof 擋下，不觸及 service 層
		mockAuthService.AssertNotCalled(t, "Grant")
	})

	t.Run("未認證（無 userID）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", handler.Create)

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   10,
			"permission": "connect",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "未認證")
	})

	t.Run("授權已存在（衝突）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
			return spec.UserID != nil && *spec.UserID == 2 && spec.AssetID != nil && *spec.AssetID == 10 &&
				spec.Permission == model.PermissionConnect && spec.GrantedBy == 1
		})).
			Return(nil, authz.ErrAuthorizationExists)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   10,
			"permission": "connect",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "授權已存在")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("用戶不存在（404）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
			return spec.UserID != nil && *spec.UserID == 999 && spec.AssetID != nil && *spec.AssetID == 10 &&
				spec.Permission == model.PermissionConnect && spec.GrantedBy == 1
		})).
			Return(nil, fmt.Errorf("%w: ID=999", authz.ErrGrantUserNotFound))

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    999,
			"asset_id":   10,
			"permission": "connect",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		// NOTFOUND_GRANT_REFERENCE 帶 params.entity，回應非純字串 map
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("資產不存在（404）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
			return spec.UserID != nil && *spec.UserID == 2 && spec.AssetID != nil && *spec.AssetID == 999 &&
				spec.Permission == model.PermissionConnect && spec.GrantedBy == 1
		})).
			Return(nil, fmt.Errorf("%w: ID=999", authz.ErrGrantAssetNotFound))

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   999,
			"permission": "connect",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		// NOTFOUND_GRANT_REFERENCE 帶 params.entity，回應非純字串 map
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "資產不存在")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
			return spec.UserID != nil && *spec.UserID == 2 && spec.AssetID != nil && *spec.AssetID == 10 &&
				spec.Permission == model.PermissionConnect && spec.GrantedBy == 1
		})).
			Return(nil, errors.New("database error"))

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		requestBody := map[string]interface{}{
			"user_id":    2,
			"asset_id":   10,
			"permission": "connect",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		// 內部錯誤不得洩漏至回應
		assert.Equal(t, "建立授權失敗", response["error"])
		assert.NotContains(t, response["error"], "database error")

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationHandler_Delete 測試刪除授權
func TestAuthorizationHandler_Delete(t *testing.T) {
	t.Run("成功刪除授權", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("RevokePermission", mock.Anything, uint(1)).Return(nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/authorizations/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/authorizations/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// message 欄已移除（成功回應不攜帶 UI 文案）
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotContains(t, response, "message")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("無效的授權 ID", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/authorizations/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/authorizations/invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的授權 ID")
	})

	t.Run("授權不存在（404）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("RevokePermission", mock.Anything, uint(999)).
			Return(authz.ErrAuthorizationNotFound)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/authorizations/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/authorizations/999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "授權不存在")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("ticket 裸刪守門 409", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("RevokePermission", mock.Anything, uint(108)).
			Return(authz.ErrTicketRevocationRequired)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/authorizations/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/authorizations/108", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		var response map[string]string
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Contains(t, response["error"], "申請單撤銷流")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("RevokePermission", mock.Anything, uint(1)).
			Return(errors.New("database error"))

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.DELETE("/authorizations/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/authorizations/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "撤銷授權失敗")

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationHandler_List 測試查詢授權列表
func TestAuthorizationHandler_List(t *testing.T) {
	t.Run("成功查詢用戶授權列表", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		assetID := uint(10)
		authorizations := []*model.AssetAuthorization{
			{
				ID:         1,
				UserID:     uptr(2),
				AssetID:    &assetID,
				Permission: model.PermissionConnect,
				GrantedBy:  1,
				CreatedAt:  time.Now(),
				User: model.User{
					ID:       2,
					Username: "testuser",
				},
				Asset: &model.Asset{
					ID:       10,
					Name:     "test-server",
					Protocol: model.ProtocolSSH,
				},
			},
		}

		mockAuthService.On("ListAuthorizations", map[string]interface{}{"user_id": uint(2)}, 1, 20).
			Return(authorizations, int64(1), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?user_id=2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(1), response["total"])
		assert.Equal(t, float64(1), response["page"])
		assert.Equal(t, float64(20), response["page_size"])

		data := response["data"].([]interface{})
		assert.Equal(t, 1, len(data))

		mockAuthService.AssertExpectations(t)
	})

	t.Run("組授權記錄帶分組目標", func(t *testing.T) {
		// serializer 原只帶資產資訊，組授權記錄無法辨識指向
		mockAuthService := new(MockAuthorizationService)

		groupID := uint(5)
		authorizations := []*model.AssetAuthorization{
			{
				ID:           7,
				UserID:       uptr(2),
				AssetGroupID: &groupID,
				Permission:   model.PermissionConnect,
				GrantedBy:    1,
				CreatedAt:    time.Now(),
				User:         model.User{ID: 2, Username: "testuser"},
				AssetGroup:   &model.AssetGroup{ID: 5, Name: "prod-group"},
			},
		}

		mockAuthService.On("ListAuthorizations", map[string]interface{}{"user_id": uint(2)}, 1, 20).
			Return(authorizations, int64(1), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?user_id=2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		data := response["data"].([]interface{})
		assert.Equal(t, 1, len(data))
		item := data[0].(map[string]interface{})
		assert.Equal(t, float64(5), item["asset_group_id"])
		assert.Equal(t, "prod-group", item["asset_group_name"])
		// 組授權無資產欄位
		assert.NotContains(t, item, "asset_id")
		assert.NotContains(t, item, "asset_name")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("成功查詢資產授權列表", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		assetID := uint(10)
		authorizations := []*model.AssetAuthorization{
			{
				ID:         1,
				UserID:     uptr(2),
				AssetID:    &assetID,
				Permission: model.PermissionView,
				GrantedBy:  1,
				CreatedAt:  time.Now(),
				User: model.User{
					ID:       2,
					Username: "user1",
				},
				Asset: &model.Asset{
					ID:       10,
					Name:     "test-server",
					Protocol: model.ProtocolRDP,
				},
			},
			{
				ID:         2,
				UserID:     uptr(3),
				AssetID:    &assetID,
				Permission: model.PermissionConnect,
				GrantedBy:  1,
				CreatedAt:  time.Now(),
				User: model.User{
					ID:       3,
					Username: "user2",
				},
				Asset: &model.Asset{
					ID:       10,
					Name:     "test-server",
					Protocol: model.ProtocolRDP,
				},
			},
		}

		mockAuthService.On("ListAuthorizations", map[string]interface{}{"asset_id": uint(10)}, 1, 20).
			Return(authorizations, int64(2), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?asset_id=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(2), response["total"])

		data := response["data"].([]interface{})
		assert.Equal(t, 2, len(data))

		mockAuthService.AssertExpectations(t)
	})

	t.Run("零參數走全量列表", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("ListAuthorizations", map[string]interface{}{}, 1, 20).
			Return([]*model.AssetAuthorization{}, int64(0), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, float64(0), response["total"])
		mockAuthService.AssertExpectations(t)
	})

	t.Run("同時指定 user_id 和 asset_id", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?user_id=2&asset_id=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "至多指定一個")
	})

	t.Run("三態與 ticket 欄位序列化", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		assetID := uint(10)
		past := time.Now().Add(-2 * time.Hour)
		expired := time.Now().Add(-1 * time.Hour)
		future := time.Now().Add(24 * time.Hour)
		reqID := uint(28)
		authorizations := []*model.AssetAuthorization{
			{ // 過期 ticket：expired + revocable=false + request_id
				ID: 108, UserID: uptr(2), AssetID: &assetID, Permission: model.PermissionConnect,
				GrantedBy: 1, CreatedAt: past, Source: model.AuthorizationSourceTicket,
				DateStart: &past, DateExpired: &expired, RequestID: &reqID,
				User:  model.User{ID: 2, Username: "testuser"},
				Asset: &model.Asset{ID: 10, Name: "test-server", Protocol: model.ProtocolSSH},
			},
			{ // 未生效 ticket：scheduled（不得混標 expired）+ revocable=false
				ID: 109, UserID: uptr(2), AssetID: &assetID, Permission: model.PermissionConnect,
				GrantedBy: 1, CreatedAt: past, Source: model.AuthorizationSourceTicket,
				DateStart: &future, RequestID: &reqID,
				User:  model.User{ID: 2, Username: "testuser"},
				Asset: &model.Asset{ID: 10, Name: "test-server", Protocol: model.ProtocolSSH},
			},
			{ // 常設 manual：active、無 revocable 欄
				ID: 54, UserID: uptr(2), AssetID: &assetID, Permission: model.PermissionConnect,
				GrantedBy: 1, CreatedAt: past, Source: model.AuthorizationSourceManual,
				User:  model.User{ID: 2, Username: "testuser"},
				Asset: &model.Asset{ID: 10, Name: "test-server", Protocol: model.ProtocolSSH},
			},
		}

		mockAuthService.On("ListAuthorizations", map[string]interface{}{}, 1, 20).
			Return(authorizations, int64(3), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		data := response["data"].([]interface{})
		assert.Equal(t, 3, len(data))

		expiredItem := data[0].(map[string]interface{})
		assert.Equal(t, "ticket", expiredItem["source"])
		assert.Equal(t, "expired", expiredItem["validity_state"])
		assert.Equal(t, false, expiredItem["revocable"])
		assert.Equal(t, float64(28), expiredItem["request_id"])
		assert.Contains(t, expiredItem, "date_expired")

		scheduledItem := data[1].(map[string]interface{})
		assert.Equal(t, "scheduled", scheduledItem["validity_state"])
		assert.Equal(t, false, scheduledItem["revocable"])

		manualItem := data[2].(map[string]interface{})
		assert.Equal(t, "manual", manualItem["source"])
		assert.Equal(t, "active", manualItem["validity_state"])
		assert.NotContains(t, manualItem, "revocable")
		assert.NotContains(t, manualItem, "request_id")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("有效 ticket revocable=true", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		assetID := uint(10)
		past := time.Now().Add(-1 * time.Hour)
		future := time.Now().Add(1 * time.Hour)
		reqID := uint(31)
		authorizations := []*model.AssetAuthorization{
			{
				ID: 120, UserID: uptr(2), AssetID: &assetID, Permission: model.PermissionConnect,
				GrantedBy: 1, CreatedAt: past, Source: model.AuthorizationSourceTicket,
				DateStart: &past, DateExpired: &future, RequestID: &reqID,
				User:  model.User{ID: 2, Username: "testuser"},
				Asset: &model.Asset{ID: 10, Name: "test-server", Protocol: model.ProtocolSSH},
			},
		}

		mockAuthService.On("ListAuthorizations", map[string]interface{}{}, 1, 20).
			Return(authorizations, int64(1), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		item := response["data"].([]interface{})[0].(map[string]interface{})
		assert.Equal(t, "active", item["validity_state"])
		assert.Equal(t, true, item["revocable"])
		assert.Equal(t, float64(31), item["request_id"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("validity 與 source 篩選傳遞伺服端", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("ListAuthorizations", mock.MatchedBy(func(f map[string]interface{}) bool {
			vf, ok := f["validity"].(authz.ValidityFilter)
			return ok && vf.State == model.ValidityExpired && !vf.Now.IsZero() &&
				f["source"] == model.AuthorizationSourceTicket && len(f) == 2
		}), 1, 20).
			Return([]*model.AssetAuthorization{}, int64(0), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?validity=expired&source=ticket", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("無效 validity 400", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?validity=bogus", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAuthService.AssertNotCalled(t, "ListAuthorizations")
	})

	t.Run("無效的 user_id", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?user_id=invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// VALIDATION_INVALID_QUERY_PARAM 帶 params.field，回應非純字串 map；
		// {field} 渲染為 zh 顯示字
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的 使用者 ID")
	})

	t.Run("無效的 asset_id", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?asset_id=invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// VALIDATION_INVALID_QUERY_PARAM 帶 params.field，回應非純字串 map；
		// {field} 渲染為 zh 顯示字
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的 資產 ID")
	})

	t.Run("自定義分頁參數", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("ListAuthorizations", map[string]interface{}{"user_id": uint(2)}, 2, 10).
			Return([]*model.AssetAuthorization{}, int64(0), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?user_id=2&page=2&page_size=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(2), response["page"])
		assert.Equal(t, float64(10), response["page_size"])

		mockAuthService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤（查詢用戶授權）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("ListAuthorizations", map[string]interface{}{"user_id": uint(2)}, 1, 20).
			Return(nil, int64(0), errors.New("database error"))

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?user_id=2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "查詢授權失敗")

		mockAuthService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤（查詢資產授權）", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)

		mockAuthService.On("ListAuthorizations", map[string]interface{}{"asset_id": uint(10)}, 1, 20).
			Return(nil, int64(0), errors.New("database error"))

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?asset_id=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "查詢授權失敗")

		mockAuthService.AssertExpectations(t)
	})
}

// TestAuthorizationHandler_Create_GroupSubject 群組主體授權
func TestAuthorizationHandler_Create_GroupSubject(t *testing.T) {
	t.Run("群組主體成功", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)
		gid := uint(5)
		agid := uint(2)
		mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
			return spec.UserID == nil && spec.UserGroupID != nil && *spec.UserGroupID == 5 &&
				spec.AssetGroupID != nil && *spec.AssetGroupID == 2
		})).Return(&model.AssetAuthorization{
			ID: 9, UserGroupID: &gid, AssetGroupID: &agid,
			Permission: model.PermissionConnect, GrantedBy: 1,
			UserGroup:  &model.UserGroup{ID: 5, Name: "ops"},
			AssetGroup: &model.AssetGroup{ID: 2, Name: "prod"},
		}, nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		body, _ := json.Marshal(map[string]interface{}{
			"user_group_id": 5, "asset_group_id": 2, "permission": "connect",
		})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, float64(5), resp["user_group_id"])
		assert.Equal(t, "ops", resp["user_group_name"])
		assert.NotContains(t, resp, "user_id")
		mockAuthService.AssertExpectations(t)
	})

	t.Run("主體同給或皆缺 400", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)
		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.POST("/authorizations", func(c *gin.Context) {
			c.Set("userID", uint(1))
			handler.Create(c)
		})

		for _, body := range []map[string]interface{}{
			{"user_id": 2, "user_group_id": 5, "asset_id": 1, "permission": "view"},
			{"asset_id": 1, "permission": "view"},
		} {
			b, _ := json.Marshal(body)
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(b))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "user_id 與 user_group_id 必須二擇一")
		}
		mockAuthService.AssertNotCalled(t, "Grant", mock.Anything, mock.Anything)
	})
}

// TestAuthorizationHandler_Create_IgnoresValidityInput 時效欄位手填封鎖
// （spec「手填入口關閉」：CreateRequest 無時效欄位，
// 客戶端傳入的 date_start/date_expired 不進 GrantSpec，一律永久授權）
func TestAuthorizationHandler_Create_IgnoresValidityInput(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	assetID := uint(10)
	// 攔截 spec：GrantSpec 無任何時效欄位可承載外部輸入（結構性保證）
	mockAuthService.On("Grant", mock.Anything, mock.MatchedBy(func(spec authz.GrantSpec) bool {
		return spec.UserID != nil && *spec.UserID == 2 && spec.AssetID != nil && *spec.AssetID == 10
	})).Return(&model.AssetAuthorization{
		ID: 1, UserID: uptr(2), AssetID: &assetID,
		Permission: model.PermissionView, GrantedBy: 1,
		User: model.User{ID: 2, Username: "u"},
	}, nil)

	handler := NewAuthorizationHandler(mockAuthService, nil)
	router := setupTestRouter()
	router.POST("/authorizations", func(c *gin.Context) {
		c.Set("userID", uint(1))
		handler.Create(c)
	})

	// 客戶端惡意帶時效欄位
	body, _ := json.Marshal(map[string]interface{}{
		"user_id": 2, "asset_id": 10, "permission": "view",
		"date_start": "2020-01-01T00:00:00Z", "date_expired": "2099-01-01T00:00:00Z",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/authorizations", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// 回應不帶時效欄位（永久授權）
	var resp map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotContains(t, resp, "date_start")
	assert.NotContains(t, resp, "date_expired")
	mockAuthService.AssertExpectations(t)
}

// TestAuthorizationHandler_BatchCreate 批次授權端點
func TestAuthorizationHandler_BatchCreate(t *testing.T) {
	newRouter := func(mockSvc *MockAuthorizationService, withAuth bool) *gin.Engine {
		handler := NewAuthorizationHandler(mockSvc, nil)
		router := setupTestRouter()
		router.POST("/authorizations/batch", func(c *gin.Context) {
			if withAuth {
				c.Set("userID", uint(1))
			}
			handler.BatchCreate(c)
		})
		return router
	}
	post := func(router *gin.Engine, payload map[string]interface{}) *httptest.ResponseRecorder {
		b, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/authorizations/batch", bytes.NewBuffer(b))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("展開成功回 created/skipped", func(t *testing.T) {
		mockSvc := new(MockAuthorizationService)
		mockSvc.On("GrantBatch", mock.Anything, []uint{2, 3}, []uint{5}, []uint{1}, []uint{4},
			model.PermissionConnect, uint(1), (*[]string)(nil)).
			Return(&authz.BatchGrantResult{Created: 8, Skipped: 1}, nil)
		router := newRouter(mockSvc, true)

		w := post(router, map[string]interface{}{
			"user_ids": []uint{2, 3}, "user_group_ids": []uint{5},
			"asset_ids": []uint{1}, "asset_group_ids": []uint{4},
			"permission": "connect",
		})
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"created":8`)
		assert.Contains(t, w.Body.String(), `"skipped":1`)
		mockSvc.AssertExpectations(t)
	})

	t.Run("空主體 400", func(t *testing.T) {
		mockSvc := new(MockAuthorizationService)
		mockSvc.On("GrantBatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything).Return(nil, authz.ErrBatchEmpty)
		router := newRouter(mockSvc, true)

		w := post(router, map[string]interface{}{"asset_ids": []uint{1}, "permission": "view"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("超上限 400", func(t *testing.T) {
		mockSvc := new(MockAuthorizationService)
		mockSvc.On("GrantBatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything).Return(nil, authz.ErrBatchTooLarge)
		router := newRouter(mockSvc, true)

		w := post(router, map[string]interface{}{"user_ids": []uint{2}, "asset_ids": []uint{1}, "permission": "view"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "上限")
	})

	t.Run("引用不存在 404", func(t *testing.T) {
		mockSvc := new(MockAuthorizationService)
		mockSvc.On("GrantBatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("%w: 使用者名單含不存在的 ID", authz.ErrGrantUserNotFound))
		router := newRouter(mockSvc, true)

		w := post(router, map[string]interface{}{"user_ids": []uint{999}, "asset_ids": []uint{1}, "permission": "view"})
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("未認證 401", func(t *testing.T) {
		mockSvc := new(MockAuthorizationService)
		router := newRouter(mockSvc, false)

		w := post(router, map[string]interface{}{"user_ids": []uint{2}, "asset_ids": []uint{1}, "permission": "view"})
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockSvc.AssertNotCalled(t, "GrantBatch")
	})

	t.Run("manage 等級已移除應拒收（J 兩階收斂）", func(t *testing.T) {
		mockSvc := new(MockAuthorizationService)
		router := newRouter(mockSvc, true)

		w := post(router, map[string]interface{}{"user_ids": []uint{2}, "asset_ids": []uint{1}, "permission": "manage"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockSvc.AssertNotCalled(t, "GrantBatch")
	})
}

// TestAuthorizationHandler_List_UserGroupFilter user_group_id 過濾與群組主體序列化
func TestAuthorizationHandler_List_UserGroupFilter(t *testing.T) {
	mockAuthService := new(MockAuthorizationService)
	gid := uint(5)
	aid := uint(10)
	mockAuthService.On("ListAuthorizations", map[string]interface{}{"user_group_id": uint(5)}, 1, 20).
		Return([]*model.AssetAuthorization{{
			ID: 1, UserGroupID: &gid, AssetID: &aid,
			Permission: model.PermissionConnect, GrantedBy: 1, CreatedAt: time.Now(),
			UserGroup: &model.UserGroup{ID: 5, Name: "ops"},
			Asset:     &model.Asset{ID: 10, Name: "srv", Protocol: model.ProtocolSSH},
		}}, int64(1), nil)

	handler := NewAuthorizationHandler(mockAuthService, nil)
	router := setupTestRouter()
	router.GET("/authorizations", handler.List)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/authorizations?user_group_id=5", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].([]interface{})
	assert.Equal(t, 1, len(data))
	item := data[0].(map[string]interface{})
	assert.Equal(t, float64(5), item["user_group_id"])
	assert.Equal(t, "ops", item["user_group_name"])
	assert.NotContains(t, item, "user_id")
	mockAuthService.AssertExpectations(t)
}

// ===== 有效權限雙視角端點 =====

// MockEffectiveResolver - EffectiveAccessResolverInterface 的 mock
type MockEffectiveResolver struct {
	mock.Mock
}

func (m *MockEffectiveResolver) ResolveEffectiveAssets(subjectUserID uint, now time.Time) (*authz.EffectiveAssetsResult, error) {
	args := m.Called(subjectUserID, now)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authz.EffectiveAssetsResult), args.Error(1)
}

func (m *MockEffectiveResolver) ResolveEffectiveUsers(assetID uint, now time.Time) (*authz.EffectiveUsersResult, error) {
	args := m.Called(assetID, now)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authz.EffectiveUsersResult), args.Error(1)
}

func TestAuthorizationHandler_EffectiveAssets(t *testing.T) {
	t.Run("成功回傳主體視角", func(t *testing.T) {
		resolver := new(MockEffectiveResolver)
		resolver.On("ResolveEffectiveAssets", uint(153), mock.Anything).
			Return(&authz.EffectiveAssetsResult{
				UserID: 153, Username: "testldap", RoleOverride: "",
				Assets: []authz.EffectiveAssetEntry{{AssetID: 1, AssetName: "srv", Permission: model.PermissionConnect}},
			}, nil)

		handler := NewAuthorizationHandler(new(MockAuthorizationService), resolver)
		router := setupTestRouter()
		router.GET("/authorizations/effective-assets", handler.EffectiveAssets)

		req := httptest.NewRequest("GET", "/authorizations/effective-assets?user_id=153", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "testldap", response["username"])
		assert.Equal(t, 1, len(response["assets"].([]interface{})))
		resolver.AssertExpectations(t)
	})

	t.Run("無效 user_id 400", func(t *testing.T) {
		handler := NewAuthorizationHandler(new(MockAuthorizationService), new(MockEffectiveResolver))
		router := setupTestRouter()
		router.GET("/authorizations/effective-assets", handler.EffectiveAssets)

		req := httptest.NewRequest("GET", "/authorizations/effective-assets?user_id=abc", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("主體不存在 404", func(t *testing.T) {
		resolver := new(MockEffectiveResolver)
		resolver.On("ResolveEffectiveAssets", uint(9999), mock.Anything).
			Return(nil, authz.ErrEffectiveSubjectNotFound)

		handler := NewAuthorizationHandler(new(MockAuthorizationService), resolver)
		router := setupTestRouter()
		router.GET("/authorizations/effective-assets", handler.EffectiveAssets)

		req := httptest.NewRequest("GET", "/authorizations/effective-assets?user_id=9999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestAuthorizationHandler_EffectiveUsers(t *testing.T) {
	t.Run("成功回傳客體視角含 role_override 摘要", func(t *testing.T) {
		resolver := new(MockEffectiveResolver)
		resolver.On("ResolveEffectiveUsers", uint(1), mock.Anything).
			Return(&authz.EffectiveUsersResult{
				AssetID: 1, AssetName: "srv", RoleOverrideNote: "admin 角色帳號隱含可及、auditor 角色帳號隱含檢視本資產（角色權限，不逐人列舉）",
				Users: []authz.EffectiveUserEntry{{UserID: 153, Username: "testldap", Permission: model.PermissionConnect}},
			}, nil)

		handler := NewAuthorizationHandler(new(MockAuthorizationService), resolver)
		router := setupTestRouter()
		router.GET("/authorizations/effective-users", handler.EffectiveUsers)

		req := httptest.NewRequest("GET", "/authorizations/effective-users?asset_id=1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.NotEmpty(t, response["role_override_note"])
		assert.Equal(t, 1, len(response["users"].([]interface{})))
		resolver.AssertExpectations(t)
	})

	t.Run("資產不存在 404", func(t *testing.T) {
		resolver := new(MockEffectiveResolver)
		resolver.On("ResolveEffectiveUsers", uint(9999), mock.Anything).
			Return(nil, authz.ErrEffectiveAssetNotFound)

		handler := NewAuthorizationHandler(new(MockAuthorizationService), resolver)
		router := setupTestRouter()
		router.GET("/authorizations/effective-users", handler.EffectiveUsers)

		req := httptest.NewRequest("GET", "/authorizations/effective-users?asset_id=9999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestAuthorizationHandler_List_NodeFilter：
// node_id 第四維——互斥 400、傳遞入 filters、與 validity 疊加、非法值 400
func TestAuthorizationHandler_List_NodeFilter(t *testing.T) {
	t.Run("node_id 與 user_id 互斥 400", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)
		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?node_id=2&user_id=1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var response map[string]string
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Contains(t, response["error"], "至多指定一個")
		mockAuthService.AssertNotCalled(t, "ListAuthorizations")
	})

	t.Run("node_id 傳遞並與 validity 疊加", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)
		mockAuthService.On("ListAuthorizations", mock.MatchedBy(func(f map[string]interface{}) bool {
			nodeID, hasNode := f["node_id"].(uint)
			vf, hasValidity := f["validity"].(authz.ValidityFilter)
			return hasNode && nodeID == 2 && hasValidity && vf.State == model.ValidityExpired
		}), 1, 20).Return([]*model.AssetAuthorization{}, int64(0), nil)

		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?node_id=2&validity=expired", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("非法 node_id 400", func(t *testing.T) {
		mockAuthService := new(MockAuthorizationService)
		handler := NewAuthorizationHandler(mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/authorizations", handler.List)

		req := httptest.NewRequest("GET", "/authorizations?node_id=abc", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAuthService.AssertNotCalled(t, "ListAuthorizations")
	})
}
