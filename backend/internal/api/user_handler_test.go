package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserService - UserService 的 mock
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) List(req *identity.ListUsersRequest) (*identity.UserListResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*identity.UserListResponse), args.Error(1)
}

func (m *MockUserService) GetByID(id uint) (*model.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) Create(req *identity.CreateUserRequest) (*model.User, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserService) Update(id uint, req *identity.UpdateUserRequest) (*model.User, map[string]string, error) {
	args := m.Called(id, req)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	var diff map[string]string
	if d, ok := args.Get(1).(map[string]string); ok {
		diff = d
	}
	return args.Get(0).(*model.User), diff, args.Error(2)
}

func (m *MockUserService) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserService) AssignRoles(userID uint, roleNames []string) error {
	args := m.Called(userID, roleNames)
	return args.Error(0)
}

func (m *MockUserService) AddRole(userID uint, roleName string) error {
	args := m.Called(userID, roleName)
	return args.Error(0)
}

func (m *MockUserService) UpdateStatus(userID uint, active bool) error {
	args := m.Called(userID, active)
	return args.Error(0)
}

func (m *MockUserService) ChangePassword(userID uint, newPassword string) error {
	args := m.Called(userID, newPassword)
	return args.Error(0)
}

func (m *MockUserService) Unlock(userID uint) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserService) SetInactivityExempt(userID uint, exempt bool) error {
	args := m.Called(userID, exempt)
	return args.Error(0)
}

func (m *MockUserService) CountLocalAdmins() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

// 外部身分管理四操作
func (m *MockUserService) ListExternalIdentities(userID uint) ([]identity.ExternalIdentityDTO, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]identity.ExternalIdentityDTO), args.Error(1)
}

func (m *MockUserService) BindExternalIdentity(userID, providerID uint, subject string,
	actor identity.IdentityAdminActor) (*identity.ExternalIdentityDTO, error) {
	args := m.Called(userID, providerID, subject, actor)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*identity.ExternalIdentityDTO), args.Error(1)
}

func (m *MockUserService) UnbindExternalIdentity(userID, identityID uint,
	actor identity.IdentityAdminActor) error {
	args := m.Called(userID, identityID, actor)
	return args.Error(0)
}

func (m *MockUserService) UnbindExternalIdentityAndDisable(userID, identityID uint,
	actor identity.IdentityAdminActor) error {
	args := m.Called(userID, identityID, actor)
	return args.Error(0)
}

func (m *MockUserService) ConvertToExternalOnly(userID uint, actor identity.IdentityAdminActor) error {
	args := m.Called(userID, actor)
	return args.Error(0)
}

// TestUserHandler_List 測試用戶列表
func TestUserHandler_List(t *testing.T) {
	t.Run("成功獲取用戶列表", func(t *testing.T) {
		mockUserService := new(MockUserService)

		activeTrue := true
		expectedResponse := &identity.UserListResponse{
			Data: []model.User{
				{ID: 1, Username: "admin", Email: emailPtr("admin@example.com"), Active: activeTrue, Roles: []model.Role{}},
				{ID: 2, Username: "user1", Email: emailPtr("user1@example.com"), Active: activeTrue, Roles: []model.Role{}},
			},
			Total: 2,
		}
		mockUserService.On("List", mock.AnythingOfType("*identity.ListUsersRequest")).
			Return(expectedResponse, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users", handler.List)

		req := httptest.NewRequest("GET", "/users", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(2), response["total"])

		data := response["data"].([]interface{})
		assert.Equal(t, 2, len(data))

		mockUserService.AssertExpectations(t)
	})

	t.Run("帶搜尋條件", func(t *testing.T) {
		mockUserService := new(MockUserService)

		activeTrue := true
		expectedResponse := &identity.UserListResponse{
			Data: []model.User{
				{ID: 1, Username: "admin", Email: emailPtr("admin@example.com"), Active: activeTrue, Roles: []model.Role{}},
			},
			Total: 1,
		}
		mockUserService.On("List", mock.MatchedBy(func(req *identity.ListUsersRequest) bool {
			return req.Search == "admin"
		})).Return(expectedResponse, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users", handler.List)

		req := httptest.NewRequest("GET", "/users?search=admin", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(1), response["total"])

		mockUserService.AssertExpectations(t)
	})

	t.Run("帶 active 過濾", func(t *testing.T) {
		mockUserService := new(MockUserService)

		activeTrue := true
		expectedResponse := &identity.UserListResponse{
			Data: []model.User{
				{ID: 1, Username: "admin", Email: emailPtr("admin@example.com"), Active: activeTrue, Roles: []model.Role{}},
			},
			Total: 1,
		}
		mockUserService.On("List", mock.MatchedBy(func(req *identity.ListUsersRequest) bool {
			return req.Active != nil && *req.Active == true
		})).Return(expectedResponse, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users", handler.List)

		req := httptest.NewRequest("GET", "/users?active=true", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockUserService.AssertExpectations(t)
	})

	t.Run("帶分頁參數", func(t *testing.T) {
		mockUserService := new(MockUserService)

		expectedResponse := &identity.UserListResponse{
			Data:  []model.User{},
			Total: 0,
		}
		mockUserService.On("List", mock.MatchedBy(func(req *identity.ListUsersRequest) bool {
			return req.Page == 2 && req.PageSize == 10
		})).Return(expectedResponse, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users", handler.List)

		req := httptest.NewRequest("GET", "/users?page=2&page_size=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("List", mock.AnythingOfType("*identity.ListUsersRequest")).
			Return(nil, errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users", handler.List)

		req := httptest.NewRequest("GET", "/users", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "查詢用戶失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_Create 測試創建用戶
func TestUserHandler_Create(t *testing.T) {
	t.Run("成功創建用戶", func(t *testing.T) {
		mockUserService := new(MockUserService)

		activeTrue := true
		createdUser := &model.User{
			ID:       1,
			Username: "newuser",
			Email:    emailPtr("newuser@example.com"),
			FullName: "New User",
			Active:   activeTrue,
		}
		mockUserService.On("Create", mock.MatchedBy(func(req *identity.CreateUserRequest) bool {
			return req.Username == "newuser" && req.Email == "newuser@example.com"
		})).Return(createdUser, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users", handler.Create)

		requestBody := map[string]interface{}{
			"username":  "newuser",
			"password":  "password123",
			"email":     "newuser@example.com",
			"full_name": "New User",
			"roles":     []string{"user"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		data := response["data"].(map[string]interface{})
		assert.Equal(t, "newuser", data["username"])

		mockUserService.AssertExpectations(t)
	})

	t.Run("請求格式錯誤（缺少必填欄位）", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users", handler.Create)

		requestBody := map[string]interface{}{
			"username": "newuser",
			// 缺少 password 和 email
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求參數錯誤")
	})

	t.Run("使用者名稱已存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Create", mock.AnythingOfType("*identity.CreateUserRequest")).
			Return(nil, identity.ErrUsernameExists)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users", handler.Create)

		requestBody := map[string]interface{}{
			"username": "admin",
			"password": "password123",
			"email":    "admin@example.com",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "使用者名稱已存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("角色不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Create", mock.AnythingOfType("*identity.CreateUserRequest")).
			Return(nil, identity.ErrRoleNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users", handler.Create)

		requestBody := map[string]interface{}{
			"username": "newuser",
			"password": "password123",
			"email":    "newuser@example.com",
			"roles":    []string{"invalid_role"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "指定的角色不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Create", mock.AnythingOfType("*identity.CreateUserRequest")).
			Return(nil, errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users", handler.Create)

		requestBody := map[string]interface{}{
			"username": "newuser",
			"password": "password123",
			"email":    "newuser@example.com",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "建立使用者失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_Get 測試獲取用戶詳情
func TestUserHandler_Get(t *testing.T) {
	t.Run("成功獲取用戶詳情", func(t *testing.T) {
		mockUserService := new(MockUserService)

		activeTrue := true
		user := &model.User{
			ID:       1,
			Username: "admin",
			Email:    emailPtr("admin@example.com"),
			FullName: "Administrator",
			Active:   activeTrue,
		}
		mockUserService.On("GetByID", uint(1)).Return(user, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users/:id", handler.Get)

		req := httptest.NewRequest("GET", "/users/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		data := response["data"].(map[string]interface{})
		assert.Equal(t, "admin", data["username"])

		mockUserService.AssertExpectations(t)
	})

	t.Run("無效的用戶 ID", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users/:id", handler.Get)

		req := httptest.NewRequest("GET", "/users/invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（resource），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的用戶 ID")
	})

	t.Run("用戶不存在（404）", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("GetByID", uint(999)).Return(nil, identity.ErrUserNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users/:id", handler.Get)

		req := httptest.NewRequest("GET", "/users/999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("GetByID", uint(1)).Return(nil, errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.GET("/users/:id", handler.Get)

		req := httptest.NewRequest("GET", "/users/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "查詢用戶失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_Update 測試更新用戶
func TestUserHandler_Update(t *testing.T) {
	t.Run("成功更新用戶", func(t *testing.T) {
		mockUserService := new(MockUserService)

		activeTrue := true
		updatedUser := &model.User{
			ID:       1,
			Username: "admin",
			Email:    emailPtr("newemail@example.com"),
			FullName: "Updated Name",
			Active:   activeTrue,
		}
		mockUserService.On("Update", uint(1), mock.AnythingOfType("*identity.UpdateUserRequest")).
			Return(updatedUser, map[string]string{}, nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id", handler.Update)

		requestBody := map[string]interface{}{
			"email":     "newemail@example.com",
			"full_name": "Updated Name",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		data := response["data"].(map[string]interface{})
		assert.Equal(t, "newemail@example.com", data["email"])

		mockUserService.AssertExpectations(t)
	})

	t.Run("無效的用戶 ID", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id", handler.Update)

		requestBody := map[string]interface{}{
			"email": "test@example.com",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/invalid", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（resource），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的用戶 ID")
	})

	t.Run("請求格式錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id", handler.Update)

		req := httptest.NewRequest("PUT", "/users/1", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求參數錯誤")
	})

	t.Run("用戶不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Update", uint(999), mock.AnythingOfType("*identity.UpdateUserRequest")).
			Return(nil, nil, identity.ErrUserNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id", handler.Update)

		requestBody := map[string]interface{}{
			"email": "test@example.com",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/999", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Update", uint(1), mock.AnythingOfType("*identity.UpdateUserRequest")).
			Return(nil, nil, errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id", handler.Update)

		requestBody := map[string]interface{}{
			"email": "test@example.com",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "更新用戶失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_Delete 測試刪除用戶
func TestUserHandler_Delete(t *testing.T) {
	t.Run("成功刪除用戶", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Delete", uint(1)).Return(nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/users/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// message 欄已移除（成功回應不攜帶 UI 文案）
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotContains(t, response, "message")

		mockUserService.AssertExpectations(t)
	})

	t.Run("無效的用戶 ID", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/users/invalid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（resource），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的用戶 ID")
	})

	t.Run("用戶不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Delete", uint(999)).Return(identity.ErrUserNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/users/999", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("不能刪除最後一個管理員", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Delete", uint(1)).Return(identity.ErrLastAdmin)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/users/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "不能刪除最後一個管理員帳號")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("Delete", uint(1)).Return(errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id", handler.Delete)

		req := httptest.NewRequest("DELETE", "/users/1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "刪除用戶失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_AssignRoles 測試分配角色
func TestUserHandler_AssignRoles(t *testing.T) {
	t.Run("成功分配角色", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("AssignRoles", uint(1), []string{"admin", "user"}).Return(nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		requestBody := map[string]interface{}{
			"roles": []string{"admin", "user"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/roles", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// message 欄已移除（成功回應不攜帶 UI 文案）
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotContains(t, response, "message")

		mockUserService.AssertExpectations(t)
	})

	t.Run("無效的用戶 ID", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		requestBody := map[string]interface{}{
			"roles": []string{"admin"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/invalid/roles", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（resource），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的用戶 ID")
	})

	t.Run("請求格式錯誤（缺少 roles）", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		requestBody := map[string]interface{}{}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/roles", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求參數錯誤")
	})

	t.Run("用戶不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("AssignRoles", uint(999), []string{"admin"}).
			Return(identity.ErrUserNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		requestBody := map[string]interface{}{
			"roles": []string{"admin"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/999/roles", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("角色不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("AssignRoles", uint(1), []string{"invalid_role"}).
			Return(identity.ErrRoleNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		requestBody := map[string]interface{}{
			"roles": []string{"invalid_role"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/roles", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "指定的角色不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("AssignRoles", uint(1), []string{"admin"}).
			Return(errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		requestBody := map[string]interface{}{
			"roles": []string{"admin"},
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/roles", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "分配角色失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_UpdateStatus 測試更新狀態
func TestUserHandler_UpdateStatus(t *testing.T) {
	t.Run("成功更新用戶狀態", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("UpdateStatus", uint(1), false).Return(nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		requestBody := map[string]interface{}{
			"active": false,
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/status", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// message 欄已移除（成功回應不攜帶 UI 文案）
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotContains(t, response, "message")

		mockUserService.AssertExpectations(t)
	})

	t.Run("無效的用戶 ID", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		requestBody := map[string]interface{}{
			"active": false,
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/invalid/status", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（resource），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的用戶 ID")
	})

	t.Run("請求格式錯誤（active 為 nil）", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		requestBody := map[string]interface{}{}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/status", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "請求參數錯誤")
	})

	t.Run("用戶不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("UpdateStatus", uint(999), false).
			Return(identity.ErrUserNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		requestBody := map[string]interface{}{
			"active": false,
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/999/status", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("不能禁用最後一個管理員", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("UpdateStatus", uint(1), false).
			Return(identity.ErrLastAdmin)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		requestBody := map[string]interface{}{
			"active": false,
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/status", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "不能禁用最後一個管理員帳號")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("UpdateStatus", uint(1), false).
			Return(errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		requestBody := map[string]interface{}{
			"active": false,
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/status", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "更新狀態失敗")

		mockUserService.AssertExpectations(t)
	})
}

// TestUserHandler_ChangePassword 測試修改密碼
func TestUserHandler_ChangePassword(t *testing.T) {
	t.Run("成功修改密碼", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("ChangePassword", uint(1), "newpassword123").Return(nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/password", handler.ChangePassword)

		requestBody := map[string]interface{}{
			"password": "newpassword123",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/password", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// message 欄已移除（成功回應不攜帶 UI 文案）
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotContains(t, response, "message")

		mockUserService.AssertExpectations(t)
	})

	t.Run("無效的用戶 ID", func(t *testing.T) {
		mockUserService := new(MockUserService)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/password", handler.ChangePassword)

		requestBody := map[string]interface{}{
			"password": "newpassword123",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/invalid/password", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（resource），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "無效的用戶 ID")
	})

	t.Run("密碼政策違規回可讀訊息", func(t *testing.T) {
		mockUserService := new(MockUserService)

		// 長度等規則已下沉到 service 層政策 validator，
		// handler 只負責把 PasswordPolicyViolation 映射為 400
		mockUserService.On("ChangePassword", uint(1), "12345").
			Return(&policy.PasswordPolicyViolation{
				Reason:  policy.ErrPasswordTooShort,
				Message: "密碼長度至少需 12 字元",
				// code 化後 handler 依 Code+Params 渲染（與真實 validator 綁定一致）
				Code:   apierror.CodePasswordTooShort,
				Params: map[string]any{"min": 12},
			})

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/password", handler.ChangePassword)

		requestBody := map[string]interface{}{
			"password": "12345",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/password", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// code 化後回應攜帶 params 物件（min），改用 interface{} 承載
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "密碼長度至少需 12 字元")

		mockUserService.AssertExpectations(t)
	})

	t.Run("用戶不存在", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("ChangePassword", uint(999), "newpassword123").
			Return(identity.ErrUserNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/password", handler.ChangePassword)

		requestBody := map[string]interface{}{
			"password": "newpassword123",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/999/password", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "用戶不存在")

		mockUserService.AssertExpectations(t)
	})

	t.Run("Service 層錯誤", func(t *testing.T) {
		mockUserService := new(MockUserService)

		mockUserService.On("ChangePassword", uint(1), "newpassword123").
			Return(errors.New("database error"))

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/password", handler.ChangePassword)

		requestBody := map[string]interface{}{
			"password": "newpassword123",
		}
		jsonBody, _ := json.Marshal(requestBody)
		req := httptest.NewRequest("PUT", "/users/1/password", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "修改密碼失敗")

		mockUserService.AssertExpectations(t)
	})
}
