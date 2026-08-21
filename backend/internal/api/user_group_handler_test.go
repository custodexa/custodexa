package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserGroupService - UserGroupServiceInterface 的 mock
type MockUserGroupService struct {
	mock.Mock
}

func (m *MockUserGroupService) List() ([]model.UserGroup, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.UserGroup), args.Error(1)
}

func (m *MockUserGroupService) Create(req *identity.UserGroupRequest) (*model.UserGroup, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserGroup), args.Error(1)
}

func (m *MockUserGroupService) Update(id uint, req *identity.UserGroupRequest) (*model.UserGroup, error) {
	args := m.Called(id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserGroup), args.Error(1)
}

func (m *MockUserGroupService) Delete(id uint, actorID uint, actorName, clientIP string) (int64, error) {
	args := m.Called(id, actorID, actorName, clientIP)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserGroupService) ReplaceMembers(id uint, userIDs []uint) (*model.UserGroup, error) {
	args := m.Called(id, userIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserGroup), args.Error(1)
}

func (m *MockUserGroupService) AuthorizationCount(id uint) (int64, error) {
	args := m.Called(id)
	return args.Get(0).(int64), args.Error(1)
}

func newUserGroupTestRouter(h *UserGroupHandler) *gin.Engine {
	r := setupTestRouter()
	// 模擬認證中間件（RequireRole 由路由綁定測試另驗）
	auth := func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		c.Set("role", "admin")
	}
	r.GET("/user-groups", auth, h.List)
	r.POST("/user-groups", auth, h.Create)
	r.PUT("/user-groups/:id", auth, h.Update)
	r.DELETE("/user-groups/:id", auth, h.Delete)
	r.PUT("/user-groups/:id/members", auth, h.ReplaceMembers)
	r.GET("/user-groups/:id/authorization-count", auth, h.AuthorizationCount)
	return r
}

func TestUserGroupHandler_CRUD(t *testing.T) {
	t.Run("列表", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("List").Return([]model.UserGroup{{ID: 1, Name: "ops", Users: []model.User{{ID: 7, Username: "u7"}}}}, nil)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/user-groups", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ops")
		assert.Contains(t, w.Body.String(), `"total":1`)
	})

	t.Run("建立與重名 409", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("Create", mock.MatchedBy(func(req *identity.UserGroupRequest) bool {
			return req.Name == "ops"
		})).Return(&model.UserGroup{ID: 1, Name: "ops"}, nil).Once()
		mockSvc.On("Create", mock.Anything).Return(nil, identity.ErrUserGroupNameExists).Once()
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		body, _ := json.Marshal(map[string]string{"name": "ops"})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/user-groups", bytes.NewReader(body)))
		assert.Equal(t, http.StatusCreated, w.Code)

		w2 := httptest.NewRecorder()
		r.ServeHTTP(w2, httptest.NewRequest("POST", "/user-groups", bytes.NewReader(body)))
		assert.Equal(t, http.StatusConflict, w2.Code)
	})

	t.Run("更新不存在 404", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("Update", uint(9), mock.Anything).Return(nil, identity.ErrUserGroupNotFound)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		body, _ := json.Marshal(map[string]string{"name": "x"})
		w := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/user-groups/9", bytes.NewReader(body))
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("刪除回連動撤銷筆數", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("Delete", uint(3), uint(1), "admin", mock.Anything).Return(int64(5), nil)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("DELETE", "/user-groups/3", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, float64(5), resp["revoked_authorizations"])
		mockSvc.AssertExpectations(t)
	})

	t.Run("成員全量替換", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("ReplaceMembers", uint(3), []uint{7, 8}).
			Return(&model.UserGroup{ID: 3, Name: "g", Users: []model.User{{ID: 7}, {ID: 8}}}, nil)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		body, _ := json.Marshal(map[string][]uint{"user_ids": {7, 8}})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("PUT", "/user-groups/3/members", bytes.NewReader(body)))
		assert.Equal(t, http.StatusOK, w.Code)
		mockSvc.AssertExpectations(t)
	})

	t.Run("成員名單含幽靈使用者 400", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("ReplaceMembers", uint(3), []uint{999}).
			Return(nil, identity.ErrUserGroupMemberNotFound)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		body, _ := json.Marshal(map[string][]uint{"user_ids": {999}})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("PUT", "/user-groups/3/members", bytes.NewReader(body)))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("授權筆數查詢", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		mockSvc.On("AuthorizationCount", uint(3)).Return(int64(7), nil)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/user-groups/3/authorization-count", nil))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"authorization_count":7`)
	})

	t.Run("無效 ID 400", func(t *testing.T) {
		mockSvc := new(MockUserGroupService)
		r := newUserGroupTestRouter(NewUserGroupHandler(mockSvc))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("DELETE", "/user-groups/abc", nil))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
