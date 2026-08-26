package api

import (
	"bytes"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/identity"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// 外部身分管理端點的錯誤映射。
//
// 重點在**規則拒絕不得落成 500**：登入途徑歸零與最後本地 admin 都是合法的業務
// 裁決，若映射漏接，管理者只會看到「系統發生錯誤」而沒有任何可行動的指引。
// 兩者的錯誤型別皆刻意相容於既有哨兵（LastLocalAdminError 滿足 errors.Is
// ErrLastAdmin），故 handler 必須以 errors.As 先取精確碼。

func decodeErr(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析回應失敗: %v (body=%s)", err, w.Body.String())
	}
	return body
}

func TestUnbindExternalIdentityEndpoint(t *testing.T) {
	t.Run("成功解綁", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("UnbindExternalIdentity", uint(7), uint(3),
			mock.AnythingOfType("identity.IdentityAdminActor")).Return(nil)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id/external-identities/:identityId", handler.UnbindExternalIdentity)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/7/external-identities/3", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		mockUserService.AssertExpectations(t)
	})

	t.Run("登入途徑歸零回 400 與精確機器碼", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("UnbindExternalIdentity", uint(7), uint(3),
			mock.AnythingOfType("identity.IdentityAdminActor")).Return(identity.ErrLastLoginPath)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id/external-identities/:identityId", handler.UnbindExternalIdentity)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/7/external-identities/3", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, string(apierror.CodeLastLoginPath), decodeErr(t, w)["code"])
	})

	t.Run("身分不存在回 404", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("UnbindExternalIdentity", uint(7), uint(3),
			mock.AnythingOfType("identity.IdentityAdminActor")).
			Return(identity.ErrExternalIdentityNotFound)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id/external-identities/:identityId", handler.UnbindExternalIdentity)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/7/external-identities/3", nil))

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, string(apierror.CodeNotFoundExternalIdentity), decodeErr(t, w)["code"])
	})
}

func TestBindExternalIdentityEndpoint(t *testing.T) {
	t.Run("身分域衝突回 409", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("BindExternalIdentity", uint(7), uint(2), "sub-x",
			mock.AnythingOfType("identity.IdentityAdminActor")).
			Return(nil, identity.ErrExternalIdentityExists)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users/:id/external-identities", handler.BindExternalIdentity)

		body, _ := json.Marshal(map[string]any{"provider_id": 2, "subject": "sub-x"})
		req := httptest.NewRequest("POST", "/users/7/external-identities", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Equal(t, string(apierror.CodeConflictExternalIdentityExists), decodeErr(t, w)["code"])
	})

	t.Run("缺欄位回 400 且不進 service", func(t *testing.T) {
		mockUserService := new(MockUserService)
		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users/:id/external-identities", handler.BindExternalIdentity)

		body, _ := json.Marshal(map[string]any{"provider_id": 2})
		req := httptest.NewRequest("POST", "/users/7/external-identities", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockUserService.AssertNotCalled(t, "BindExternalIdentity")
	})
}

func TestConvertToExternalOnlyEndpoint(t *testing.T) {
	t.Run("尚無外部身分回 400", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("ConvertToExternalOnly", uint(7),
			mock.AnythingOfType("identity.IdentityAdminActor")).
			Return(identity.ErrExternalIdentityRequired)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users/:id/external-only", handler.ConvertToExternalOnly)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/users/7/external-only", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, string(apierror.CodeExternalIdentityRequired), decodeErr(t, w)["code"])
	})

	t.Run("最後本地 admin 回 400 與 RULE_USER_LAST_LOCAL_ADMIN", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("ConvertToExternalOnly", uint(7),
			mock.AnythingOfType("identity.IdentityAdminActor")).
			Return(identity.ErrLastLocalAdmin)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.POST("/users/:id/external-only", handler.ConvertToExternalOnly)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/users/7/external-only", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, string(apierror.CodeLastLocalAdmin), decodeErr(t, w)["code"])
	})
}

// TestLastLocalAdminMapsToPreciseCode 2.7 遺留：停用／刪除／移除角色三條既有路徑
// 遇本地 admin 不變式時，須回 RULE_USER_LAST_LOCAL_ADMIN 而非舊的
// RULE_USER_LAST_ADMIN_*（後者的語義是「還有沒有 admin」，與解封能力無關）
func TestLastLocalAdminMapsToPreciseCode(t *testing.T) {
	t.Run("停用", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("UpdateStatus", uint(7), false).Return(identity.ErrLastLocalAdmin)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/status", handler.UpdateStatus)

		body, _ := json.Marshal(map[string]any{"active": false})
		req := httptest.NewRequest("PUT", "/users/7/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, string(apierror.CodeLastLocalAdmin), decodeErr(t, w)["code"])
	})

	t.Run("刪除", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("Delete", uint(7)).Return(identity.ErrLastLocalAdmin)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.DELETE("/users/:id", handler.Delete)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/users/7", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, string(apierror.CodeLastLocalAdmin), decodeErr(t, w)["code"])
	})

	t.Run("移除 admin 角色", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("AssignRoles", uint(7), []string{"user"}).Return(identity.ErrLastLocalAdmin)

		handler := newTestUserHandler(mockUserService)
		router := setupTestRouter()
		router.PUT("/users/:id/roles", handler.AssignRoles)

		body, _ := json.Marshal(map[string]any{"roles": []string{"user"}})
		req := httptest.NewRequest("PUT", "/users/7/roles", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, string(apierror.CodeLastLocalAdmin), decodeErr(t, w)["code"])
	})
}
