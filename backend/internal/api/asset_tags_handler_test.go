package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/custodexa/backend/internal/modules/asset"
)

// asRole 以指定角色掛 handler（模擬 AuthMiddleware 注入）
func asRole(role string, h gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("role", role)
		c.Set("userID", uint(1))
		c.Set("username", "tester")
		h(c)
	}
}

func TestAssetHandler_List_TagsParam(t *testing.T) {
	t.Run("一般使用者帶 tags 參數明確拒 400", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)
		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)

		router := setupTestRouter()
		router.GET("/assets", asRole("user", handler.List))

		req := httptest.NewRequest("GET", "/assets?tags=%E7%94%9F%E7%94%A2", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAssetService.AssertNotCalled(t, "List")
	})

	t.Run("admin 帶 tags 參數傳入 filter", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)

		mockAssetService.On("List", mock.MatchedBy(func(filter *asset.AssetFilter) bool {
			return len(filter.Tags) == 2 && filter.Tags[0] == "生產" && filter.Tags[1] == "資料庫"
		})).Return(&asset.AssetListResponse{Page: 1, PageSize: 20}, nil)

		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)
		router := setupTestRouter()
		router.GET("/assets", asRole("admin", handler.List))

		req := httptest.NewRequest("GET", "/assets?tags=生產,資料庫", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAssetService.AssertExpectations(t)
	})

	t.Run("tags 參數超上限 400", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAuthService := new(MockAssetAuthorizationService)
		handler := NewAssetHandler(mockAssetService, mockAuthService, nil)

		router := setupTestRouter()
		router.GET("/assets", asRole("admin", handler.List))

		raw := ""
		for i := 0; i < 21; i++ {
			if i > 0 {
				raw += ","
			}
			raw += "tag" + string(rune('a'+i))
		}
		req := httptest.NewRequest("GET", "/assets?tags="+raw, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAssetService.AssertNotCalled(t, "List")
	})
}

func TestAssetHandler_ListTags_角色守衛(t *testing.T) {
	newRouter := func(role string, svc *MockAssetService) *gin.Engine {
		handler := NewAssetHandler(svc, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.GET("/assets/tags", asRole(role, handler.ListTags))
		return router
	}

	t.Run("admin 取得清單含使用數", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("ListTags").Return([]asset.TagCount{
			{Name: "DBA", Count: 3}, {Name: "生產", Count: 5},
		}, nil)

		req := httptest.NewRequest("GET", "/assets/tags", nil)
		w := httptest.NewRecorder()
		newRouter("admin", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp struct {
			Data []asset.TagCount `json:"data"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Len(t, resp.Data, 2)
		assert.Equal(t, 3, resp.Data[0].Count)
		mockAssetService.AssertExpectations(t)
	})

	t.Run("auditor 可用", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("ListTags").Return([]asset.TagCount{}, nil)

		req := httptest.NewRequest("GET", "/assets/tags", nil)
		w := httptest.NewRecorder()
		newRouter("auditor", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("一般使用者 403（不洩漏未授權標籤詞彙）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)

		req := httptest.NewRequest("GET", "/assets/tags", nil)
		w := httptest.NewRecorder()
		newRouter("user", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockAssetService.AssertNotCalled(t, "ListTags")
	})
}

func TestAssetHandler_RenameTag(t *testing.T) {
	newRouter := func(role string, svc *MockAssetService) *gin.Engine {
		handler := NewAssetHandler(svc, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.POST("/assets/tags/rename", asRole(role, handler.RenameTag))
		return router
	}
	body := func(from, to string) *bytes.Reader {
		b, _ := json.Marshal(map[string]string{"from": from, "to": to})
		return bytes.NewReader(b)
	}

	t.Run("admin 改名回受影響數", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("RenameTag", "DbA標籤", "DBA").Return(int64(3), nil)

		req := httptest.NewRequest("POST", "/assets/tags/rename", body("DbA標籤", "DBA"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("admin", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]int64
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, int64(3), resp["affected"])
		mockAssetService.AssertExpectations(t)
	})

	t.Run("auditor 403", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		req := httptest.NewRequest("POST", "/assets/tags/rename", body("a", "b"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("auditor", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockAssetService.AssertNotCalled(t, "RenameTag")
	})

	t.Run("驗證錯誤映射 400", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("RenameTag", "a", "b,c").Return(int64(0), asset.ErrTagContainsComma)

		req := httptest.NewRequest("POST", "/assets/tags/rename", body("a", "b,c"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("admin", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("缺欄位 400", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		req := httptest.NewRequest("POST", "/assets/tags/rename", bytes.NewReader([]byte(`{"from":"a"}`)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("admin", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockAssetService.AssertNotCalled(t, "RenameTag")
	})
}

func TestAssetHandler_DeleteTag(t *testing.T) {
	newRouter := func(role string, svc *MockAssetService) *gin.Engine {
		handler := NewAssetHandler(svc, new(MockAssetAuthorizationService), nil)
		router := setupTestRouter()
		router.POST("/assets/tags/delete", asRole(role, handler.DeleteTag))
		return router
	}

	t.Run("admin 刪除回受影響數", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("DeleteTag", "廢棄").Return(int64(5), nil)

		b, _ := json.Marshal(map[string]string{"name": "廢棄"})
		req := httptest.NewRequest("POST", "/assets/tags/delete", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("admin", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]int64
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, int64(5), resp["affected"])
	})

	t.Run("一般使用者 403", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		b, _ := json.Marshal(map[string]string{"name": "x"})
		req := httptest.NewRequest("POST", "/assets/tags/delete", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("user", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockAssetService.AssertNotCalled(t, "DeleteTag")
	})

	t.Run("驗證錯誤映射 400（ErrTagContainsComma，非僅 ErrTagEmpty）", func(t *testing.T) {
		mockAssetService := new(MockAssetService)
		mockAssetService.On("DeleteTag", "a,b").Return(int64(0), asset.ErrTagContainsComma)

		b, _ := json.Marshal(map[string]string{"name": "a,b"})
		req := httptest.NewRequest("POST", "/assets/tags/delete", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouter("admin", mockAssetService).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]any
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "VALIDATION_TAG_CONTAINS_COMMA", resp["code"])
	})
}
