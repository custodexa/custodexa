package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAssetGroupService - AssetGroupService 的 mock（asset-node-tree 介面）
type MockAssetGroupService struct {
	mock.Mock
}

func (m *MockAssetGroupService) ListWithAssets() ([]asset.GroupWithAssets, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]asset.GroupWithAssets), args.Error(1)
}

func (m *MockAssetGroupService) Tree(parentID *uint, vis *asset.TreeVisibility) ([]asset.TreeNode, error) {
	args := m.Called(parentID, vis)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]asset.TreeNode), args.Error(1)
}

func (m *MockAssetGroupService) Create(req *asset.AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error) {
	args := m.Called(req, actorID, actorName, clientIP)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetGroup), args.Error(1)
}

func (m *MockAssetGroupService) Update(id uint, req *asset.AssetGroupRequest, actorID uint, actorName, clientIP string) (*model.AssetGroup, error) {
	args := m.Called(id, req, actorID, actorName, clientIP)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetGroup), args.Error(1)
}

func (m *MockAssetGroupService) Move(id uint, newParentID *uint, actorID uint, actorName, clientIP string) (*model.AssetGroup, error) {
	args := m.Called(id, newParentID, actorID, actorName, clientIP)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AssetGroup), args.Error(1)
}

func (m *MockAssetGroupService) Delete(id uint, actorID uint, actorName, clientIP string) (int64, error) {
	args := m.Called(id, actorID, actorName, clipOrEmpty(clientIP))
	return args.Get(0).(int64), args.Error(1)
}

func clipOrEmpty(s string) string { return s }

// MockNodeVisibility - 可視節點鏈解析 mock（asset-node-tree D6）
type MockNodeVisibility struct {
	mock.Mock
}

func (m *MockNodeVisibility) VisibleTreeScope(ctx context.Context, userID uint) (*asset.TreeVisibility, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*asset.TreeVisibility), args.Error(1)
}

// groupListFixture 樹形三節點：node1 prod（兩資產，授權其一）、
// node2 staging（一資產無授權、parent=node1）、node3 empty（空節點）
func groupListFixture() []asset.GroupWithAssets {
	p1 := uint(1)
	return []asset.GroupWithAssets{
		{ID: 1, Name: "prod", Path: "prod", Assets: []model.Asset{{ID: 11, Name: "db-1"}, {ID: 12, Name: "db-2"}}},
		{ID: 2, Name: "staging", ParentID: &p1, Path: "prod / staging", Assets: []model.Asset{{ID: 21, Name: "web-1"}}},
		{ID: 3, Name: "empty", Path: "empty", Assets: []model.Asset{}},
	}
}

type groupListResponse struct {
	Data  []asset.GroupWithAssets `json:"data"`
	Total int                     `json:"total"`
}

func newGroupHandlerForTest(groups *MockAssetGroupService, auth *MockAssetAuthorizationService, vis *MockNodeVisibility) *AssetGroupHandler {
	return NewAssetGroupHandler(groups, auth, vis)
}

// TestAssetGroupHandler_List_Scoping asset-access-scoping P1-1（樹語義升級）：
// List 不得把全站資產經節點洩漏給一般 user；有授權資產的節點保留祖先鏈
func TestAssetGroupHandler_List_Scoping(t *testing.T) {
	t.Run("admin 看全量節點與資產", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockAuth := new(MockAssetAuthorizationService)
		mockGroups.On("ListWithAssets").Return(groupListFixture(), nil)

		handler := newGroupHandlerForTest(mockGroups, mockAuth, new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.List(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp groupListResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, 3, resp.Total)
		assert.Len(t, resp.Data[0].Assets, 2)
		// 特權路徑不觸發授權查詢
		mockAuth.AssertNotCalled(t, "GetAuthorizedAssets", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("一般 user 僅見授權資產且隱藏無關節點", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockAuth := new(MockAssetAuthorizationService)
		mockGroups.On("ListWithAssets").Return(groupListFixture(), nil)
		// user 7 僅授權資產 11（node1 的 db-1）
		mockAuth.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return([]*authz.AuthorizedAssetDTO{{Asset: model.Asset{ID: 11, Name: "db-1"}}}, nil)

		handler := newGroupHandlerForTest(mockGroups, mockAuth, new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups", func(c *gin.Context) {
			c.Set("role", "user")
			c.Set("userID", uint(7))
			handler.List(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp groupListResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		// node2（無授權資產）與 node3（空節點）都不可見
		assert.Equal(t, 1, resp.Total)
		assert.Equal(t, uint(1), resp.Data[0].ID)
		// node1 只剩授權的 db-1，未授權的 db-2 不得洩漏
		assert.Len(t, resp.Data[0].Assets, 1)
		assert.Equal(t, uint(11), resp.Data[0].Assets[0].ID)
		mockAuth.AssertExpectations(t)
	})

	t.Run("授權資產在子節點時祖先鏈保留", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockAuth := new(MockAssetAuthorizationService)
		mockGroups.On("ListWithAssets").Return(groupListFixture(), nil)
		// user 7 僅授權資產 21（node2 staging，parent=node1 prod）
		mockAuth.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return([]*authz.AuthorizedAssetDTO{{Asset: model.Asset{ID: 21, Name: "web-1"}}}, nil)

		handler := newGroupHandlerForTest(mockGroups, mockAuth, new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups", func(c *gin.Context) {
			c.Set("role", "user")
			c.Set("userID", uint(7))
			handler.List(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp groupListResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		// node1（祖先空殼）＋node2（授權資產所在）；node3 不可見
		assert.Equal(t, 2, resp.Total)
		assert.Equal(t, uint(1), resp.Data[0].ID)
		assert.Len(t, resp.Data[0].Assets, 0) // 祖先僅結構，未授權資產不洩漏
		assert.Equal(t, uint(2), resp.Data[1].ID)
		assert.Len(t, resp.Data[1].Assets, 1)
	})

	t.Run("一般 user 無任何授權回空清單", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockAuth := new(MockAssetAuthorizationService)
		mockGroups.On("ListWithAssets").Return(groupListFixture(), nil)
		mockAuth.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return([]*authz.AuthorizedAssetDTO{}, nil)

		handler := newGroupHandlerForTest(mockGroups, mockAuth, new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups", func(c *gin.Context) {
			c.Set("role", "user")
			c.Set("userID", uint(7))
			handler.List(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		var resp groupListResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, 0, resp.Total)
	})

	t.Run("一般 user 缺 userID 回 401", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockAuth := new(MockAssetAuthorizationService)
		mockGroups.On("ListWithAssets").Return(groupListFixture(), nil)

		handler := newGroupHandlerForTest(mockGroups, mockAuth, new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups", func(c *gin.Context) {
			c.Set("role", "user")
			handler.List(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockAuth.AssertNotCalled(t, "GetAuthorizedAssets", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("授權查詢失敗回 500 不得誤放行", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockAuth := new(MockAssetAuthorizationService)
		mockGroups.On("ListWithAssets").Return(groupListFixture(), nil)
		mockAuth.On("GetAuthorizedAssets", mock.Anything, uint(7), model.PermissionView).
			Return(nil, assert.AnError)

		handler := newGroupHandlerForTest(mockGroups, mockAuth, new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups", func(c *gin.Context) {
			c.Set("role", "user")
			c.Set("userID", uint(7))
			handler.List(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestAssetGroupHandler_Tree_Scoping 樹端點收斂（asset-node-tree D6）：
// 非特權以可視節點鏈過濾；admin 全量（visible=nil）
func TestAssetGroupHandler_Tree_Scoping(t *testing.T) {
	t.Run("admin 全量樹", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockGroups.On("Tree", (*uint)(nil), (*asset.TreeVisibility)(nil)).
			Return([]asset.TreeNode{{ID: 1, Name: "prod"}}, nil)

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), new(MockNodeVisibility))
		router := setupTestRouter()
		router.GET("/asset-groups/tree", func(c *gin.Context) {
			c.Set("role", "admin")
			handler.Tree(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups/tree", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		mockGroups.AssertExpectations(t)
	})

	t.Run("一般 user 樹經可視鏈收斂", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockVis := new(MockNodeVisibility)
		visible := &asset.TreeVisibility{NodeIDs: map[uint]bool{1: true, 2: true}, AssetIDs: map[uint]bool{11: true}}
		mockVis.On("VisibleTreeScope", mock.Anything, uint(7)).Return(visible, nil)
		mockGroups.On("Tree", (*uint)(nil), visible).
			Return([]asset.TreeNode{{ID: 1, Name: "prod"}}, nil)

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), mockVis)
		router := setupTestRouter()
		router.GET("/asset-groups/tree", func(c *gin.Context) {
			c.Set("role", "user")
			c.Set("userID", uint(7))
			handler.Tree(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups/tree", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		mockVis.AssertExpectations(t)
		mockGroups.AssertExpectations(t)
	})

	t.Run("可視鏈解析失敗回 500 不得全量洩漏", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockVis := new(MockNodeVisibility)
		mockVis.On("VisibleTreeScope", mock.Anything, uint(7)).Return(nil, assert.AnError)

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), mockVis)
		router := setupTestRouter()
		router.GET("/asset-groups/tree", func(c *gin.Context) {
			c.Set("role", "user")
			c.Set("userID", uint(7))
			handler.Tree(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/asset-groups/tree", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockGroups.AssertNotCalled(t, "Tree", mock.Anything, mock.Anything)
	})
}

// TestAssetGroupHandler_ErrorEnvelope 節點樹端點的機器碼封套
// （backend-i18n-unification A2）：sentinel 依 errors.Is 映射到碼、狀態碼不變；
// 未知錯誤走 INTERNAL_*，成功刪除不再攜帶 UI 文案（D9）。
func TestAssetGroupHandler_ErrorEnvelope(t *testing.T) {
	decode := func(w *httptest.ResponseRecorder) map[string]any {
		var body map[string]any
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return body
	}

	t.Run("同層同名回 409 CONFLICT_ASSET_NODE_NAME", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockGroups.On("Create", mock.Anything, uint(7), mock.Anything, mock.Anything).Return(nil, asset.ErrGroupNameExists)

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), new(MockNodeVisibility))
		router := setupTestRouter()
		router.POST("/asset-groups", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Create(c)
		})

		req := httptest.NewRequest("POST", "/asset-groups", strings.NewReader(`{"name":"prod"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		body := decode(w)
		assert.Equal(t, "CONFLICT_ASSET_NODE_NAME", body["code"])
		assert.Equal(t, "同層已有同名節點", body["error"])
	})

	t.Run("非空節點回 400 RULE_NODE_NOT_EMPTY", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockGroups.On("Delete", uint(3), uint(7), mock.Anything, mock.Anything).Return(int64(0), asset.ErrNodeNotEmpty)

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), new(MockNodeVisibility))
		router := setupTestRouter()
		router.DELETE("/asset-groups/:id", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Delete(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/asset-groups/3", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "RULE_NODE_NOT_EMPTY", decode(w)["code"])
	})

	t.Run("未知錯誤走 INTERNAL_ASSET_NODE_DELETE 且不外洩成因", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockGroups.On("Delete", uint(3), uint(7), mock.Anything, mock.Anything).Return(int64(0), errors.New("db exploded at 10.9.9.9"))

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), new(MockNodeVisibility))
		router := setupTestRouter()
		router.DELETE("/asset-groups/:id", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Delete(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/asset-groups/3", nil))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, "INTERNAL_ASSET_NODE_DELETE", decode(w)["code"])
		assert.NotContains(t, w.Body.String(), "10.9.9.9")
	})

	t.Run("刪除成功不帶 message 但保留 revoked_authorizations", func(t *testing.T) {
		mockGroups := new(MockAssetGroupService)
		mockGroups.On("Delete", uint(3), uint(7), mock.Anything, mock.Anything).Return(int64(2), nil)

		handler := newGroupHandlerForTest(mockGroups, new(MockAssetAuthorizationService), new(MockNodeVisibility))
		router := setupTestRouter()
		router.DELETE("/asset-groups/:id", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Delete(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("DELETE", "/asset-groups/3", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		body := decode(w)
		assert.NotContains(t, body, "message")
		assert.Equal(t, float64(2), body["revoked_authorizations"])
	})

	t.Run("無效節點 ID 回 400 VALIDATION_INVALID_NODE_ID", func(t *testing.T) {
		handler := newGroupHandlerForTest(new(MockAssetGroupService), new(MockAssetAuthorizationService), new(MockNodeVisibility))
		router := setupTestRouter()
		router.PUT("/asset-groups/:id", func(c *gin.Context) {
			c.Set("userID", uint(7))
			handler.Update(c)
		})

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("PUT", "/asset-groups/abc", nil))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "VALIDATION_INVALID_NODE_ID", decode(w)["code"])
	})
}
