package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 使用者群組單筆讀取：與列表元素同形（同一份成員欄位計算）；不存在與已刪除同一回應；
// 缺群組管理能力者在入口得到與列表相同的拒絕，不因識別是否存在而不同。

type userGroupGetOneEnv struct {
	t  *testing.T
	db *gorm.DB
	r  *gin.Engine
}

func newUserGroupGetOneEnv(t *testing.T) *userGroupGetOneEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, migrateWithAuthz(db, &model.User{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupMappingRuleSupport{}, &model.AssetAuthorization{}))
	h := NewUserGroupHandler(identity.NewUserGroupService(db, audit.NewTxSink(), nil))

	r := gin.New()
	role := ""
	r.Use(func(c *gin.Context) {
		role = c.GetHeader("X-Test-Role")
		c.Set("userID", uint(1))
		c.Set("username", "operator")
		middleware.SetPrincipal(c, legacyPrincipal(role))
		c.Next()
	})
	g := r.Group("/api/v1/user-groups", middleware.EnforceRegistry())
	g.GET("", h.List)
	g.GET("/:id", h.Get)
	return &userGroupGetOneEnv{t: t, db: db, r: r}
}

func (e *userGroupGetOneEnv) get(role, path string) (int, []byte) {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Test-Role", role)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func (e *userGroupGetOneEnv) user(name string) uint {
	e.t.Helper()
	email := name + "@example.test"
	u := model.User{Username: name, Email: &email, Password: "x", Active: true}
	require.NoError(e.t, e.db.Create(&u).Error)
	return u.ID
}

func TestUserGroupHandler_GetOne(t *testing.T) {
	e := newUserGroupGetOneEnv(t)
	manualOnly, mappedOnly, both := e.user("manual-only"), e.user("mapped-only"), e.user("manual-and-mapped")

	mixed := model.UserGroup{Name: "ops", Description: "manual and mapped members"}
	require.NoError(t, e.db.Create(&mixed).Error)
	for _, m := range []struct {
		uid    uint
		manual bool
	}{{manualOnly, true}, {mappedOnly, false}, {both, true}} {
		// Manual 欄有資料庫預設值 true，零值不會寫入；只經映射加入者以 SQL 直接寫 false
		require.NoError(t, e.db.Exec("INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (?, ?, ?)",
			mixed.ID, m.uid, m.manual).Error)
	}
	for _, uid := range []uint{mappedOnly, both} {
		require.NoError(t, e.db.Create(&model.UserGroupMappingRuleSupport{UserID: uid, UserGroupID: mixed.ID,
			Channel: "provider:1", RuleID: 1}).Error)
	}
	empty := model.UserGroup{Name: "empty"}
	require.NoError(t, e.db.Create(&empty).Error)
	deleted := model.UserGroup{Name: "gone"}
	require.NoError(t, e.db.Create(&deleted).Error)
	require.NoError(t, e.db.Delete(&deleted).Error)

	code, listBody := e.get(model.RoleAdmin, "/api/v1/user-groups")
	require.Equal(t, http.StatusOK, code, string(listBody))
	var list struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(listBody, &list))
	require.Len(t, list.Data, 2, "列表不含已刪除群組")

	t.Run("single_read_equals_list_element", func(t *testing.T) {
		for _, row := range list.Data {
			id := uint(row["id"].(float64))
			code, body := e.get(model.RoleAdmin, fmt.Sprintf("/api/v1/user-groups/%d", id))
			require.Equal(t, http.StatusOK, code, string(body))
			var got map[string]any
			require.NoError(t, json.Unmarshal(body, &got))
			assert.Equal(t, row, got, "群組 %d：單筆與列表元素逐欄相同", id)
		}
	})

	t.Run("manual_and_mapped_members_coexist", func(t *testing.T) {
		code, body := e.get(model.RoleAdmin, fmt.Sprintf("/api/v1/user-groups/%d", mixed.ID))
		require.Equal(t, http.StatusOK, code, string(body))
		var got struct {
			UserIDs       []uint `json:"user_ids"`
			ManualUserIDs []uint `json:"manual_user_ids"`
			MappedUserIDs []uint `json:"mapped_user_ids"`
			MemberSources []struct {
				UserID uint `json:"user_id"`
				Manual bool `json:"manual"`
				Mapped bool `json:"mapped"`
			} `json:"member_sources"`
			Users []map[string]any `json:"users"`
		}
		require.NoError(t, json.Unmarshal(body, &got))
		assert.Equal(t, []uint{manualOnly, mappedOnly, both}, got.UserIDs)
		assert.Equal(t, []uint{manualOnly, both}, got.ManualUserIDs)
		assert.Equal(t, []uint{mappedOnly, both}, got.MappedUserIDs)
		require.Len(t, got.MemberSources, 3)
		assert.Equal(t, true, got.MemberSources[2].Manual && got.MemberSources[2].Mapped, "同一人手動與映射並存")
		assert.Len(t, got.Users, 3, "成員物件與列表同樣預載")
	})

	t.Run("missing_and_deleted_answer_the_same", func(t *testing.T) {
		missCode, missBody := e.get(model.RoleAdmin, "/api/v1/user-groups/999999")
		delCode, delBody := e.get(model.RoleAdmin, fmt.Sprintf("/api/v1/user-groups/%d", deleted.ID))
		assert.Equal(t, http.StatusNotFound, missCode, string(missBody))
		assert.Equal(t, missCode, delCode)
		assert.Equal(t, string(missBody), string(delBody), "已刪除群組與不存在群組同本文")
	})

	t.Run("missing_capability_denied_like_list_regardless_of_id", func(t *testing.T) {
		for _, role := range []string{model.RoleUser, model.RoleAuditor, model.RoleApprover} {
			listCode, listDenied := e.get(role, "/api/v1/user-groups")
			require.Equal(t, http.StatusForbidden, listCode, "%s：列表被拒（前提）", role)
			for _, path := range []string{
				fmt.Sprintf("/api/v1/user-groups/%d", mixed.ID),
				fmt.Sprintf("/api/v1/user-groups/%d", deleted.ID),
				"/api/v1/user-groups/999999",
			} {
				code, body := e.get(role, path)
				assert.Equal(t, listCode, code, "%s %s：與列表同狀態碼", role, path)
				assert.Equal(t, string(listDenied), string(body), "%s %s：與列表同拒絕本文", role, path)
			}
		}
	})

	t.Run("invalid_id_is_bad_request", func(t *testing.T) {
		code, body := e.get(model.RoleAdmin, "/api/v1/user-groups/abc")
		assert.Equal(t, http.StatusBadRequest, code, string(body))
	})

	t.Run("id_boundaries_depend_only_on_input", func(t *testing.T) {
		assertIDBoundaries(t, func(raw string) (int, []byte) { return e.get(model.RoleAdmin, "/api/v1/user-groups/"+raw) },
			mixed.ID, deleted.ID, false)
		// 缺群組管理能力者：任何識別（含不合法的格式）都在入口得到與列表相同的拒絕
		listCode, listDenied := e.get(model.RoleUser, "/api/v1/user-groups")
		require.Equal(t, http.StatusForbidden, listCode)
		for _, raw := range append([]string{"0", "4294967295", "0" + fmt.Sprint(mixed.ID)}, singleReadMalformedIDs...) {
			code, body := e.get(model.RoleUser, "/api/v1/user-groups/"+raw)
			assert.Equal(t, listCode, code, "%q：與列表同狀態碼", raw)
			assert.Equal(t, string(listDenied), string(body), "%q：與列表同拒絕本文", raw)
		}
	})
}
