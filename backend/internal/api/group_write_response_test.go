package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 節點與使用者群組的寫入回應與隨後讀取一致：節點寫入回應帶寫入後的完整路徑；群組寫入回應的成員欄位
// （user_ids、manual_user_ids、mapped_user_ids、member_sources）由列表所用的同一份計算填入。

// sameNameFieldsEqual 寫入回應與讀取回應兩邊都有的鍵，值必須相同；回傳不同的鍵。
func sameNameFieldsEqual(t *testing.T, write, read map[string]any, skip ...string) {
	t.Helper()
	skipped := map[string]bool{}
	for _, k := range skip {
		skipped[k] = true
	}
	for k, wv := range write {
		rv, ok := read[k]
		if !ok || skipped[k] {
			continue
		}
		wj, _ := json.Marshal(wv)
		rj, _ := json.Marshal(rv)
		assert.JSONEq(t, string(rj), string(wj), "欄位 %s：寫入回應與讀取不同", k)
	}
}

func decodeObj(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m), string(body))
	return m
}

func TestAssetGroupHandler_WriteResponse(t *testing.T) {
	e := newNodeScopeEnv(t)
	admin := e.superAdmin()
	read := func(id any) map[string]any {
		code, body := e.do(admin, http.MethodGet, fmt.Sprintf("/asset-groups/%v", id), nil)
		require.Equal(t, http.StatusOK, code, string(body))
		return decodeObj(t, body)
	}

	t.Run("create_returns_full_path", func(t *testing.T) {
		pid := e.id("prod/db")
		code, body := e.do(admin, http.MethodPost, "/asset-groups", map[string]any{"name": "cache", "parent_id": pid})
		require.Equal(t, http.StatusCreated, code, string(body))
		w := decodeObj(t, body)
		assert.Equal(t, "prod / db / cache", w["path"], string(body))
		r := read(w["id"])
		assert.Equal(t, r["path"], w["path"])
		sameNameFieldsEqual(t, w, r)
	})
	t.Run("rename_returns_new_path", func(t *testing.T) {
		code, body := e.do(admin, http.MethodPut, "/asset-groups/"+e.idStr("prod/web"), map[string]any{"name": "frontend", "description": "renamed"})
		require.Equal(t, http.StatusOK, code, string(body))
		w := decodeObj(t, body)
		assert.Equal(t, "prod / frontend", w["path"], string(body))
		r := read(e.id("prod/web"))
		assert.Equal(t, r["path"], w["path"])
		sameNameFieldsEqual(t, w, r)
	})
	t.Run("move_returns_path_under_new_parent", func(t *testing.T) {
		code, body := e.do(admin, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/a")+"/move", map[string]any{"parent_id": e.id("sit")})
		require.Equal(t, http.StatusOK, code, string(body))
		w := decodeObj(t, body)
		assert.Equal(t, "sit / a", w["path"], string(body))
		r := read(e.id("prod/db/a"))
		assert.Equal(t, r["path"], w["path"])
		sameNameFieldsEqual(t, w, r)
	})
	t.Run("move_to_root_returns_root_path", func(t *testing.T) {
		code, body := e.do(admin, http.MethodPut, "/asset-groups/"+e.idStr("prod/db/b")+"/move", map[string]any{"parent_id": nil})
		require.Equal(t, http.StatusOK, code, string(body))
		w := decodeObj(t, body)
		assert.Equal(t, "b", w["path"], string(body))
		assert.NotContains(t, w, "parent_id")
		r := read(e.id("prod/db/b"))
		assert.Equal(t, r["path"], w["path"])
		sameNameFieldsEqual(t, w, r)
	})
}

func TestUserGroupHandler_WriteResponse(t *testing.T) {
	e := newUserGroupGetOneEnv(t)
	h := NewUserGroupHandler(identity.NewUserGroupService(e.db, audit.NewTxSink(), nil))
	// 成員替換經指派關卡、權限版本與成員的憑證世代：補上這些路徑讀寫的表
	require.NoError(t, migrateWithAuthz(e.db, &model.AuditLog{}, &model.Role{}, &model.RolePermission{},
		&model.UserRole{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.RefreshToken{},
		&model.UserRoleMappingRuleSupport{}, &model.UserChannelObservation{}, &model.GroupUserGroupMapping{},
		&model.ApproverScope{}, &model.PermissionStateEvent{}, &model.AuthzState{}))
	require.NoError(t, e.db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	g := e.r.Group("/api/v1/user-groups-write")
	g.POST("", h.Create)
	g.PUT("/:id", h.Update)
	g.PUT("/:id/members", h.ReplaceMembers)
	send := func(method, path string, body any) map[string]any {
		t.Helper()
		code, raw := e.send(method, path, body)
		require.Less(t, code, 300, string(raw))
		return decodeObj(t, raw)
	}
	read := func(id any) map[string]any {
		t.Helper()
		code, raw := e.get(model.RoleAdmin, fmt.Sprintf("/api/v1/user-groups/%v", id))
		require.Equal(t, http.StatusOK, code, string(raw))
		return decodeObj(t, raw)
	}
	memberKeys := []string{"user_ids", "manual_user_ids", "mapped_user_ids", "member_sources", "users"}
	assertMembersMatch := func(t *testing.T, w, r map[string]any) {
		t.Helper()
		for _, k := range memberKeys {
			wj, _ := json.Marshal(w[k])
			rj, _ := json.Marshal(r[k])
			assert.JSONEq(t, string(rj), string(wj), "成員欄位 %s：寫入回應與讀取不同", k)
		}
		sameNameFieldsEqual(t, w, r)
	}

	manual, mapped, both := e.user("wr-manual"), e.user("wr-mapped"), e.user("wr-both")
	created := send(http.MethodPost, "/api/v1/user-groups-write", map[string]any{"name": "wr-ops", "description": "write response"})
	id := uint(created["id"].(float64))
	for _, k := range []string{"user_ids", "manual_user_ids", "mapped_user_ids", "member_sources"} {
		assert.Contains(t, created, k, "建立回應帶成員欄位 %s", k)
	}
	assertMembersMatch(t, created, read(id))

	// 只由外部群組映射加入的成員：成員列非手動、有規則支持。Manual 欄有資料庫預設值 true，以 GORM 建立時
	// 零值不會寫入，所以以 SQL 直接寫 false，並讀回確認起始狀態確實是非手動
	for _, uid := range []uint{mapped, both} {
		require.NoError(t, e.db.Exec("INSERT INTO user_group_members (user_group_id, user_id, manual) VALUES (?, ?, ?)",
			id, uid, false).Error)
		require.NoError(t, e.db.Create(&model.UserGroupMappingRuleSupport{UserGroupID: id, UserID: uid, Channel: "oidc:fixture", RuleID: 1}).Error)
	}
	var manualFlags []bool
	require.NoError(t, e.db.Model(&model.UserGroupMember{}).Where("user_group_id = ?", id).Order("user_id").Pluck("manual", &manualFlags).Error)
	require.Equal(t, []bool{false, false}, manualFlags, "前提：起始的兩位成員都只由映射而來")

	type source struct {
		UserID uint `json:"user_id"`
		Manual bool `json:"manual"`
		Mapped bool `json:"mapped"`
	}
	// assertSources 成員來源逐人比對：user_ids、manual_user_ids、mapped_user_ids 與 member_sources 一致
	assertSources := func(t *testing.T, w map[string]any, want []source) {
		t.Helper()
		raw, _ := json.Marshal(w)
		var got struct {
			UserIDs       []uint   `json:"user_ids"`
			ManualUserIDs []uint   `json:"manual_user_ids"`
			MappedUserIDs []uint   `json:"mapped_user_ids"`
			MemberSources []source `json:"member_sources"`
		}
		require.NoError(t, json.Unmarshal(raw, &got))
		var ids, manuals, mappeds []uint
		for _, s := range want {
			ids = append(ids, s.UserID)
			if s.Manual {
				manuals = append(manuals, s.UserID)
			}
			if s.Mapped {
				mappeds = append(mappeds, s.UserID)
			}
		}
		assert.ElementsMatch(t, ids, got.UserIDs, "有效成員")
		assert.ElementsMatch(t, manuals, got.ManualUserIDs, "手動成員")
		assert.ElementsMatch(t, mappeds, got.MappedUserIDs, "映射成員")
		assert.ElementsMatch(t, want, got.MemberSources, "成員來源")
	}

	t.Run("pure_mapped_members_before_replace", func(t *testing.T) {
		assertSources(t, read(id), []source{{mapped, false, true}, {both, false, true}})
	})
	t.Run("replace_members_returns_member_fields", func(t *testing.T) {
		// 手動名單指定 manual 與 both：manual 只手動、mapped 只映射且保留、both 兩者皆是
		w := send(http.MethodPut, fmt.Sprintf("/api/v1/user-groups-write/%d/members", id), map[string]any{"manual_user_ids": []uint{manual, both}})
		assertSources(t, w, []source{{manual, true, false}, {mapped, false, true}, {both, true, true}})
		assertMembersMatch(t, w, read(id))
	})
	t.Run("update_returns_member_fields", func(t *testing.T) {
		w := send(http.MethodPut, fmt.Sprintf("/api/v1/user-groups-write/%d", id), map[string]any{"name": "wr-ops-renamed", "description": "x"})
		assert.Equal(t, "wr-ops-renamed", w["name"])
		assertSources(t, w, []source{{manual, true, false}, {mapped, false, true}, {both, true, true}})
		assertMembersMatch(t, w, read(id))
	})
	t.Run("clearing_manual_members_keeps_mapped_members", func(t *testing.T) {
		w := send(http.MethodPut, fmt.Sprintf("/api/v1/user-groups-write/%d/members", id), map[string]any{"manual_user_ids": []uint{}})
		assertSources(t, w, []source{{mapped, false, true}, {both, false, true}})
		assertMembersMatch(t, w, read(id))
	})
}

// send 以超級管理者送出寫入請求。
func (e *userGroupGetOneEnv) send(method, path string, body any) (int, []byte) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(e.t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Role", model.RoleAdmin)
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}
