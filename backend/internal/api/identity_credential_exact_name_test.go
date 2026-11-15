package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/pkg/crypto"
)

// 使用者（username）、使用者群組與共用憑證（name）列表的名稱精確查找：
// 只在呼叫者本來就看得到的集合裡、與其他篩選交集後篩選，計數在篩選之後；空值回 400。

func getJSON(t *testing.T, r http.Handler, path string, header ...string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, w.Body.String()
}

func listField(resp map[string]any, key string) []string {
	data, _ := resp["data"].([]any)
	out := make([]string, 0, len(data))
	for _, d := range data {
		v, _ := d.(map[string]any)[key].(string)
		out = append(out, v)
	}
	return out
}

func assertInvalidQueryParam(t *testing.T, code int, resp map[string]any, raw, field string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, code, raw)
	assert.Equal(t, "VALIDATION_INVALID_QUERY_PARAM", resp["code"], raw)
	assert.Equal(t, map[string]any{"field": field}, resp["params"], raw)
}

func TestUserHandler_ExactUsername(t *testing.T) {
	db, h, _, _ := principalAPIEnv(t) // 既有：人類帳號 human、自動化帳號 agent
	for _, u := range []model.User{
		{Username: "Human", Password: "!", Kind: model.KindHuman, Active: true}, // 只差大小寫：建立時以原樣字串判重，兩者並存
		{Username: "human-ops", Password: "!", Kind: model.KindHuman, Active: true},
		{Username: "dormant", Password: "!", Kind: model.KindHuman, Active: true},
	} {
		u := u
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Model(&model.User{}).Where("username = ?", "dormant").Update("active", false).Error)
	gone := model.User{Username: "gone", Password: "!", Kind: model.KindHuman, Active: true}
	require.NoError(t, db.Create(&gone).Error)
	require.NoError(t, db.Delete(&gone).Error)

	r := gin.New()
	r.GET("/users", h.List)
	names := func(q string) ([]string, map[string]any) {
		t.Helper()
		code, resp, raw := getJSON(t, r, "/users?"+q)
		require.Equal(t, http.StatusOK, code, raw)
		got := listField(resp, "username")
		assert.EqualValues(t, len(got), resp["total"], "總數在篩選之後：%s", raw)
		return got, resp
	}

	t.Run("exact_match_only", func(t *testing.T) {
		got, _ := names("username=human")
		assert.Equal(t, []string{"human"}, got)
		got, _ = names("username=Human")
		assert.Equal(t, []string{"Human"}, got, "只差大小寫的另一個帳號各自獨立")
		for _, v := range []string{"hum", "HUMAN", "human ", " human", "ops"} {
			got, _ = names(url.Values{"username": {v}}.Encode())
			assert.Empty(t, got, "%q 不命中", v)
		}
	})

	t.Run("missing_answers_with_empty_list", func(t *testing.T) {
		code, resp, raw := getJSON(t, r, "/users?username=no-such-user")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Empty(t, listField(resp, "username"))
		assert.EqualValues(t, 0, resp["total"])
		_, _, deleted := getJSON(t, r, "/users?username=gone")
		assert.Equal(t, raw, deleted, "已刪除的帳號與不存在同本文")
	})

	t.Run("agent_collision_does_not_grant_visibility", func(t *testing.T) {
		// 自動化帳號 agent 與人類帳號共用同一個使用者名稱唯一性，但預設列表不含自動化帳號
		_, _, missing := getJSON(t, r, "/users?username=no-such-user")
		_, _, raw := getJSON(t, r, "/users?username=agent")
		assert.Equal(t, missing, raw, "未要求包含自動化帳號時查不到")
		got, _ := names("username=agent&include_agents=true")
		assert.Equal(t, []string{"agent"}, got)
		got, _ = names("username=agent&kind=agent")
		assert.Equal(t, []string{"agent"}, got)
		got, _ = names("username=human&kind=agent")
		assert.Empty(t, got, "與 kind 交集")
	})

	t.Run("combines_with_search_active_and_paging", func(t *testing.T) {
		got, _ := names("username=human&search=ops")
		assert.Empty(t, got, "與 search 交集")
		got, _ = names("username=human-ops&search=ops")
		assert.Equal(t, []string{"human-ops"}, got)
		got, _ = names("username=dormant&active=true")
		assert.Empty(t, got, "與 active 交集")
		got, _ = names("username=dormant&active=false")
		assert.Equal(t, []string{"dormant"}, got)
		got, resp := names("username=human-ops&page=1&page_size=1")
		assert.Equal(t, []string{"human-ops"}, got, "在分頁之前套用")
		assert.EqualValues(t, 1, resp["total"])
	})

	t.Run("empty_value_is_bad_request", func(t *testing.T) {
		code, resp, raw := getJSON(t, r, "/users?username=")
		assertInvalidQueryParam(t, code, resp, raw, "username")
	})
}

func TestUserGroupHandler_ExactName(t *testing.T) {
	e := newUserGroupGetOneEnv(t)
	for _, name := range []string{"ops", "Ops", "ops-east", "dba"} {
		require.NoError(t, e.db.Create(&model.UserGroup{Name: name}).Error)
	}
	gone := model.UserGroup{Name: "retired"}
	require.NoError(t, e.db.Create(&gone).Error)
	require.NoError(t, e.db.Delete(&gone).Error)

	list := func(q string) ([]string, map[string]any, string) {
		t.Helper()
		code, resp, raw := getJSON(t, e.r, "/api/v1/user-groups?"+q, "X-Test-Role", model.RoleAdmin)
		require.Equal(t, http.StatusOK, code, raw)
		return listField(resp, "name"), resp, raw
	}

	got, resp, _ := list("name=ops")
	assert.Equal(t, []string{"ops"}, got)
	assert.EqualValues(t, 1, resp["total"])
	all, _, _ := list("")
	_, full, _ := getJSON(t, e.r, "/api/v1/user-groups", "X-Test-Role", model.RoleAdmin)
	for _, row := range full["data"].([]any) {
		if row.(map[string]any)["name"] == "ops" {
			assert.Equal(t, row, resp["data"].([]any)[0], "與列表中那一筆逐欄相同")
		}
	}
	assert.Len(t, all, 4)

	got, _, _ = list("name=Ops")
	assert.Equal(t, []string{"Ops"}, got, "只差大小寫的群組各自獨立")
	for _, v := range []string{"op", "OPS", "ops ", " ops"} {
		got, _, _ = list(url.Values{"name": {v}}.Encode())
		assert.Empty(t, got, "%q 不命中", v)
	}
	_, _, missing := list("name=no-such-group")
	_, _, deleted := list("name=retired")
	assert.Equal(t, missing, deleted, "已刪除的群組不被找到，與不存在同本文")

	code, r, raw := getJSON(t, e.r, "/api/v1/user-groups?name=", "X-Test-Role", model.RoleAdmin)
	assertInvalidQueryParam(t, code, r, raw, "name")

	// 缺群組管理能力者在入口即被拒，與是否帶 name、名稱是否存在無關
	c1, _, d1 := getJSON(t, e.r, "/api/v1/user-groups", "X-Test-Role", model.RoleUser)
	c2, _, d2 := getJSON(t, e.r, "/api/v1/user-groups?name=ops", "X-Test-Role", model.RoleUser)
	c3, _, d3 := getJSON(t, e.r, "/api/v1/user-groups?name=no-such-group", "X-Test-Role", model.RoleUser)
	assert.Equal(t, http.StatusForbidden, c1)
	assert.Equal(t, []int{c1, c1}, []int{c2, c3})
	assert.Equal(t, []string{d1, d1}, []string{d2, d3})
}

// idsCredentialScope 範圍化檢視的替身：檢視集合為固定的憑證識別（以查詢條件加在憑證主表上），
// 其餘判定一律放行。用來確認名稱查找在檢視集合之內生效。
type idsCredentialScope struct{ ids []uint }

func (s idsCredentialScope) CredentialScopeView(context.Context) (asset.CredentialScopeView, error) {
	return idsCredentialView(s), nil
}

func (s idsCredentialScope) CredentialImpactScopeIn(context.Context, *gorm.DB, string, []uint) (map[uint]bool, map[uint]bool, bool, error) {
	return nil, nil, false, nil
}

type idsCredentialView struct{ ids []uint }

func (v idsCredentialView) ApplyVisible(q *gorm.DB) (*gorm.DB, error) {
	return q.Where("credentials.id IN ?", v.ids), nil
}

func (v idsCredentialView) AssetsInView(ids []uint) (map[uint]bool, error) { return allIDs(ids), nil }

func (v idsCredentialView) AssetsInCapability(_ string, ids []uint) (map[uint]bool, error) {
	return allIDs(ids), nil
}

func (v idsCredentialView) Allows(string, []uint) (bool, string) { return true, "" }

func (v idsCredentialView) MaskNodes(nodeIDs []uint) ([]uint, int) { return nodeIDs, 0 }

func allIDs(ids []uint) map[uint]bool {
	out := make(map[uint]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func TestCredentialHandler_ExactName(t *testing.T) {
	f := setupCredentialAPIEnv(t) // 既有：共用憑證「共用維運帳號」與兩台資產各自的專用憑證
	r, mgr := credentialTestRouter(t, f)
	tok, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)
	ids := map[string]uint{"共用維運帳號": f.sharedID}
	for _, n := range []string{"ops-key", "OPS-KEY", "ops-key-2"} {
		c, err := f.creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
			Name: n, Username: "svc", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-for-test",
		})
		require.NoError(t, err)
		ids[n] = c.ID
	}
	list := func(q string) (int, map[string]any, string) {
		t.Helper()
		return getJSON(t, r, "/api/v1/credentials?"+q, "Authorization", "Bearer "+tok)
	}
	names := func(q string) []string {
		t.Helper()
		code, resp, raw := list(q)
		require.Equal(t, http.StatusOK, code, raw)
		got := listField(resp, "name")
		assert.EqualValues(t, len(got), resp["total"], "總數在篩選之後：%s", raw)
		return got
	}

	t.Run("exact_match_with_creation_trim", func(t *testing.T) {
		assert.Equal(t, []string{"ops-key"}, names("name=ops-key"))
		assert.Equal(t, []string{"OPS-KEY"}, names("name=OPS-KEY"), "只差大小寫的共用憑證各自獨立")
		// 建立時名稱先去頭尾空白再判重，查找套用同一規則
		assert.Equal(t, []string{"ops-key"}, names(url.Values{"name": {"  ops-key\t"}}.Encode()))
		for _, v := range []string{"ops", "ops-ke", "Ops-Key", "ops key"} {
			assert.Empty(t, names(url.Values{"name": {v}}.Encode()), "%q 不命中", v)
		}
		assert.Equal(t, []string{"共用維運帳號"}, names(url.Values{"name": {"共用維運帳號"}}.Encode()))
	})

	t.Run("combines_with_other_filters_and_paging", func(t *testing.T) {
		assert.Empty(t, names("name=ops-key&scope=dedicated"), "與 scope 交集")
		assert.Equal(t, []string{"ops-key"}, names("name=ops-key&scope=shared"))
		assert.Empty(t, names("name=ops-key&username=shareduser"), "與 username 交集")
		assert.Empty(t, names("name=ops-key&search=key-2"), "與 search 交集")
		code, resp, raw := list("name=ops-key-2&page=1&page_size=1")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"ops-key-2"}, listField(resp, "name"), "在分頁之前套用")
		assert.EqualValues(t, 1, resp["total"])
	})

	t.Run("blank_value_is_bad_request", func(t *testing.T) {
		for _, v := range []string{"", "   "} {
			code, resp, raw := list(url.Values{"name": {v}}.Encode())
			assertInvalidQueryParam(t, code, resp, raw, "name")
		}
	})

	t.Run("deleted_shared_credential_with_same_name", func(t *testing.T) {
		require.NoError(t, f.db.AutoMigrate(&model.CredentialImpactConfirmation{})) // 刪除流程清除影響確認用
		old, err := f.creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
			Name: "retired-key", Username: "svc", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-for-test",
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"retired-key"}, names("name=retired-key"), "前提：刪除前查得到")
		require.NoError(t, f.creds.Delete(credAdminCtx(), old.ID))
		_, _, missing := list("name=no-such-credential")
		_, _, raw := list("name=retired-key")
		assert.Equal(t, missing, raw, "已刪除的共用憑證不被找到，與不存在同本文")

		// 同名重建後只找到新的那一筆
		fresh, err := f.creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
			Name: "retired-key", Username: "svc", ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-for-test",
		})
		require.NoError(t, err)
		code, resp, raw := list("name=retired-key")
		require.Equal(t, http.StatusOK, code, raw)
		data := resp["data"].([]any)
		require.Len(t, data, 1, raw)
		assert.EqualValues(t, fresh.ID, data[0].(map[string]any)["id"], "只回重建的那一筆")
		assert.EqualValues(t, 1, resp["total"])
	})

	t.Run("out_of_view_answers_like_missing", func(t *testing.T) {
		f.creds.WithScopeSource(idsCredentialScope{ids: []uint{ids["ops-key"]}})
		t.Cleanup(func() { f.creds.WithScopeSource(nil) })
		assert.Equal(t, []string{"ops-key"}, names("name=ops-key"), "檢視集合內的照常找到")
		_, _, missing := list("name=no-such-credential")
		for _, n := range []string{"OPS-KEY", "ops-key-2", "共用維運帳號"} {
			_, _, raw := list(url.Values{"name": {n}}.Encode())
			assert.Equal(t, missing, raw, "檢視集合外的 %q 與不存在同本文", n)
		}
	})
}
