package api

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// fakeRoleDefinitionReader 回固定的可見列表；calls 記錄 List 被呼叫的次數（400 必須在讀取之前寫出）。
type fakeRoleDefinitionReader struct {
	rows  []identity.RoleDefinitionRow
	calls int
}

func (f *fakeRoleDefinitionReader) List(context.Context, *authz.Principal) (*identity.RoleDefinitionList, error) {
	f.calls++
	rows := append([]identity.RoleDefinitionRow{}, f.rows...)
	return &identity.RoleDefinitionList{Data: rows, Total: len(rows), CanDefine: true}, nil
}

func (f *fakeRoleDefinitionReader) Get(context.Context, uint) (*identity.RoleDefinitionDetail, error) {
	return nil, identity.ErrRoleDefinitionNotFound
}

func (f *fakeRoleDefinitionReader) DraftSummary([]string) (*identity.RoleDraftSummary, error) {
	return nil, nil
}

func TestRoleDefinitionListNameLookup(t *testing.T) {
	reader := &fakeRoleDefinitionReader{rows: []identity.RoleDefinitionRow{
		{ID: 1, Name: "資料庫維運"},
		{ID: 2, Name: "稽核助理"},
		{ID: 3, Name: "資料庫維運（研發）"},
		{ID: 4, Name: "Ops"},
	}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/role-definitions", NewRoleDefinitionHandler(reader, nil).List)
	get := func(q string) (int, map[string]any, string) { return getJSON(t, r, "/role-definitions"+q) }

	t.Run("不帶參數：列表不變", func(t *testing.T) {
		code, resp, raw := get("")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Len(t, resp["data"], 4)
		assert.EqualValues(t, 4, resp["total"])
		assert.Equal(t, true, resp["can_define"])
	})

	t.Run("查到恰好一筆，就是列表中的那一筆", func(t *testing.T) {
		code, resp, raw := get("?" + url.Values{"name": {"資料庫維運"}}.Encode())
		require.Equal(t, http.StatusOK, code, raw)
		data := resp["data"].([]any)
		require.Len(t, data, 1)
		assert.EqualValues(t, 1, data[0].(map[string]any)["id"])
		assert.EqualValues(t, 1, resp["total"], "總數只計符合的列")
		assert.Equal(t, true, resp["can_define"], "其他頂層欄位不變")
	})

	t.Run("去除前後空白後逐字相等：與名稱唯一性判定同一個定義", func(t *testing.T) {
		code, resp, raw := get("?" + url.Values{"name": {"  資料庫維運\t"}}.Encode())
		require.Equal(t, http.StatusOK, code, raw)
		require.Len(t, resp["data"], 1)
		assert.Equal(t, identity.NormalizeRoleName("  資料庫維運\t"), "資料庫維運")
		// 不做部分比對、不改大小寫
		for _, miss := range []string{"資料庫", "ops", "OPS ", "資料庫維運（研"} {
			code, resp, raw = get("?" + url.Values{"name": {miss}}.Encode())
			require.Equal(t, http.StatusOK, code, raw)
			assert.Empty(t, resp["data"], "%q 不應命中", miss)
			assert.EqualValues(t, 0, resp["total"])
		}
	})

	t.Run("查不到：空列表與總數 0", func(t *testing.T) {
		code, resp, raw := get("?name=no-such-role")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []any{}, resp["data"])
		assert.EqualValues(t, 0, resp["total"])
	})

	t.Run("參數重複或為空：400，且不讀取任何資料", func(t *testing.T) {
		for _, q := range []string{"?name=Ops&name=Ops", "?name=Ops&name=稽核助理", "?name=", "?name=%20%20"} {
			before := reader.calls
			code, resp, raw := get(q)
			assert.Equal(t, http.StatusBadRequest, code, "%s：%s", q, raw)
			assert.Equal(t, string(apierror.CodeInvalidQueryParam), resp["code"], q)
			assert.Equal(t, before, reader.calls, "%s：400 在讀取之前寫出", q)
		}
	})
}
