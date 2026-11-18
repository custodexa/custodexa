package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 分頁參數如實：每頁筆數超過上限時套用上限（不退回預設），回應帶實際套用的頁碼與每頁筆數；
// 各端點對不合法分頁值的既有處理不變（授權與使用者列表套用預設，共用憑證列表回 400）。

func TestAuthorizationHandler_PageSize(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int
	}{
		{"101", 100}, {"500", 100}, {"100", 100}, {"1", 1}, {"37", 37},
		{"0", 20}, {"-3", 20}, {"abc", 20}, {"", 20},
	} {
		t.Run(fmt.Sprintf("page_size=%q", c.raw), func(t *testing.T) {
			svc := new(MockAuthorizationService)
			// 服務收到的每頁筆數即實際套用的值
			svc.On("ListAuthorizations", map[string]interface{}{}, 1, c.want).
				Return([]*model.AssetAuthorization{}, int64(0), nil).Once()
			router := setupTestRouter()
			router.GET("/authorizations", NewAuthorizationHandler(svc, nil).List)
			path := "/authorizations"
			if c.raw != "" {
				path += "?page_size=" + c.raw
			}
			code, resp, raw := getJSON(t, router, path)
			require.Equal(t, http.StatusOK, code, raw)
			assert.EqualValues(t, c.want, resp["page_size"], "回應帶實際套用的每頁筆數")
			assert.EqualValues(t, 1, resp["page"])
			svc.AssertExpectations(t)
		})
	}
}

func TestUserHandler_ListPaging(t *testing.T) {
	db, h, _, _ := principalAPIEnv(t)
	for i := 0; i < 4; i++ {
		u := model.User{Username: fmt.Sprintf("paging-%d", i), Password: "!", Kind: model.KindHuman, Active: true}
		require.NoError(t, db.Create(&u).Error)
	}
	r := gin.New()
	r.GET("/users", h.List)

	code, resp, raw := getJSON(t, r, "/users?page=1&page_size=2")
	require.Equal(t, http.StatusOK, code, raw)
	assert.EqualValues(t, 1, resp["page"])
	assert.EqualValues(t, 2, resp["page_size"])
	assert.Len(t, resp["data"], 2, "資料至多一頁")
	assert.EqualValues(t, 5, resp["total"], "總數為全部符合條件的筆數（預設不含自動化帳號）")

	code, resp, _ = getJSON(t, r, "/users?page=3&page_size=2")
	require.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 3, resp["page"])
	assert.Len(t, resp["data"], 1)

	// 不合法的值照舊套用預設，並在回應中帶出套用後的值
	for _, q := range []string{"", "?page=0&page_size=0", "?page=abc&page_size=-1", "?page_size=xyz"} {
		code, resp, raw = getJSON(t, r, "/users"+q)
		require.Equal(t, http.StatusOK, code, raw)
		assert.EqualValues(t, 1, resp["page"], "%s", q)
		assert.EqualValues(t, 20, resp["page_size"], "%s", q)
	}
	// 每頁筆數上限 1000：上限以內原樣套用；超過時套用上限並回報（改前 5000 原樣套用）
	code, resp, _ = getJSON(t, r, "/users?page=1&page_size=1000")
	require.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 1000, resp["page_size"])
	for _, q := range []string{"/users?page=1&page_size=5000", "/users?page_size=1001", "/users?page_size=99999999999"} {
		code, resp, raw = getJSON(t, r, q)
		require.Equal(t, http.StatusOK, code, raw)
		assert.EqualValues(t, 1000, resp["page_size"], "%s：回報實際套用的上限", q)
		assert.EqualValues(t, 5, resp["total"], "%s：總數為全部符合條件的筆數", q)
	}
	// 資料確實以上限切頁：補到 1005 位，每頁 5000 只回 1000 筆，總數仍為全部
	extra := make([]model.User, 0, 1000)
	for i := 0; i < 1000; i++ {
		extra = append(extra, model.User{Username: fmt.Sprintf("paging-cap-%04d", i), Password: "!", Kind: model.KindHuman, Active: true})
	}
	require.NoError(t, db.CreateInBatches(&extra, 200).Error)
	code, resp, raw = getJSON(t, r, "/users?page=1&page_size=5000")
	require.Equal(t, http.StatusOK, code, raw)
	assert.EqualValues(t, 1000, resp["page_size"])
	assert.Len(t, resp["data"], 1000, "資料至多 1000 筆")
	assert.EqualValues(t, 1005, resp["total"])
	code, resp, _ = getJSON(t, r, "/users?page=2&page_size=5000")
	require.Equal(t, http.StatusOK, code)
	assert.Len(t, resp["data"], 5, "第 2 頁以上限為每頁筆數接續")
}

func TestParseListPageSize(t *testing.T) {
	for raw, want := range map[string]int{
		"": 20, "abc": 20, "0": 20, "-1": 20, "1.5": 20,
		"1": 1, "999": 999, "1000": 1000, "1001": 1000, "5000": 1000, "99999999999999999999": 20,
	} {
		assert.Equal(t, want, parseListPageSize(raw, 20), "page_size=%q", raw)
	}
}

func TestCredentialListPagingReportsApplied(t *testing.T) {
	f := setupCredentialAPIEnv(t)
	r, mgr := credentialTestRouter(t, f)
	tok, err := mgr.GenerateToken(1, "admin", "a@example.com", model.RoleAdmin, crypto.AuthContext{})
	require.NoError(t, err)
	get := func(q string) (int, map[string]any, string) {
		return getJSON(t, r, "/api/v1/credentials"+q, "Authorization", "Bearer "+tok)
	}

	code, resp, raw := get("")
	require.Equal(t, http.StatusOK, code, raw)
	_, hasPage := resp["page"]
	_, hasSize := resp["page_size"]
	assert.False(t, hasPage || hasSize, "未帶頁碼時回全量、不帶分頁欄位：%s", raw)
	total := resp["total"]

	code, resp, raw = get("?page=1&page_size=2")
	require.Equal(t, http.StatusOK, code, raw)
	assert.EqualValues(t, 1, resp["page"])
	assert.EqualValues(t, 2, resp["page_size"])
	assert.Equal(t, total, resp["total"])

	code, resp, _ = get("?page=2")
	require.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 2, resp["page"])
	assert.EqualValues(t, credentialDefaultPageSize, resp["page_size"], "未帶每頁筆數時回報預設值")

	code, resp, _ = get("?page=1&page_size=100000")
	require.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, credentialMaxPageSize, resp["page_size"], "超過上限時回報實際套用的上限")

	// 只帶每頁筆數、不帶頁碼：維持不分頁、不帶分頁欄位
	code, resp, _ = get("?page_size=2")
	require.Equal(t, http.StatusOK, code)
	_, hasPage = resp["page"]
	assert.False(t, hasPage)

	// 不合法的分頁值照舊回 400 並指出參數
	for q, field := range map[string]string{"?page=0": "page", "?page=1&page_size=abc": "page_size", "?page=x": "page"} {
		code, resp, raw = get(q)
		assertInvalidQueryParam(t, code, resp, raw, field)
	}

	// 資料確實依回報的值切頁：共用憑證筆數超過每頁上限，逐頁比對識別與筆數
	for i := 0; i < credentialMaxPageSize+5; i++ {
		n := fmt.Sprintf("paging-cred-%03d", i)
		require.NoError(t, f.db.Create(&model.Credential{Name: &n, Scope: model.CredentialScopeShared, Username: "svc",
			SecretType: model.ChangeSecretTypePassword, AuthMethod: "sql", ProtocolFamily: model.ProtocolFamilySSH}).Error)
	}
	ids := func(resp map[string]any) []any {
		var out []any
		for _, row := range resp["data"].([]any) {
			out = append(out, row.(map[string]any)["id"])
		}
		return out
	}
	code, resp, raw = get("")
	require.Equal(t, http.StatusOK, code, raw)
	all := ids(resp)
	require.Greater(t, len(all), credentialMaxPageSize, "前提：資料超過每頁上限")
	assert.EqualValues(t, len(all), resp["total"], "未帶頁碼時回全量")

	pages := (len(all) + 1) / 2
	for _, p := range []int{1, 2, pages} {
		code, resp, raw = get(fmt.Sprintf("?page=%d&page_size=2", p))
		require.Equal(t, http.StatusOK, code, raw)
		end := p * 2
		if end > len(all) {
			end = len(all)
		}
		assert.Equal(t, all[(p-1)*2:end], ids(resp), "第 %d 頁（每頁 2）的識別依全量順序切出", p)
		assert.EqualValues(t, len(all), resp["total"], "第 %d 頁的總數為全量", p)
	}
	code, resp, _ = get(fmt.Sprintf("?page=%d&page_size=2", pages+1))
	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, resp["data"], "超過末頁為空")
	assert.EqualValues(t, len(all), resp["total"])

	code, resp, _ = get("?page=1&page_size=100000")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, all[:credentialMaxPageSize], ids(resp), "超過上限時第 1 頁恰為上限筆數")
	code, resp, _ = get("?page=2&page_size=100000")
	require.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, credentialMaxPageSize, resp["page_size"])
	assert.Equal(t, all[credentialMaxPageSize:], ids(resp), "第 2 頁以上限為每頁筆數接續")

	code, resp, _ = get("?page_size=2")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, all, ids(resp), "只帶每頁筆數、不帶頁碼時回全量")
	_, hasPage = resp["page"]
	_, hasSize = resp["page_size"]
	assert.False(t, hasPage || hasSize, "只帶每頁筆數、不帶頁碼時不帶兩個分頁欄位")
}
