package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產列表的名稱精確查找：三條路徑（檢視捷徑主體的全量、一般使用者的授權集合、範圍化檢視者的聯集）
// 都在可見範圍收斂之後、計數與分頁之前套用，比對為原樣字串等值。每個案例以「帶 name 的列表」
// 等於「不帶 name 的同一列表中名稱完全相同的那幾列」為準，並與不存在的名稱比對回應。

type assetNameEnv struct {
	*treeFixture
	h *AssetHandler
}

func newAssetNameEnv(t *testing.T) *assetNameEnv {
	t.Helper()
	f := newTreeFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.AssetAccount{}))
	old := database.DB
	database.DB = f.db
	t.Cleanup(func() { database.DB = old })
	svc, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	svc.SetTopologyPermissionPort(noopTopologyPort{})
	h := NewAssetHandler(svc, authz.NewAssetAuthorizationService(f.db), nil)
	h.SetAssetScope(authz.NewAssetScopeReader(f.eval, f.db))
	return &assetNameEnv{treeFixture: f, h: h}
}

// listAssets 回狀態碼、整體回應與原始本文。
func (e *assetNameEnv) listAssets(uid uint, q url.Values) (int, map[string]any, string) {
	e.t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
		require.NoError(e.t, err)
		middleware.SetPrincipal(c, p)
		c.Set("userID", uid)
		c.Set("username", fmt.Sprintf("u%d", uid))
		c.Next()
	})
	r.GET("/assets", e.h.List)
	req := httptest.NewRequest(http.MethodGet, "/assets?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp, w.Body.String()
}

func assetRows(resp map[string]any) []map[string]any {
	data, _ := resp["data"].([]any)
	out := make([]map[string]any, 0, len(data))
	for _, d := range data {
		out = append(out, d.(map[string]any))
	}
	return out
}

func assetNames(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r["name"].(string))
	}
	sort.Strings(out)
	return out
}

func withQuery(base url.Values, kv ...string) url.Values {
	q := url.Values{}
	for k, v := range base {
		q[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return q
}

// assertExactNameAgreesWithList 帶 name 的結果＝同一主體不帶 name 的列表（同其他篩選、整頁取回）中名稱完全相同的列，
// 總數等於筆數；回帶 name 結果的名稱清單。
func (e *assetNameEnv) assertExactNameAgreesWithList(t *testing.T, uid uint, base url.Values, name string) []string {
	t.Helper()
	full := withQuery(base, "page_size", "1000")
	code, all, raw := e.listAssets(uid, full)
	require.Equal(t, http.StatusOK, code, raw)
	var want []map[string]any
	for _, r := range assetRows(all) {
		if r["name"] == name {
			want = append(want, r)
		}
	}
	code, got, raw := e.listAssets(uid, withQuery(full, "name", name))
	require.Equal(t, http.StatusOK, code, raw)
	gotRows := assetRows(got)
	assert.ElementsMatch(t, want, gotRows, "name=%q 的結果等於不帶 name 的列表中名稱完全相同的列（%v）", name, base)
	assert.EqualValues(t, len(want), got["total"], "name=%q 的總數只計名稱相同者", name)
	return assetNames(gotRows)
}

func TestAssetHandler_ExactName(t *testing.T) {
	setup := func(t *testing.T) (e *assetNameEnv, admin, mgr, plain uint) {
		e = newAssetNameEnv(t)
		// 只差大小寫、只差尾端空白的名稱：資產建立時以原樣字串判重，這些是不同的資產
		e.assets["A-DB"] = e.asset("A-DB", "sit/web")
		e.assets["a-db "] = e.asset("a-db ", "prod/db/b")
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", e.assets["a-db-b"]).Update("active", false).Error)
		admin = e.superAdmin()
		mgr = e.user("asset-node-manager")
		e.grantNodes(mgr, e.role(authz.PermAssetView), "prod/db")
		plain = e.user("asset-plain-user")
		for _, n := range []string{"a-db", "a-db-b", "a-sit-web"} {
			e.connect(plain, e.assets[n])
		}
		return e, admin, mgr, plain
	}

	t.Run("each_path_returns_only_the_exact_match", func(t *testing.T) {
		e, admin, mgr, plain := setup(t)
		// 先確認三個主體確實走三條不同路徑：範圍化聯集帶管理範圍摘要，授權集合的列帶入口判定欄
		_, scoped, _ := e.listAssets(mgr, url.Values{"name": {"a-db"}})
		assert.Contains(t, scoped, assetFieldManagementScope, "節點範圍管理者走範圍化聯集")
		_, authorized, _ := e.listAssets(plain, url.Values{"name": {"a-db"}})
		assert.NotContains(t, authorized, assetFieldManagementScope)
		assert.Contains(t, assetRows(authorized)[0], "permission", "一般使用者走授權集合")
		_, full, _ := e.listAssets(admin, url.Values{"name": {"a-db"}})
		assert.NotContains(t, full, assetFieldManagementScope)
		assert.NotContains(t, assetRows(full)[0], "permission", "超級管理者走全量")
		for who, uid := range map[string]uint{"full": admin, "scoped": mgr, "authorized": plain} {
			got := e.assertExactNameAgreesWithList(t, uid, nil, "a-db")
			assert.Equal(t, []string{"a-db"}, got, "%s 路徑：完全相符只回該資產", who)
		}
	})

	t.Run("partial_and_variant_names_do_not_match", func(t *testing.T) {
		e, admin, mgr, plain := setup(t)
		for who, uid := range map[string]uint{"full": admin, "scoped": mgr, "authorized": plain} {
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, nil, "a-d"), "%s：前半段不命中", who)
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, nil, "db"), "%s：子字串不命中", who)
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, nil, " a-db"), "%s：前置空白不改寫", who)
		}
		// 只差大小寫與尾端空白的資產各自獨立，查找只回名稱位元組相同的那一筆
		assert.Equal(t, []string{"A-DB"}, e.assertExactNameAgreesWithList(t, admin, nil, "A-DB"))
		assert.Equal(t, []string{"a-db "}, e.assertExactNameAgreesWithList(t, admin, nil, "a-db "))
		assert.Equal(t, []string{"a-db "}, e.assertExactNameAgreesWithList(t, mgr, nil, "a-db "), "範圍內的尾端空白變體")
	})

	t.Run("out_of_view_answers_like_missing", func(t *testing.T) {
		e, _, mgr, plain := setup(t)
		for who, c := range map[string]struct {
			uid    uint
			hidden []string
		}{
			"scoped":     {mgr, []string{"a-web", "a-sit-web", "A-DB", "a-prod"}},
			"authorized": {plain, []string{"a-web", "A-DB", "a-db-a", "a-db "}},
		} {
			code, _, missing := e.listAssets(c.uid, url.Values{"name": {"no-such-asset"}})
			require.Equal(t, http.StatusOK, code)
			var miss map[string]any
			require.NoError(t, json.Unmarshal([]byte(missing), &miss))
			assert.EqualValues(t, 0, miss["total"])
			for _, n := range c.hidden {
				code, _, raw := e.listAssets(c.uid, url.Values{"name": {n}})
				require.Equal(t, http.StatusOK, code)
				assert.Equal(t, missing, raw, "%s：看不到的 %q 與不存在的名稱同本文", who, n)
			}
		}
	})

	t.Run("combines_with_search_protocol_active_and_node", func(t *testing.T) {
		e, admin, mgr, plain := setup(t)
		for who, uid := range map[string]uint{"full": admin, "scoped": mgr, "authorized": plain} {
			assert.Equal(t, []string{"a-db"}, e.assertExactNameAgreesWithList(t, uid, url.Values{"search": {"db"}}, "a-db"), who)
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, url.Values{"search": {"sit"}}, "a-db"), "%s：與 search 交集", who)
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, url.Values{"protocol": {"rdp"}}, "a-db"), "%s：與 protocol 交集", who)
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, url.Values{"active": {"true"}}, "a-db-b"), "%s：停用資產不符 active=true", who)
			assert.Equal(t, []string{"a-db-b"}, e.assertExactNameAgreesWithList(t, uid, url.Values{"active": {"false"}}, "a-db-b"), who)
			assert.Empty(t, e.assertExactNameAgreesWithList(t, uid, url.Values{"node_id": {e.idStr("sit")}}, "a-db"), "%s：與節點篩選交集", who)
		}
	})

	t.Run("applied_before_count_and_paging", func(t *testing.T) {
		e, admin, mgr, plain := setup(t)
		for who, uid := range map[string]uint{"full": admin, "scoped": mgr, "authorized": plain} {
			code, all, _ := e.listAssets(uid, url.Values{"page_size": {"1"}})
			require.Equal(t, http.StatusOK, code)
			require.Greater(t, all["total"].(float64), float64(1), "%s：不帶 name 時總數大於一頁", who)
			code, got, raw := e.listAssets(uid, url.Values{"page_size": {"1"}, "page": {"1"}, "name": {"a-db"}})
			require.Equal(t, http.StatusOK, code, raw)
			assert.EqualValues(t, 1, got["total"], "%s：計數在篩選之後", who)
			assert.Equal(t, []string{"a-db"}, assetNames(assetRows(got)), "%s：第一頁就是相符的那一筆", who)
			code, got, _ = e.listAssets(uid, url.Values{"page_size": {"1"}, "page": {"2"}, "name": {"a-db"}})
			require.Equal(t, http.StatusOK, code)
			assert.Empty(t, assetRows(got), "%s：第二頁為空", who)
		}
	})

	t.Run("target_on_a_later_unfiltered_page_is_found_on_the_first_page", func(t *testing.T) {
		e, admin, mgr, plain := setup(t)
		for who, uid := range map[string]uint{"full": admin, "scoped": mgr, "authorized": plain} {
			code, all, raw := e.listAssets(uid, url.Values{"page_size": {"1000"}})
			require.Equal(t, http.StatusOK, code, raw)
			rows := assetRows(all)
			require.GreaterOrEqual(t, len(rows), 3, "%s：前提：可見資產至少三筆", who)
			// 不帶 name 時排在最後的資產：每頁一筆時它在末頁，不在第一頁
			target := rows[len(rows)-1]["name"].(string)
			code, first, _ := e.listAssets(uid, url.Values{"page_size": {"1"}, "page": {"1"}})
			require.Equal(t, http.StatusOK, code)
			require.NotEqual(t, []string{target}, assetNames(assetRows(first)), "%s：前提：目標不在未篩選的第一頁", who)

			code, got, raw := e.listAssets(uid, url.Values{"page_size": {"1"}, "page": {"1"}, "name": {target}})
			require.Equal(t, http.StatusOK, code, raw)
			assert.Equal(t, []string{target}, assetNames(assetRows(got)), "%s：篩選後目標在第一頁", who)
			assert.EqualValues(t, 1, got["total"], "%s：總數只計相符者", who)
		}
	})

	t.Run("empty_value_is_bad_request_before_any_lookup", func(t *testing.T) {
		e, admin, mgr, plain := setup(t)
		var first string
		for _, uid := range []uint{admin, mgr, plain} {
			code, resp, raw := e.listAssets(uid, url.Values{"name": {""}})
			require.Equal(t, http.StatusBadRequest, code, raw)
			assert.Equal(t, "VALIDATION_INVALID_QUERY_PARAM", resp["code"], raw)
			params, _ := resp["params"].(map[string]any)
			assert.Equal(t, "name", params["field"], raw)
			if first == "" {
				first = raw
			}
			assert.Equal(t, first, raw, "空值的 400 只由輸入決定，與主體無關")
		}
		code, _, _ := e.listAssets(admin, url.Values{"name": {" "}})
		assert.Equal(t, http.StatusOK, code, "只有空白的值不改寫、不視為空值")
	})

	t.Run("absent_parameter_keeps_list_unchanged", func(t *testing.T) {
		e, admin, _, _ := setup(t)
		_, a, rawA := e.listAssets(admin, url.Values{"page_size": {"1000"}})
		_, _, rawB := e.listAssets(admin, url.Values{"page_size": {"1000"}, "username": {"a-db"}})
		assert.Equal(t, rawA, rawB, "資產列表不認得的參數照舊忽略")
		assert.EqualValues(t, len(e.assets), a["total"])
	})
}
