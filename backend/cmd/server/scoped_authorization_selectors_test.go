package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 授權畫面的有限選擇器夾具。
// 拓撲：p（定位祖先）→ a（範圍根）→ b；c（範圍外）→ d。名稱以 zz-so- 起頭。
//   - x 掛 b 帶標籤 web、prod；y 掛 d 帶標籤 db、prod；m 同時掛 b 與 d 帶標籤 web。
type soEnv struct {
	*awEnv
	op, nobody, emptyScope uint
	x, y, m                uint
}

// newSOEnv 的 extra 見 newAWEnv。
func newSOEnv(t *testing.T, extra ...authz.Permission) *soEnv {
	t.Helper()
	e := &soEnv{awEnv: newAWEnv(t, extra...)}
	e.node("zz-so-p", "")
	e.node("zz-so-a", "zz-so-p")
	e.node("zz-so-b", "zz-so-a")
	e.node("zz-so-c", "")
	e.node("zz-so-d", "zz-so-c")
	e.x = e.asset("zz-so-x", "zz-so-b")
	e.y = e.asset("zz-so-y", "zz-so-d")
	e.m = e.asset("zz-so-m", "zz-so-b", "zz-so-d")
	for id, tags := range map[uint]string{e.x: "web,prod", e.y: "db,Prod", e.m: "Web"} {
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", id).Update("tags", tags).Error)
	}
	e.op = e.user("zz-so-op")
	e.grantNodes(e.op, e.role(authz.PermAuthorizationManage), "zz-so-a")
	e.nobody = e.user("zz-so-nobody")
	// 指派存在但沒有任何範圍節點：不算有效
	e.emptyScope = e.user("zz-so-empty")
	e.grantNodes(e.emptyScope, e.role(authz.PermAuthorizationManage))
	return e
}

func (e *soEnv) getJSON(uid uint, path string) (int, map[string]any, string) {
	e.t.Helper()
	code, body := e.do2(uid, "GET", path, "")
	var out map[string]any
	if code == http.StatusOK {
		require.NoError(e.t, json.Unmarshal([]byte(body), &out), body)
	}
	return code, out, body
}

func soRows(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	raw, ok := out["data"].([]any)
	require.True(t, ok, "data 不是陣列")
	rows := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		rows = append(rows, r.(map[string]any))
	}
	return rows
}

func soKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func soNames(rows []map[string]any, key string) []string {
	var out []string
	for _, r := range rows {
		out = append(out, fmt.Sprint(r[key]))
	}
	sort.Strings(out)
	return out
}

// TestAuthorizationSubjectOptions 主體目錄：欄位固定、有生效指派才可讀（空範圍指派不算）、
// 不依節點範圍過濾、搜尋與分頁在資料庫端完成。
func TestAuthorizationSubjectOptions(t *testing.T) {
	e := newSOEnv(t)
	grp := model.UserGroup{Name: "zz-so-grp", Description: "so group"}
	require.NoError(t, e.db.Create(&grp).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: grp.ID, UserID: e.op, Manual: true}).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMember{UserGroupID: grp.ID, UserID: e.nobody, Manual: true}).Error)

	t.Run("user rows have a fixed field set", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, "/api/v1/authorizations/subject-options?kind=user&search=zz-so-op")
		require.Equal(t, http.StatusOK, code, body)
		rows := soRows(t, out)
		require.Len(t, rows, 1, body)
		require.Equal(t, []string{"active", "display_name", "id", "kind", "roles", "username"}, soKeys(rows[0]))
		require.Equal(t, "zz-so-op", rows[0]["username"])
		require.Equal(t, "human", rows[0]["kind"])
		require.NotContains(t, body, "test.local")
	})
	t.Run("directory is not filtered by node scope", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, "/api/v1/authorizations/subject-options?kind=user&search=zz-so-&page_size=100")
		require.Equal(t, http.StatusOK, code, body)
		require.Equal(t, []string{"zz-so-empty", "zz-so-nobody", "zz-so-op"}, soNames(soRows(t, out), "username"))
		require.EqualValues(t, 3, out["total"])
	})
	t.Run("group rows have a fixed field set and member count", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, "/api/v1/authorizations/subject-options?kind=user_group")
		require.Equal(t, http.StatusOK, code, body)
		rows := soRows(t, out)
		require.Len(t, rows, 1, body)
		require.Equal(t, []string{"description", "id", "member_count", "name"}, soKeys(rows[0]))
		require.EqualValues(t, 2, rows[0]["member_count"])
	})
	t.Run("paging total is independent of page size and is capped", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, "/api/v1/authorizations/subject-options?kind=user&search=zz-so-&page=2&page_size=2")
		require.Equal(t, http.StatusOK, code, body)
		require.Len(t, soRows(t, out), 1)
		require.EqualValues(t, 3, out["total"])
		_, out, _ = e.getJSON(e.op, "/api/v1/authorizations/subject-options?kind=user&page_size=5000")
		require.EqualValues(t, 1000, out["page_size"])
	})
	t.Run("global holder reads the directory", func(t *testing.T) {
		holder := e.user("zz-so-global-holder")
		e.grantGlobal(holder, e.role(authz.PermAuthorizationManage))
		for _, uid := range []uint{e.super, holder} {
			code, _, body := e.getJSON(uid, "/api/v1/authorizations/subject-options?kind=user")
			require.Equal(t, http.StatusOK, code, body)
		}
	})
	t.Run("no effective assignment gets a single forbidden", func(t *testing.T) {
		for _, uid := range []uint{e.nobody, e.emptyScope} {
			code, body := e.do2(uid, "GET", "/api/v1/authorizations/subject-options?kind=user", "")
			require.Equal(t, http.StatusForbidden, code, body)
			require.NotContains(t, body, "zz-so-")
		}
	})
	t.Run("kind is required", func(t *testing.T) {
		for _, q := range []string{"", "?kind=asset"} {
			code, _ := e.do2(e.op, "GET", "/api/v1/authorizations/subject-options"+q, "")
			require.Equal(t, http.StatusBadRequest, code, q)
		}
	})
}

// TestAuthorizationTargetOptions 客體候選：資產、節點、標籤皆依授權規則管理能力的集合述詞投影；
// 範圍外的歸屬節點只給計數；範圍外的節點篩選與不存在同形。
func TestAuthorizationTargetOptions(t *testing.T) {
	e := newSOEnv(t)
	const missing = 999913
	base := "/api/v1/authorizations/target-options?kind="

	t.Run("asset candidates are the in-scope assets", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, base+"asset")
		require.Equal(t, http.StatusOK, code, body)
		require.Equal(t, []string{"zz-so-m", "zz-so-x"}, soNames(soRows(t, out), "name"), body)
		require.EqualValues(t, 2, out["total"])
		require.NotContains(t, body, "zz-so-y")
		require.NotContains(t, body, "zz-so-d")
		require.NotContains(t, body, "zz-so-c")
	})
	t.Run("asset rows carry in-scope nodes and an out of scope count only when masked", func(t *testing.T) {
		_, out, body := e.getJSON(e.op, base+"asset&search=zz-so-m")
		rows := soRows(t, out)
		require.Len(t, rows, 1, body)
		require.Equal(t, []string{"host", "id", "name", "nodes", "out_of_scope_node_count", "protocol"}, soKeys(rows[0]))
		require.EqualValues(t, 1, rows[0]["out_of_scope_node_count"])
		nodes := rows[0]["nodes"].([]any)
		require.Len(t, nodes, 1)
		require.Equal(t, "zz-so-p / zz-so-a / zz-so-b", nodes[0].(map[string]any)["path"])
		_, out, body = e.getJSON(e.op, base+"asset&search=zz-so-x")
		row := soRows(t, out)[0]
		require.NotContains(t, soKeys(row), "out_of_scope_node_count", body)
	})
	t.Run("node candidates are the scope subtree plus locating ancestors", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, base+"node")
		require.Equal(t, http.StatusOK, code, body)
		rows := soRows(t, out)
		sel := map[string]bool{}
		for _, r := range rows {
			require.Equal(t, []string{"id", "name", "path", "selectable"}, soKeys(r))
			sel[fmt.Sprint(r["name"])] = r["selectable"].(bool)
		}
		require.Equal(t, map[string]bool{"zz-so-p": false, "zz-so-a": true, "zz-so-b": true}, sel, body)
	})
	t.Run("node filter in scope is intersected with scope", func(t *testing.T) {
		_, out, body := e.getJSON(e.op, fmt.Sprintf("%sasset&node_id=%d", base, e.nodes["zz-so-b"]))
		require.Equal(t, []string{"zz-so-m", "zz-so-x"}, soNames(soRows(t, out), "name"), body)
	})
	t.Run("out of scope node filter equals nonexistent", func(t *testing.T) {
		for _, kind := range []string{"asset", "node", "tag"} {
			for _, n := range []string{"zz-so-c", "zz-so-d", "zz-so-p"} {
				c1, b1 := e.do2(e.op, "GET", fmt.Sprintf("%s%s&node_id=%d", base, kind, e.nodes[n]), "")
				c2, b2 := e.do2(e.op, "GET", fmt.Sprintf("%s%s&node_id=%d", base, kind, missing), "")
				require.Equal(t, http.StatusOK, c1, b1)
				require.Equal(t, c2, c1)
				require.Equal(t, b2, b1, kind+" "+n)
			}
		}
	})
	t.Run("tags come only from in-scope candidate assets", func(t *testing.T) {
		code, out, body := e.getJSON(e.op, base+"tag")
		require.Equal(t, http.StatusOK, code, body)
		rows := soRows(t, out)
		got := map[string]float64{}
		for _, r := range rows {
			require.Equal(t, []string{"count", "name"}, soKeys(r))
			got[fmt.Sprint(r["name"])] = r["count"].(float64)
		}
		require.Equal(t, map[string]float64{"web": 2, "prod": 1}, got, body)
		require.NotContains(t, body, `"db"`)
	})
	t.Run("tag filters are ANDed and searched within scope", func(t *testing.T) {
		_, out, body := e.getJSON(e.op, base+"asset&tags=web&tags=Prod")
		require.Equal(t, []string{"zz-so-x"}, soNames(soRows(t, out), "name"), body)
		_, out, body = e.getJSON(e.op, base+"asset&tags=db")
		require.Empty(t, soRows(t, out), body)
		_, out, body = e.getJSON(e.op, base+"tag&search=pr")
		require.Equal(t, []string{"prod"}, soNames(soRows(t, out), "name"), body)
	})
	t.Run("global holder gets everything", func(t *testing.T) {
		// 超級管理者與非超管的全域持有者都得全集
		holder := e.user("zz-so-global-holder")
		e.grantGlobal(holder, e.role(authz.PermAuthorizationManage))
		for _, uid := range []uint{e.super, holder} {
			_, out, body := e.getJSON(uid, base+"asset&page_size=1000")
			require.GreaterOrEqual(t, int(out["total"].(float64)), 3, body)
			require.Subset(t, soNames(soRows(t, out), "name"), []string{"zz-so-m", "zz-so-x", "zz-so-y"}, body)
			_, out, body = e.getJSON(uid, base+"tag")
			require.Contains(t, soNames(soRows(t, out), "name"), "db", body)
			_, out, body = e.getJSON(uid, base+"node")
			for _, r := range soRows(t, out) {
				require.True(t, r["selectable"].(bool))
			}
			require.Subset(t, soNames(soRows(t, out), "name"), []string{"zz-so-c", "zz-so-d"}, body)
		}
	})
	t.Run("zero node filter equals nonexistent", func(t *testing.T) {
		for _, kind := range []string{"asset", "node", "tag"} {
			c0, b0 := e.do2(e.op, "GET", fmt.Sprintf("%s%s&node_id=0", base, kind), "")
			cm, bm := e.do2(e.op, "GET", fmt.Sprintf("%s%s&node_id=%d", base, kind, missing), "")
			require.Equal(t, http.StatusOK, c0, b0)
			require.Equal(t, cm, c0, kind)
			require.Equal(t, bm, b0, kind)
		}
	})
	t.Run("only the authorization capability projects candidates", func(t *testing.T) {
		// 另一份夾具：資產檢視也標為範圍生效，使 B 上的資產檢視指派確實被物化
		f := newSOEnv(t, authz.PermAssetView)
		f.node("zz-so-bv", "")
		f.node("zz-so-cc", "")
		bv := f.asset("zz-so-bv-asset", "zz-so-bv")
		cc := f.asset("zz-so-cc-asset", "zz-so-cc")
		for id, tags := range map[uint]string{bv: "bview", cc: "cconn"} {
			require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", id).Update("tags", tags).Error)
		}
		mixed := f.user("zz-so-mixed")
		f.grantNodes(mixed, f.role(authz.PermAuthorizationManage), "zz-so-a")
		f.grantNodes(mixed, f.role(authz.PermAssetView), "zz-so-bv")
		f.seedRule(mixed, cc) // 可連線 C 下的資產
		p, err := authz.ResolveUserOnWithCatalogue(f.db, f.cat, mixed, authz.TokenFacts{})
		require.NoError(t, err)
		require.True(t, p.Has(authz.PermAssetView), "B 上的資產檢視指派須已物化")
		require.True(t, p.Has(authz.PermAuthorizationManage))

		code, out, body := f.getJSON(mixed, base+"asset&page_size=100")
		require.Equal(t, http.StatusOK, code, body)
		require.Equal(t, []string{"zz-so-m", "zz-so-x"}, soNames(soRows(t, out), "name"), body)
		code, out, body = f.getJSON(mixed, base+"node&page_size=100")
		require.Equal(t, http.StatusOK, code, body)
		require.ElementsMatch(t, []string{"zz-so-a", "zz-so-b", "zz-so-p"}, soNames(soRows(t, out), "name"), body)
		code, out, body = f.getJSON(mixed, base+"tag&page_size=100")
		require.Equal(t, http.StatusOK, code, body)
		require.ElementsMatch(t, []string{"prod", "web"}, soNames(soRows(t, out), "name"), body)
		for _, n := range []string{"zz-so-bv", "zz-so-cc"} {
			c1, b1 := f.do2(mixed, "GET", fmt.Sprintf("%sasset&node_id=%d", base, f.nodes[n]), "")
			c2, b2 := f.do2(mixed, "GET", fmt.Sprintf("%sasset&node_id=%d", base, missing), "")
			require.Equal(t, c2, c1, n)
			require.Equal(t, b2, b1, n)
		}
	})
	t.Run("no effective assignment gets a single forbidden", func(t *testing.T) {
		for _, uid := range []uint{e.nobody, e.emptyScope} {
			code, body := e.do2(uid, "GET", base+"asset", "")
			require.Equal(t, http.StatusForbidden, code, body)
			require.NotContains(t, body, "zz-so-")
		}
	})
	t.Run("invalid parameters are rejected", func(t *testing.T) {
		for _, q := range []string{"/api/v1/authorizations/target-options", base + "user", base + "asset&node_id=abc"} {
			code, _ := e.do2(e.op, "GET", q, "")
			require.Equal(t, http.StatusBadRequest, code, q)
		}
	})
}
