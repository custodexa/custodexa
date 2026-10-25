package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 標籤字典與資產讀取在資產檢視範圍生效後的契約。

func TestScopedTagDictionary(t *testing.T) {
	// 讀取皆否時，只有「資產存在且在範圍外」才是範圍拒絕；不存在與已刪除走現行不存在路徑，
	// 不留範圍拒絕原因。對外兩者同形。
	t.Run("view_missing_asset_not_scope_denial", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		viewer := e.user("zz-sa-tagviewer")
		e.grantNodes(viewer, e.role(authz.PermAssetView), "zz-sa-a")
		out := e.asset("zz-sa-tag-out", "zz-sa-c")
		gone := e.asset("zz-sa-tag-gone", "zz-sa-c")
		require.NoError(t, e.db.Delete(&model.Asset{}, gone).Error)

		p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, viewer, authz.TokenFacts{})
		require.NoError(t, err)
		ctx := authz.ContextWithPrincipal(context.Background(), p)
		reader := authz.NewAssetScopeReader(e.eval, e.db)

		denied, err := reader.AssetViewScopeDenial(ctx, out)
		require.NoError(t, err)
		require.NotNil(t, denied, "存在且在範圍外：判出範圍拒絕")

		for name, id := range map[string]uint{"不存在": 999907, "已刪除": gone} {
			d, err := reader.AssetViewScopeDenial(ctx, id)
			require.NoError(t, err, name)
			assert.Nil(t, d, "%s：不是範圍拒絕", name)
		}

		cOut, rOut := e.do(viewer, true, "GET", idPath(out), "")
		cMiss, rMiss := e.do(viewer, true, "GET", "/api/v1/assets/"+saMissing, "")
		cGone, rGone := e.do(viewer, true, "GET", idPath(gone), "")
		assert.Equal(t, http.StatusNotFound, cOut, rOut)
		assert.Equal(t, cOut, cMiss)
		assert.Equal(t, cOut, cGone)
		assert.JSONEq(t, rMiss, rOut, "範圍外與不存在同形")
		assert.JSONEq(t, rMiss, rGone, "已刪除與不存在同形")
	})

	t.Run("dictionary_projection_counts_visible_only", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		viewer := e.user("zz-sa-tagviewer")
		e.grantNodes(viewer, e.role(authz.PermAssetView), "zz-sa-a")
		sdTagged(t, e, "zz-sa-in-1", "生產,web", "zz-sa-a")
		sdTagged(t, e, "zz-sa-in-2", "web", "zz-sa-a")
		sdTagged(t, e, "zz-sa-out-1", "生產,機密", "zz-sa-c")

		got := sdDictionary(t, e, viewer)
		assert.NotContains(t, got, "機密", "只在範圍外的標籤不在字典內")
		assert.Equal(t, 1, got["生產"], "範圍內外各一時使用數只計可視的 1")
		assert.Equal(t, 2, got["web"])

		code, raw := e.do(e.super, true, "GET", "/api/v1/assets/tags", "")
		require.Equal(t, http.StatusOK, code, raw)
		all := sdParse(t, raw)
		assert.Equal(t, 1, all["機密"], "admin 的字典不變：含範圍外標籤")
		assert.Equal(t, 2, all["生產"])
	})

	t.Run("four_boundary_subjects", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		sdTagged(t, e, "zz-sa-b-in", "生產", "zz-sa-a")
		sdTagged(t, e, "zz-sa-b-out", "機密", "zz-sa-c")
		viewRole := func() uint { return e.role(authz.PermAssetView) }

		// 有資產檢視生效來源：全域與節點範圍混合；節點範圍指派的節點全部刪除但另經全域指派持資產檢視
		mixed := e.user("zz-sa-mixed")
		e.grantGlobal(mixed, viewRole())
		e.grantNodes(mixed, viewRole(), "zz-sa-a")
		gone := e.user("zz-sa-gonenodes")
		e.grantNodes(gone, viewRole(), "zz-sa-far-2")
		e.grantGlobal(gone, viewRole())
		require.NoError(t, e.db.Delete(&model.AssetGroup{}, e.nodes["zz-sa-far-2"]).Error)
		for name, uid := range map[string]uint{"全域與節點範圍混合": mixed, "節點已刪但有全域檢視": gone} {
			code, raw := e.do(uid, true, "GET", "/api/v1/assets/tags", "")
			require.NotEqual(t, http.StatusForbidden, code, "%s：不被拒 %s", name, raw)
			require.Equal(t, http.StatusOK, code, "%s：%s", name, raw)
			dict := sdParse(t, raw)
			names := []string{}
			for n := range dict {
				names = append(names, n)
			}
			sort.Strings(names)
			assert.Equal(t, sdListTags(t, e, uid), names, "%s：字典標籤集合等於同一主體不帶篩選的列表資產上的標籤集合", name)
		}

		// 沒有資產檢視生效來源：只持節點範圍編輯能力；唯一的節點範圍資產檢視指派節點已全部刪除
		editOnly := e.user("zz-sa-editonly")
		e.grantNodes(editOnly, e.role(authz.PermAssetUpdate), "zz-sa-a")
		viewGone := e.user("zz-sa-viewgone")
		e.grantNodes(viewGone, viewRole(), "zz-sa-far-1")
		require.NoError(t, e.db.Delete(&model.AssetGroup{}, e.nodes["zz-sa-far-1"]).Error)
		var bodies []string
		for name, uid := range map[string]uint{"只持節點範圍編輯": editOnly, "檢視節點已刪": viewGone} {
			cDict, rDict := e.do(uid, true, "GET", "/api/v1/assets/tags", "")
			cList, rList := e.do(uid, true, "GET", "/api/v1/assets?page_size=500", "")
			assert.Equal(t, http.StatusForbidden, cDict, "%s：字典 %s", name, rDict)
			assert.Equal(t, http.StatusForbidden, cList, "%s：列表 %s", name, rList)
			assert.JSONEq(t, rList, rDict, "%s：兩個回應本文相同（單一 forbidden）", name)
			bodies = append(bodies, rDict)
		}
		assert.JSONEq(t, bodies[0], bodies[1])

		// 只經全域指派持有資產檢視能力的自訂角色主體：維持現行拒絕，與沒有來源者同形
		globalOnly := e.user("zz-sa-globalonly")
		e.grantGlobal(globalOnly, viewRole())
		cG, rG := e.do(globalOnly, true, "GET", "/api/v1/assets/tags", "")
		assert.Equal(t, http.StatusForbidden, cG, rG)
		assert.JSONEq(t, bodies[0], rG)
	})

	t.Run("list_tag_filter_scoped", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		viewer := e.user("zz-sa-filterviewer")
		e.grantNodes(viewer, e.role(authz.PermAssetView), "zz-sa-a")
		in1 := sdTagged(t, e, "zz-sa-f-in1", "生產", "zz-sa-a")
		in2 := sdTagged(t, e, "zz-sa-f-in2", "生產", "zz-sa-a")
		out := sdTagged(t, e, "zz-sa-f-out", "生產", "zz-sa-c")
		q := "tags=" + url.QueryEscape("生產")

		l := e.list(viewer, q)
		assert.Equal(t, int64(2), l.Total, "total 只計可視的符合者")
		assert.True(t, l.ids()[in1] && l.ids()[in2] && !l.ids()[out])

		l = e.list(viewer, q+"&search=zz-sa-f-in2")
		assert.Equal(t, int64(1), l.Total, "tags 與 search 疊加")
		assert.True(t, l.ids()[in2] && !l.ids()[in1])

		globalOnly := e.user("zz-sa-filterglobal")
		e.grantGlobal(globalOnly, e.role(authz.PermAssetView))
		code, raw := e.do(globalOnly, true, "GET", "/api/v1/assets?"+q, "")
		assert.Equal(t, http.StatusBadRequest, code, raw)
		assert.Equal(t, string(apierror.CodeTagFilterPrivilegedOnly), saErrorCode(t, raw))

		noSource := e.user("zz-sa-filternosource")
		e.grantNodes(noSource, e.role(authz.PermAssetUpdate), "zz-sa-a")
		cWith, rWith := e.do(noSource, true, "GET", "/api/v1/assets?"+q, "")
		cWithout, rWithout := e.do(noSource, true, "GET", "/api/v1/assets", "")
		assert.Equal(t, http.StatusForbidden, cWith, rWith)
		assert.Equal(t, cWithout, cWith)
		assert.JSONEq(t, rWithout, rWith, "帶不帶 tags 都是列表路由閘的同一個 403")

		sdTagged(t, e, "zz-sa-f-dbprod", "db_prod", "zz-sa-b")
		adm := e.list(e.super, "tags=db_prod")
		assert.Equal(t, int64(1), adm.Total, "admin 帶 tags 篩選照現行")
	})

	t.Run("write_normalization_uses_visible_dictionary", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		e.assets.SetTagReferencePort(api.NewAssetTagReference(e.authzSvc, authz.NewAssetScopeReader(e.eval, e.db)))
		mgr := e.user("zz-sa-tagmgr")
		e.grantNodes(mgr, e.role(authz.PermAssetView, authz.PermAssetUpdate), "zz-sa-a")
		out := sdTagged(t, e, "zz-sa-w-out", "DBA", "zz-sa-c")
		x1 := sdTagged(t, e, "zz-sa-w-x1", "", "zz-sa-a")
		x2 := sdTagged(t, e, "zz-sa-w-x2", "", "zz-sa-a")
		put := func(uid, id uint, tags string) (int, string) {
			return e.do(uid, true, "PUT", idPath(id), fmt.Sprintf(`{"tags":%q}`, tags))
		}
		tagsOf := func(id uint) string {
			var a model.Asset
			require.NoError(t, e.db.Where("id = ?", id).Limit(1).Find(&a).Error)
			return a.Tags
		}

		// 範圍外只有「DBA」：範圍化管理者存「dba」落庫為「dba」
		cOut, rOut := put(mgr, x1, "dba")
		require.Equal(t, http.StatusOK, cOut, rOut)
		assert.Equal(t, "dba", tagsOf(x1), "不被歸一到範圍外的寫法")
		// 清掉 x1 的「dba」：可視字典以資產 id 升冪的首見寫法為準，留著它會讓下一步的
		// 「範圍內已有 DBA」變成「範圍內先有 dba」
		require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", x1).UpdateColumn("tags", "").Error)
		// 範圍內已有「DBA」：存「Dba」落庫為「DBA」
		sdTagged(t, e, "zz-sa-w-vis", "DBA", "zz-sa-a")
		cIn, rIn := put(mgr, x2, "Dba")
		require.Equal(t, http.StatusOK, cIn, rIn)
		assert.Equal(t, "DBA", tagsOf(x2), "歸一到可視字典內的寫法")

		// 套用只在範圍外的「DBA」與全新標籤：回應除標籤字串外鍵集與值型別相同
		x3 := sdTagged(t, e, "zz-sa-w-x3", "", "zz-sa-a")
		x4 := sdTagged(t, e, "zz-sa-w-x4", "", "zz-sa-a")
		_, rApplied := put(mgr, x3, "DBA")
		_, rFresh := put(mgr, x4, "全新標籤X")
		assert.Equal(t, sdShape(t, rFresh), sdShape(t, rApplied))

		// 範圍外資產與不存在 ID 的含標籤更新：回應逐欄相同，範圍外資產標籤不變
		cOutOfScope, rOutOfScope := put(mgr, out, "zz-changed")
		cMissing, rMissing := e.do(mgr, true, "PUT", "/api/v1/assets/"+saMissing, `{"tags":"zz-changed"}`)
		assert.Equal(t, cMissing, cOutOfScope)
		assert.JSONEq(t, rMissing, rOutOfScope)
		assert.Equal(t, "DBA", tagsOf(out), "範圍外資產標籤不變")

		// 全域主體照現行：全庫已有「DBA」，存「Dba」歸一為「DBA」
		x5 := sdTagged(t, e, "zz-sa-w-x5", "", "zz-sa-b")
		cG, rG := put(e.super, x5, "Dba")
		require.Equal(t, http.StatusOK, cG, rG)
		assert.Equal(t, "DBA", tagsOf(x5))
	})

	t.Run("import_preview_matches_commit_normalization", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		e.assets.SetTagReferencePort(api.NewAssetTagReference(e.authzSvc, authz.NewAssetScopeReader(e.eval, e.db)))
		mgr := e.user("zz-sa-impmgr")
		e.grantNodes(mgr, e.role(authz.PermAssetView, authz.PermAssetCreate), "zz-sa-a")
		sdTagged(t, e, "zz-sa-i-vis", "Etl", "zz-sa-a")
		sdTagged(t, e, "zz-sa-i-out", "DBA", "zz-sa-c")
		body := fmt.Sprintf(`{"source":"form","rows":[
			{"name":"zz-sa-i-n1","protocol":"ssh","host":"10.88.0.1","port":22,"tags":"etl,dba","node_ids":[%d]},
			{"name":"zz-sa-i-n2","protocol":"ssh","host":"10.88.0.2","port":22,"tags":"ETL,DBA,Dba","node_ids":[%d]}]}`,
			e.nodes["zz-sa-a"], e.nodes["zz-sa-a"])

		cPrev, rPrev := e.do(mgr, true, "POST", "/api/v1/assets/import/preview", body)
		require.Equal(t, http.StatusOK, cPrev, rPrev)
		var prev struct {
			OK   bool `json:"ok"`
			Rows []struct {
				Resolved struct {
					Tags string `json:"tags"`
				} `json:"resolved"`
			} `json:"rows"`
		}
		require.NoError(t, json.Unmarshal([]byte(rPrev), &prev), rPrev)
		require.True(t, prev.OK, rPrev)
		require.Len(t, prev.Rows, 2)
		for _, r := range prev.Rows {
			assert.Contains(t, splitTagCSV(r.Resolved.Tags), "Etl", "歸一到可視字典內的寫法")
			assert.NotContains(t, splitTagCSV(r.Resolved.Tags), "DBA", "不被歸一到範圍外的寫法")
		}

		cCommit, rCommit := e.do(mgr, true, "POST", "/api/v1/assets/import", body)
		require.Equal(t, http.StatusCreated, cCommit, rCommit)
		var done struct {
			AssetIDs []uint `json:"asset_ids"`
		}
		require.NoError(t, json.Unmarshal([]byte(rCommit), &done), rCommit)
		require.Len(t, done.AssetIDs, 2)
		for i, id := range done.AssetIDs {
			var a model.Asset
			require.NoError(t, e.db.Where("id = ?", id).Limit(1).Find(&a).Error)
			assert.Equal(t, prev.Rows[i].Resolved.Tags, a.Tags, "預檢回報的標籤與提交後落庫相同（第 %d 列）", i)
		}
	})
}

// sdTagged 建資產並直接寫標籤欄（不經 hook）。
func sdTagged(t *testing.T, e *saEnv, name, tags string, nodes ...string) uint {
	t.Helper()
	id := e.asset(name, nodes...)
	require.NoError(t, e.db.Model(&model.Asset{}).Where("id = ?", id).UpdateColumn("tags", tags).Error)
	return id
}

// sdParse 字典回應：標籤名稱到使用數。
func sdParse(t *testing.T, raw string) map[string]int {
	t.Helper()
	var out struct {
		Data []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	m := map[string]int{}
	for _, d := range out.Data {
		m[d.Name] = d.Count
	}
	return m
}

func sdDictionary(t *testing.T, e *saEnv, uid uint) map[string]int {
	t.Helper()
	code, raw := e.do(uid, true, "GET", "/api/v1/assets/tags", "")
	require.Equal(t, http.StatusOK, code, raw)
	return sdParse(t, raw)
}

// sdListTags 同一主體不帶篩選的列表資產上的標籤集合（排序、去重）。
func sdListTags(t *testing.T, e *saEnv, uid uint) []string {
	t.Helper()
	l := e.list(uid, "")
	set := map[string]bool{}
	for _, r := range l.Data {
		raw, _ := r["tags"].(string)
		for _, tag := range splitTagCSV(raw) {
			set[tag] = true
		}
	}
	out := []string{}
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func splitTagCSV(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// sdShape 回應頂層鍵與值型別（略過標籤字串本身）。
func sdShape(t *testing.T, raw string) map[string]string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	out := map[string]string{}
	for k, v := range m {
		out[k] = fmt.Sprintf("%T", v)
	}
	return out
}
