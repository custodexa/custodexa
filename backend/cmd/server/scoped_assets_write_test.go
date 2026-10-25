package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產寫入的範圍規則（建立、歸屬合併、範圍外同形與守衛順序），經正式 handler 與真判定器。
// 樹沿用 saTree；名稱一律 zz-sa- 起頭。

// saAssetCount 資產表（未刪除）筆數。
func saAssetCount(t *testing.T, e *saEnv) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.Asset{}).Count(&n).Error)
	return n
}

// saMounted 資產目前的歸屬（節點名稱，排序）。
func saMounted(t *testing.T, e *saEnv, assetID uint) []string {
	t.Helper()
	var rows []model.AssetNode
	require.NoError(t, e.db.Where("asset_id = ?", assetID).Find(&rows).Error)
	names := map[uint]string{}
	for n, id := range e.nodes {
		names[id] = n
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, names[r.NodeID])
	}
	sort.Strings(out)
	return out
}

// saNodeIDs 以名稱組 node_ids 的 JSON 陣列；名稱 "missing" 代入不存在的節點 ID。
func saNodeIDs(e *saEnv, names ...string) string {
	ids := make([]uint, 0, len(names))
	for _, n := range names {
		if n == "missing" {
			ids = append(ids, 999917)
			continue
		}
		ids = append(ids, e.nodes[n])
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

func saPutNodes(e *saEnv, uid, assetID uint, names ...string) (int, string) {
	return e.do(uid, true, "PUT", idPath(assetID), `{"node_ids":`+saNodeIDs(e, names...)+`}`)
}

// saBodyNodes 回應本文的 node_ids（節點名稱，排序）與範圍外計數。
func saBodyNodes(t *testing.T, e *saEnv, raw string) ([]string, any) {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	names := map[uint]string{}
	for n, id := range e.nodes {
		names[id] = n
	}
	out := []string{}
	for _, id := range uintsOf(m["node_ids"]) {
		out = append(out, names[id])
	}
	sort.Strings(out)
	return out, m["out_of_scope_node_count"]
}

func saErrorCode(t *testing.T, raw string) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
	if s, ok := m["code"].(string); ok {
		return s
	}
	if inner, ok := m["error"].(map[string]any); ok {
		s, _ := inner["code"].(string)
		return s
	}
	return ""
}

func TestScopedAssetWrites(t *testing.T) {
	five := []authz.Permission{authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete, authz.PermAssetTest}

	t.Run("create_initial_attribution", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		mgr := e.user("zz-sa-mgr")
		e.grantNodes(mgr, e.role(five...), "zz-sa-a", "zz-sa-b")
		// 建立範圍比檢視範圍多一個 c：建立成功的回應不得露出 c
		e.grantNodes(mgr, e.role(authz.PermAssetCreate), "zz-sa-a", "zz-sa-c")
		body := func(name, nodes string) string {
			return fmt.Sprintf(`{"name":%q,"protocol":"ssh","host":"10.88.0.%d","port":22%s}`, name, len(name), nodes)
		}
		before := saAssetCount(t, e)
		cEmpty, rEmpty := e.do(mgr, true, "POST", "/api/v1/assets", body("zz-sa-new-empty", ""))
		cOut, rOut := e.do(mgr, true, "POST", "/api/v1/assets", body("zz-sa-new-out", `,"node_ids":`+saNodeIDs(e, "zz-sa-far-1")))
		cMiss, rMiss := e.do(mgr, true, "POST", "/api/v1/assets", body("zz-sa-new-miss", `,"node_ids":`+saNodeIDs(e, "missing")))
		assert.Equal(t, before, saAssetCount(t, e), "三次失敗皆不建立")
		assert.Equal(t, http.StatusBadRequest, cEmpty, rEmpty)
		assert.Equal(t, string(apierror.CodeAssetNodeRequired), saErrorCode(t, rEmpty))
		assert.GreaterOrEqual(t, cOut, 400, rOut)
		assert.Equal(t, cMiss, cOut, "範圍外與不存在節點同形：狀態")
		assert.JSONEq(t, rMiss, rOut, "範圍外與不存在節點同形：本文")

		code, raw := e.do(mgr, true, "POST", "/api/v1/assets", body("zz-sa-new-ok", `,"node_ids":`+saNodeIDs(e, "zz-sa-a", "zz-sa-c")))
		require.Equal(t, http.StatusCreated, code, raw)
		nodes, count := saBodyNodes(t, e, raw)
		assert.Equal(t, []string{"zz-sa-a"}, nodes, "回應只含管理可視範圍內的歸屬")
		assert.EqualValues(t, 1, count)
		assert.NotContains(t, raw, "zz-sa-c", "範圍外節點名稱不出")
		var created model.Asset
		require.NoError(t, e.db.Where("name = ?", "zz-sa-new-ok").First(&created).Error)
		assert.Equal(t, []string{"zz-sa-a", "zz-sa-c"}, saMounted(t, e, created.ID), "實際歸屬兩個都掛上")
		_, detail := e.do(mgr, true, "GET", idPath(created.ID), "")
		dNodes, dCount := saBodyNodes(t, e, detail)
		assert.Equal(t, dNodes, nodes, "建立回應與詳情同遮蔽")
		assert.Equal(t, dCount, count)

		code, raw = e.do(e.super, true, "POST", "/api/v1/assets", body("zz-sa-new-global", ""))
		require.Equal(t, http.StatusCreated, code, raw)
		var g model.Asset
		require.NoError(t, e.db.Where("name = ?", "zz-sa-new-global").First(&g).Error)
		assert.Empty(t, saMounted(t, e, g.ID), "全域主體可建立未分組資產（與現行相同）")
	})

	t.Run("update_merges_attribution", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		mgr := e.user("zz-sa-mgr")
		e.grantNodes(mgr, e.role(five...), "zz-sa-a", "zz-sa-b")
		e.grantNodes(mgr, e.role(authz.PermAssetView), "zz-sa-far-1") // D：只在檢視範圍

		ac := e.asset("zz-sa-ac", "zz-sa-a", "zz-sa-c")
		v0, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)
		code, raw := saPutNodes(e, mgr, ac, "zz-sa-b")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-b", "zz-sa-c"}, saMounted(t, e, ac), "A 換成 B，範圍外的 C 保留")
		v1, err := authz.CurrentVersion(e.db)
		require.NoError(t, err)
		assert.Greater(t, v1, v0, "歸屬變更後權限版本有推進")
		nodes, count := saBodyNodes(t, e, raw)
		assert.Equal(t, []string{"zz-sa-b"}, nodes, "更新回應不含範圍外歸屬")
		assert.EqualValues(t, 1, count)
		assert.NotContains(t, raw, "zz-sa-c")
		_, detail := e.do(mgr, true, "GET", idPath(ac), "")
		dNodes, dCount := saBodyNodes(t, e, detail)
		assert.Equal(t, dNodes, nodes, "更新回應與詳情同遮蔽")
		assert.Equal(t, dCount, count)

		cOut, rOut := saPutNodes(e, mgr, ac, "zz-sa-b", "zz-sa-c")
		// C'：範圍外且資產原本沒掛的新節點
		cNew, rNew := saPutNodes(e, mgr, ac, "zz-sa-b", "zz-sa-far-2")
		cView, rView := saPutNodes(e, mgr, ac, "zz-sa-b", "zz-sa-far-1")
		cMiss, rMiss := saPutNodes(e, mgr, ac, "zz-sa-b", "missing")
		assert.GreaterOrEqual(t, cOut, 400, rOut)
		for name, got := range map[string][2]any{"範圍外新節點": {cNew, rNew}, "只在檢視範圍": {cView, rView}, "不存在": {cMiss, rMiss}} {
			assert.Equal(t, cOut, got[0], "%s：狀態與範圍外相同", name)
			assert.JSONEq(t, rOut, got[1].(string), "%s：本文與範圍外相同", name)
		}
		assert.Equal(t, []string{"zz-sa-b", "zz-sa-c"}, saMounted(t, e, ac), "拒絕後歸屬不變")

		onlyA := e.asset("zz-sa-only-a", "zz-sa-a")
		code, raw = saPutNodes(e, mgr, onlyA)
		assert.Equal(t, http.StatusBadRequest, code, raw)
		assert.Equal(t, string(apierror.CodeAssetNodeRequired), saErrorCode(t, raw))
		assert.Equal(t, []string{"zz-sa-a"}, saMounted(t, e, onlyA))
		code, raw = saPutNodes(e, e.super, onlyA)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Empty(t, saMounted(t, e, onlyA), "不帶標記的全域主體整組取代：送空即未分組")

		code, raw = e.do(mgr, true, "PUT", idPath(ac), `{"name":"zz-sa-ac-renamed"}`)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-b", "zz-sa-c"}, saMounted(t, e, ac), "不帶 node_ids 的改名不動歸屬")

		code, raw = saPutNodes(e, e.super, ac, "zz-sa-b")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-b"}, saMounted(t, e, ac), "全域主體送 [B] 後只剩 B")
	})

	t.Run("write_response_follows_detail_visibility", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		globalPerms := []authz.Permission{authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetCreate}
		// 混合主體：全域的檢視、編輯與建立，另有節點 a 的檢視指派（帶範圍化標記）
		mixed := e.user("zz-sa-mixed")
		e.grantGlobal(mixed, e.role(globalPerms...))
		e.grantNodes(mixed, e.role(authz.PermAssetView), "zz-sa-a")
		// 對照：同樣的全域指派，沒有任何節點範圍指派
		global := e.user("zz-sa-global")
		e.grantGlobal(global, e.role(globalPerms...))
		cID := e.nodes["zz-sa-c"]
		createBody := func(name, host string) string {
			return fmt.Sprintf(`{"name":%q,"protocol":"ssh","host":%q,"port":22,"node_ids":%s}`, name, host, saNodeIDs(e, "zz-sa-c"))
		}
		decode := func(t *testing.T, raw string) map[string]any {
			t.Helper()
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &m), raw)
			return m
		}
		hidden := func(t *testing.T, raw string) {
			t.Helper()
			m := decode(t, raw)
			_, hasIDs := m["node_ids"]
			_, hasPaths := m["node_paths"]
			assert.False(t, hasIDs, "不帶範圍外節點的識別碼：%s", raw)
			assert.False(t, hasPaths, "不帶範圍外節點的路徑：%s", raw)
			assert.EqualValues(t, 1, m["out_of_scope_node_count"], "範圍外歸屬只出計數：%s", raw)
			assert.NotContains(t, raw, "zz-sa-c", "範圍外節點名稱不出")
		}
		full := func(t *testing.T, raw string) map[string]any {
			t.Helper()
			m := decode(t, raw)
			assert.Equal(t, []uint{cID}, uintsOf(m["node_ids"]), "完整歸屬：%s", raw)
			for _, k := range []string{"actions", "out_of_scope_node_count"} {
				_, has := m[k]
				assert.False(t, has, "不帶標記的主體回應鍵集不變：%s", k)
			}
			return m
		}

		far := e.asset("zz-sa-far", "zz-sa-c")
		code, raw := e.do(mixed, true, "GET", idPath(far), "")
		require.Equal(t, http.StatusNotFound, code, "前提：詳情對混合主體不可視：%s", raw)
		code, raw = e.do(mixed, true, "PUT", idPath(far), `{"name":"zz-sa-far-renamed"}`)
		require.Equal(t, http.StatusOK, code, raw)
		hidden(t, raw)
		assert.Equal(t, []string{"zz-sa-c"}, saMounted(t, e, far), "改名不動歸屬")

		code, raw = e.do(mixed, true, "POST", "/api/v1/assets", createBody("zz-sa-new-far", "10.89.0.1"))
		require.Equal(t, http.StatusCreated, code, raw)
		hidden(t, raw)
		var created model.Asset
		require.NoError(t, e.db.Where("name = ?", "zz-sa-new-far").First(&created).Error)
		assert.Equal(t, []string{"zz-sa-c"}, saMounted(t, e, created.ID), "實際歸屬照請求掛上")
		code, raw = e.do(mixed, true, "GET", idPath(created.ID), "")
		assert.Equal(t, http.StatusNotFound, code, "建立後詳情同樣不可視：%s", raw)

		// 只經連線可視：詳情照現行帶完整歸屬，更新回應與詳情相同
		e.connGrant(mixed, far)
		code, detail := e.do(mixed, true, "GET", idPath(far), "")
		require.Equal(t, http.StatusOK, code, detail)
		code, raw = e.do(mixed, true, "PUT", idPath(far), `{"name":"zz-sa-far-again"}`)
		require.Equal(t, http.StatusOK, code, raw)
		dNodes, dCount := saBodyNodes(t, e, detail)
		nodes, count := saBodyNodes(t, e, raw)
		assert.Equal(t, []string{"zz-sa-c"}, nodes, "只經連線可視：歸屬照現行")
		assert.Equal(t, dNodes, nodes, "更新回應與詳情同形")
		assert.Equal(t, dCount, count)

		// 反向：沒有節點範圍指派的全域編輯者，建立與更新回應照現行帶完整歸屬
		code, raw = e.do(global, true, "PUT", idPath(far), `{"name":"zz-sa-far-global"}`)
		require.Equal(t, http.StatusOK, code, raw)
		m := full(t, raw)
		assert.Equal(t, []any{"zz-sa-c"}, m["node_paths"], "更新回應帶節點路徑")
		code, raw = e.do(global, true, "POST", "/api/v1/assets", createBody("zz-sa-new-global-far", "10.89.0.2"))
		require.Equal(t, http.StatusCreated, code, raw)
		full(t, raw)
	})

	t.Run("view_and_update_scopes_differ", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		split := e.user("zz-sa-split")
		e.grantNodes(split, e.role(authz.PermAssetView), "zz-sa-a")
		e.grantNodes(split, e.role(authz.PermAssetUpdate), "zz-sa-a", "zz-sa-b", "zz-sa-c")
		mixed := e.user("zz-sa-mixed")
		e.grantGlobal(mixed, e.role(authz.PermAssetUpdate))
		e.grantNodes(mixed, e.role(authz.PermAssetView), "zz-sa-a")
		ab := e.asset("zz-sa-ab", "zz-sa-a", "zz-sa-b")

		_, detail := e.do(split, true, "GET", idPath(ab), "")
		nodes, _ := saBodyNodes(t, e, detail)
		assert.Equal(t, []string{"zz-sa-a"}, nodes, "詳情只見 A")
		code, raw := saPutNodes(e, split, ab, "zz-sa-a")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-a", "zz-sa-b"}, saMounted(t, e, ab), "看不到的 B 保留")
		code, raw = saPutNodes(e, split, ab, "zz-sa-a", "zz-sa-c")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-a", "zz-sa-b", "zz-sa-c"}, saMounted(t, e, ab), "可加入原未掛載的範圍內候選")

		ab2 := e.asset("zz-sa-ab2", "zz-sa-a", "zz-sa-b")
		code, raw = saPutNodes(e, mixed, ab2, "zz-sa-a")
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, []string{"zz-sa-a", "zz-sa-b"}, saMounted(t, e, ab2), "全域編輯＋節點檢視：看不到的 B 仍保留")
	})

	t.Run("out_of_scope_same_shape_and_gate_order", func(t *testing.T) {
		e := newSAEnv(t)
		saTree(e)
		mgr := e.user("zz-sa-mgr")
		e.grantNodes(mgr, e.role(five...), "zz-sa-a")
		policyOnly := e.user("zz-sa-policy")
		e.grantGlobal(policyOnly, e.role(authz.PermAccessPolicyManage))
		in := e.asset("zz-sa-in", "zz-sa-a")
		out := e.asset("zz-sa-out", "zz-sa-c")
		missing := "/api/v1/assets/" + saMissing

		e.testCalls = 0
		for _, rq := range []struct{ method, suffix, body string }{
			{"PUT", "", `{"name":"zz-sa-renamed"}`},
			{"DELETE", "", ""},
			{"POST", "/test-connection", `{}`},
		} {
			cOut, rOut := e.do(mgr, true, rq.method, idPath(out)+rq.suffix, rq.body)
			cMiss, rMiss := e.do(mgr, true, rq.method, missing+rq.suffix, rq.body)
			assert.Equal(t, http.StatusNotFound, cOut, "%s%s：範圍外 404：%s", rq.method, rq.suffix, rOut)
			assert.Equal(t, cMiss, cOut, "%s%s：狀態", rq.method, rq.suffix)
			assert.JSONEq(t, rMiss, rOut, "%s%s：本文", rq.method, rq.suffix)
		}
		assert.Zero(t, e.testCalls, "範圍外測試連線不得到達服務")
		var o model.Asset
		require.NoError(t, e.db.First(&o, out).Error)
		assert.Equal(t, "zz-sa-out", o.Name, "範圍外資產未被改名或刪除")

		// 欄位閘先於目標解析：不持存取政策能力者夾帶 access_policy，三種 ID 同一個 403
		body := `{"name":"zz-sa-gate","access_policy":"` + model.AccessPolicyOpen + `"}`
		cIn, rIn := e.do(mgr, true, "PUT", idPath(in), body)
		cO, rO := e.do(mgr, true, "PUT", idPath(out), body)
		cM, rM := e.do(mgr, true, "PUT", missing, body)
		assert.Equal(t, http.StatusForbidden, cIn, rIn)
		assert.Equal(t, []int{cIn, cIn}, []int{cO, cM})
		assert.JSONEq(t, rIn, rO)
		assert.JSONEq(t, rIn, rM)
		for _, id := range []uint{in, out} {
			var a model.Asset
			require.NoError(t, e.db.First(&a, id).Error)
			assert.NotEqual(t, "zz-sa-gate", a.Name, "兩欄不變")
			assert.Nil(t, a.AccessPolicy, "兩欄不變")
		}

		// 只含存取政策：不要求資產編輯能力（單台政策範圍不在本段）
		code, raw := e.do(policyOnly, true, "PUT", idPath(out), `{"access_policy":"`+model.AccessPolicyOpen+`"}`)
		require.Equal(t, http.StatusOK, code, raw)
		var a model.Asset
		require.NoError(t, e.db.First(&a, out).Error)
		require.NotNil(t, a.AccessPolicy)
		assert.Equal(t, model.AccessPolicyOpen, *a.AccessPolicy)
	})
}
