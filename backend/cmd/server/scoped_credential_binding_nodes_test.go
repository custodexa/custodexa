package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
)

// 憑證詳情掛載列的所屬節點：範圍化檢視者只見檢視範圍內的歸屬路徑與範圍外歸屬節點數，
// 全域主體見全部歸屬且回應不含範圍外欄位。路徑與資產列表同一投影。
func TestScopedCredentialBindingNodePaths(t *testing.T) {
	p := newSCProjection(t)
	multi := p.asset("zz-sc-asset-in-multi", "zz-sc-in/kid", "zz-sc-out")
	p.mount(p.mixID, multi)

	paths, err := asset.NodePathMap(database.DB)
	require.NoError(t, err)
	kid, top, out := paths[p.nodes["zz-sc-in/kid"]], paths[p.nodes["zz-sc-in"]], paths[p.nodes["zz-sc-out"]]
	nodeCount := func(n int) string {
		raw, _ := json.Marshal(disclosure.NodeCountValue{Value: disclosure.Count(disclosure.OutOfScopeNodeCount, n)})
		return string(raw)
	}

	type binding map[string]any
	detail := func(uid uint) (map[uint]binding, string) {
		code, raw := p.call(uid, "GET", credPath(p.mixID), "")
		require.Equal(t, http.StatusOK, code, raw)
		var body struct {
			Data struct {
				Bindings []binding `json:"bindings"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &body), raw)
		byAsset := map[uint]binding{}
		for _, b := range body.Data.Bindings {
			byAsset[uint(b["asset_id"].(float64))] = b
		}
		return byAsset, raw
	}
	pathsOf := func(b binding) []string {
		var ps []string
		for _, v := range b["node_paths"].([]any) {
			ps = append(ps, v.(string))
		}
		return ps
	}

	t.Run("範圍化主體只見範圍內路徑與範圍外計數", func(t *testing.T) {
		rows, raw := detail(p.viewer)
		require.Len(t, rows, 3, "範圍內兩台加多歸屬一台")
		require.Equal(t, []string{kid}, pathsOf(rows[multi]))
		got, _ := json.Marshal(rows[multi][disclosure.FieldOutOfScopeNodeCount])
		require.Equal(t, nodeCount(1), string(got))
		require.Equal(t, []string{kid}, pathsOf(rows[p.aIn]))
		got, _ = json.Marshal(rows[p.aIn][disclosure.FieldOutOfScopeNodeCount])
		require.Equal(t, nodeCount(0), string(got))
		for id, b := range rows {
			if id != multi && id != p.aIn {
				require.Equal(t, []string{top}, pathsOf(b))
			}
		}
		require.NotContains(t, raw, "zz-sc-out")
	})

	t.Run("全域主體見全部歸屬且無範圍外欄位", func(t *testing.T) {
		rows, raw := detail(p.super)
		require.Len(t, rows, 6)
		require.ElementsMatch(t, []string{kid, out}, pathsOf(rows[multi]))
		require.Equal(t, []string{out}, pathsOf(rows[p.aOut]))
		require.NotContains(t, raw, disclosure.FieldOutOfScopeNodeCount)
		require.NotContains(t, raw, disclosure.FieldOutOfScopeAssetCount)
	})
}
