package authz

import (
	"fmt"
	"sort"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

var _ ScopeTopology = (*asset.ScopeTopologyReader)(nil)

// 夾具編號（節點）：
//
//	1 根 ── 2 ── 3                    三層樹，皆未刪
//	4 根 ── 5(已刪) ── 6              未刪根 → 已刪中間 → 未刪葉
//	7(已刪)                            已刪節點，上面掛資產
//
// 資產：1 掛 3；2 掛 2 與 6（多歸屬）；3 掛 6；4 掛已刪節點 7；5 未分組；
// 6 已刪除（掛 3）；7 掛 1 與 3。帳號：1、2 分屬資產 1、2；3 已刪除（屬資產 1）。
func seedScopeTopology(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAccount{}, &model.AuditLog{}))
	up := func(v uint) *uint { return &v }
	groups := []model.AssetGroup{
		{ID: 1, Name: "n1"}, {ID: 2, Name: "n2", ParentID: up(1)}, {ID: 3, Name: "n3", ParentID: up(2)},
		{ID: 4, Name: "n4"}, {ID: 5, Name: "n5", ParentID: up(4)}, {ID: 6, Name: "n6", ParentID: up(5)},
		{ID: 7, Name: "n7"},
	}
	for i := range groups {
		require.NoError(t, db.Create(&groups[i]).Error)
	}
	require.NoError(t, db.Delete(&model.AssetGroup{}, 5).Error)
	require.NoError(t, db.Delete(&model.AssetGroup{}, 7).Error)
	for i := 1; i <= 7; i++ {
		require.NoError(t, db.Create(&model.Asset{ID: uint(i), Name: fmt.Sprintf("a%d", i), Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1}).Error)
	}
	require.NoError(t, db.Delete(&model.Asset{}, 6).Error)
	for _, m := range [][2]uint{{1, 3}, {2, 2}, {2, 6}, {3, 6}, {4, 7}, {6, 3}, {7, 1}, {7, 3}} {
		require.NoError(t, db.Create(&model.AssetNode{AssetID: m[0], NodeID: m[1]}).Error)
	}
	for _, a := range [][2]uint{{1, 1}, {2, 2}, {3, 1}} {
		require.NoError(t, db.Create(&model.AssetAccount{ID: a[0], AssetID: a[1], CredentialID: a[0]}).Error)
	}
	require.NoError(t, db.Delete(&model.AssetAccount{}, 3).Error)
	return db
}

func idSet(ids []uint) map[uint]bool {
	m := map[uint]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func sortedIDs(ids []uint) []uint {
	out := append([]uint{}, ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TestScopeTargetResolvers 目標解析：拓撲唯讀介面與三種內建解析器。
func TestScopeTargetResolvers(t *testing.T) {
	db := seedScopeTopology(t)
	topo := asset.NewScopeTopologyReader()
	resolvers := builtinScopeResolvers()

	liveNodes := []uint{1, 2, 3, 4, 6}

	t.Run("covers_existing_authorization_ancestor_query", func(t *testing.T) {
		for assetID := uint(1); assetID <= 7; assetID++ {
			cover, exists, err := topo.AssetCoverNodes(db, assetID)
			require.NoError(t, err)
			if assetID == 6 {
				assert.False(t, exists, "已刪資產不 exists")
				continue
			}
			require.True(t, exists)
			var old []uint
			require.NoError(t, db.Raw("SELECT id FROM "+assetAncestorNodesSubquery, assetID).Scan(&old).Error)
			oldSet, newSet := idSet(old), idSet(cover)
			for _, n := range liveNodes {
				assert.Equalf(t, oldSet[n], newSet[n], "資產 %d 對節點 %d：既有祖先查詢與本介面涵蓋結論須一致", assetID, n)
			}
			for _, n := range cover {
				assert.Contains(t, liveNodes, n, "已刪節點不作範圍節點")
			}
		}
	})

	t.Run("deleted_shapes_and_ungrouped", func(t *testing.T) {
		// 未刪根 → 已刪中間 → 未刪葉：葉不穿過已刪中間節點到根
		c, ok, err := topo.AssetCoverNodes(db, 3)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, []uint{6}, c)
		// 掛在已刪節點上的資產：存在但沒有任何涵蓋節點
		c, ok, err = topo.AssetCoverNodes(db, 4)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Empty(t, c)
		// 未分組
		c, ok, err = topo.AssetCoverNodes(db, 5)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Empty(t, c)
	})

	t.Run("multi_attachment", func(t *testing.T) {
		c, ok, err := topo.AssetCoverNodes(db, 2)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, []uint{1, 2, 6}, sortedIDs(c), "兩個掛載節點各自加祖先，已刪中間不穿過")
		c, _, err = topo.AssetCoverNodes(db, 7)
		require.NoError(t, err)
		assert.Equal(t, []uint{1, 2, 3}, sortedIDs(c), "掛載節點與其祖先重疊時去重")
	})

	t.Run("asset_resolver", func(t *testing.T) {
		r, err := resolvers[ScopeTargetAsset](db, topo, AssetTarget(3))
		require.NoError(t, err)
		assert.True(t, r.Exists)
		assert.Equal(t, ScopeLayerAsset, r.Layer)
		assert.Equal(t, []uint{6}, r.CoverNodes)
		for _, id := range []uint{6, 999} { // 已刪除、不存在
			r, err = resolvers[ScopeTargetAsset](db, topo, AssetTarget(id))
			require.NoError(t, err)
			assert.Equal(t, ResolvedScopeTarget{Layer: ScopeLayerAsset}, r)
		}
	})

	t.Run("account_resolver", func(t *testing.T) {
		r, err := resolvers[ScopeTargetAssetAccount](db, topo, AssetAccountTarget(2, 2))
		require.NoError(t, err)
		assert.True(t, r.Exists)
		assert.Equal(t, ScopeLayerAsset, r.Layer, "存在時涵蓋節點是資產的，範圍外即資產層")
		assert.Equal(t, []uint{1, 2, 6}, sortedIDs(r.CoverNodes), "帳號隨所屬資產")

		// 資產 1 搭配資產 2 的帳號：帳號不屬於所指資產，帳號層
		r, err = resolvers[ScopeTargetAssetAccount](db, topo, AssetAccountTarget(1, 2))
		require.NoError(t, err)
		assert.Equal(t, ResolvedScopeTarget{Layer: ScopeLayerAccount, CoverNodes: []uint{1, 2, 3}}, withSortedCover(r), "帶回資產 1 的涵蓋節點，供判定器先判資產範圍")
		// 已刪帳號、不存在帳號：帳號層
		for _, acc := range []uint{3, 999} {
			r, err = resolvers[ScopeTargetAssetAccount](db, topo, AssetAccountTarget(1, acc))
			require.NoError(t, err)
			assert.Equal(t, ScopeLayerAccount, r.Layer, "帳號 %d", acc)
			assert.False(t, r.Exists)
			assert.NotEmpty(t, r.CoverNodes, "帳號 %d 仍帶回資產涵蓋節點", acc)
		}
		// 資產已刪或不存在：資產層（先於帳號）
		for _, a := range []uint{6, 999} {
			r, err = resolvers[ScopeTargetAssetAccount](db, topo, AssetAccountTarget(a, 1))
			require.NoError(t, err)
			assert.Equal(t, ResolvedScopeTarget{Layer: ScopeLayerAsset}, r, "資產 %d", a)
		}
	})

	t.Run("node_resolver", func(t *testing.T) {
		r, err := resolvers[ScopeTargetNode](db, topo, NodeTarget(3))
		require.NoError(t, err)
		assert.True(t, r.Exists)
		assert.Equal(t, ScopeLayerNode, r.Layer)
		assert.Equal(t, []uint{1, 2, 3}, sortedIDs(r.CoverNodes), "範圍根節點自身也在內")
		r, err = resolvers[ScopeTargetNode](db, topo, NodeTarget(6))
		require.NoError(t, err)
		assert.Equal(t, []uint{6}, r.CoverNodes, "不穿過已刪中間節點")
		for _, id := range []uint{5, 7, 999} { // 已刪除、不存在
			r, err = resolvers[ScopeTargetNode](db, topo, NodeTarget(id))
			require.NoError(t, err)
			assert.Equal(t, ResolvedScopeTarget{Layer: ScopeLayerNode}, r, "節點 %d", id)
		}
	})

	t.Run("subtree_queries", func(t *testing.T) {
		nodes := func(roots ...uint) []uint {
			var ids []uint
			require.NoError(t, db.Raw("?", topo.SubtreeNodeIDs(db, roots)).Scan(&ids).Error)
			return sortedIDs(ids)
		}
		assets := func(roots ...uint) []uint {
			var ids []uint
			require.NoError(t, db.Raw("?", topo.SubtreeAssetIDs(db, roots)).Scan(&ids).Error)
			return sortedIDs(ids)
		}
		assert.Equal(t, []uint{1, 2, 3}, nodes(1))
		assert.Equal(t, []uint{4}, nodes(4), "已刪中間節點不穿過")
		assert.Empty(t, nodes(5), "已刪根不起算")
		assert.Empty(t, nodes())
		assert.Equal(t, []uint{1, 2, 3, 6}, nodes(1, 6))
		assert.Equal(t, []uint{1, 2, 7}, assets(1), "去重；已刪資產 6 除外")
		assert.Equal(t, []uint{2, 3}, assets(6))
		assert.Empty(t, assets(4))
		assert.Empty(t, assets(7))
		assert.Empty(t, assets())
	})

	t.Run("kinds_and_registration", func(t *testing.T) {
		assert.Len(t, resolvers, 3)
		_, ok := resolvers[ScopeTargetKind("credential")]
		assert.False(t, ok, "未登記種類沒有內建解析器")
		ev := NewScopeEvaluator(ProductCatalogue(), topo)
		for _, k := range []ScopeTargetKind{ScopeTargetAsset, ScopeTargetAssetAccount, ScopeTargetNode} {
			assert.NotNil(t, ev.resolvers[k], string(k))
		}
		assert.Nil(t, ev.resolvers[ScopeTargetKind("credential")])
		extra := NewScopeEvaluator(ProductCatalogue(), topo, ScopeTargetResolverRegistration{
			Kind: "credential", Resolve: resolveAssetScopeTarget})
		assert.NotNil(t, extra.resolvers["credential"])

		// 種類與解析器不符、拓撲缺席都回錯誤，不是不存在
		_, err := resolvers[ScopeTargetAsset](db, topo, NodeTarget(1))
		assert.Error(t, err)
		_, err = resolvers[ScopeTargetAsset](db, nil, AssetTarget(1))
		assert.Error(t, err)
	})
	runDecideResultSubtests(t)
	runDecideDenialSubtests(t)
}

func withSortedCover(r ResolvedScopeTarget) ResolvedScopeTarget {
	r.CoverNodes = sortedIDs(r.CoverNodes)
	return r
}
