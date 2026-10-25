package asset_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 掛載變更審計列附拓撲涵蓋差集：初始掛載與歸屬實際改變時同交易取前後快照；
// 審計、涵蓋查詢失敗或未注入產生器時整筆回滾。
//
//	go test ./internal/modules/asset/ -run '^TestScopedAssetTopologyAudit$' -count=1 -v

// swMountAudits 資產的掛載審計列（details 含 node_ids 變更）。
func (e *swEnv) mountAudits(assetID uint) []model.AuditLog {
	e.t.Helper()
	var rows []model.AuditLog
	require.NoError(e.t, e.db.Where("resource = ? AND resource_id = ? AND details LIKE ?",
		model.ResourceAsset, assetID, `%"field":"node_ids"%`).Order("id").Find(&rows).Error)
	return rows
}

// coverageOf 解析審計列的 topology_coverage；缺鍵時測試失敗。
func coverageOf(t *testing.T, row model.AuditLog) asset.TopologyCoverage {
	t.Helper()
	var d struct {
		TopologyCoverage *asset.TopologyCoverage `json:"topology_coverage"`
	}
	require.NoError(t, json.Unmarshal([]byte(row.Details), &d), row.Details)
	require.NotNil(t, d.TopologyCoverage, "掛載審計列須含 topology_coverage：%s", row.Details)
	return *d.TopologyCoverage
}

// nodeChangeOf 解析審計列 details 的 node_ids 變更（舊、新節點集合）。
func nodeChangeOf(t *testing.T, row model.AuditLog) (old, new []uint) {
	t.Helper()
	var d struct {
		Changes []struct {
			Field string `json:"field"`
			Old   []uint `json:"old"`
			New   []uint `json:"new"`
		} `json:"changes"`
	}
	require.NoError(t, json.Unmarshal([]byte(row.Details), &d), row.Details)
	for _, c := range d.Changes {
		if c.Field == "node_ids" {
			return c.Old, c.New
		}
	}
	t.Fatalf("審計列缺 node_ids 變更：%s", row.Details)
	return nil, nil
}

func (e *swEnv) groupGrantOn(node string) uint {
	e.t.Helper()
	g := model.UserGroup{Name: "sw-group-" + node}
	require.NoError(e.t, e.db.Create(&g).Error)
	gid, nid := g.ID, e.nodes[node]
	require.NoError(e.t, e.db.Create(&model.AssetAuthorization{UserGroupID: &gid, AssetGroupID: &nid,
		Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
	return g.ID
}

func TestScopedAssetTopologyAudit(t *testing.T) {
	t.Run("mount_and_unmount_record_group_coverage", func(t *testing.T) {
		e := newSwEnv(t)
		g := e.groupGrantOn("sw-b")
		want := asset.CoverageGrant{Kind: model.BindingSubjectUserGroup, ID: g, Level: string(model.PermissionConnect)}
		id := e.asset("sw-cov", "sw-a")

		require.NoError(t, e.setNodes(e.super, id, "sw-a", "sw-b")())
		rows := e.mountAudits(id)
		require.Len(t, rows, 1, "每筆變更只有一列掛載審計")
		assert.Equal(t, model.ActionUpdate, rows[0].Action)
		assert.Contains(t, rows[0].Details, `"field":"node_ids"`)
		oldIDs, newIDs := nodeChangeOf(t, rows[0])
		assert.Contains(t, newIDs, e.nodes["sw-b"], "審計列含被加掛的節點本身")
		assert.NotContains(t, oldIDs, e.nodes["sw-b"])
		c := coverageOf(t, rows[0])
		assert.Contains(t, c.Grants.Gained.Items, want, "加掛到帶群組授權的節點：該群組列為得到")
		assert.Equal(t, []uint{id}, c.Assets.Gained.Items)

		require.NoError(t, e.setNodes(e.super, id, "sw-a")())
		rows = e.mountAudits(id)
		require.Len(t, rows, 2)
		assert.Equal(t, model.ActionUpdate, rows[1].Action)
		c = coverageOf(t, rows[1])
		assert.Contains(t, c.Grants.Lost.Items, want, "移出：該群組列為失去")

		require.NoError(t, e.setNodes(e.super, id, "sw-a")(), "集合不變的更新")
		assert.Len(t, e.mountAudits(id), 2, "集合不變不寫掛載審計")
	})

	t.Run("scoped_manager_change_also_recorded", func(t *testing.T) {
		e := newSwEnv(t)
		g := e.groupGrantOn("sw-c")
		id := e.asset("sw-cov-mgr", "sw-a", "sw-c")
		require.NoError(t, e.setNodes(e.manager, id)(), "範圍化主體移出自己範圍內的節點")
		rows := e.mountAudits(id)
		require.Len(t, rows, 1)
		c := coverageOf(t, rows[0])
		assert.NotContains(t, c.Grants.Lost.Items,
			asset.CoverageGrant{Kind: model.BindingSubjectUserGroup, ID: g, Level: string(model.PermissionConnect)},
			"仍掛在 sw-c：群組涵蓋未失去")
	})

	t.Run("create_initial_mount_has_coverage", func(t *testing.T) {
		e := newSwEnv(t)
		g := e.groupGrantOn("sw-b")
		a, err := e.svc.Create(e.ctx(e.super), &asset.CreateAssetRequest{Name: "sw-cov-new", Protocol: model.ProtocolSSH,
			Host: "10.68.0.1", Port: 22, CreatedBy: e.super, NodeIDs: e.ids("sw-b")})
		require.NoError(t, err)
		rows := e.mountAudits(a.ID)
		require.Len(t, rows, 1, "初始掛載一列")
		c := coverageOf(t, rows[0])
		assert.Contains(t, c.Grants.Gained.Items,
			asset.CoverageGrant{Kind: model.BindingSubjectUserGroup, ID: g, Level: string(model.PermissionConnect)})
	})

	t.Run("failures_roll_back", func(t *testing.T) {
		for _, mode := range []string{"audit_write_fails", "coverage_query_fails", "coverage_port_missing"} {
			t.Run(mode, func(t *testing.T) {
				e := newSwEnv(t)
				id := e.asset("sw-cov-rollback", "sw-a")
				switch mode {
				case "audit_write_fails":
					e.auditFail.Store(true)
				case "coverage_query_fails":
					e.covFail.Store(true)
				case "coverage_port_missing":
					e.svc.SetCoverageSnapshotPort(nil)
				}
				name := "sw-cov-renamed"
				ids := e.ids("sw-a", "sw-b")
				_, err := e.svc.Update(e.ctx(e.super), id, &asset.UpdateAssetRequest{Name: &name, NodeIDs: &ids})
				require.Error(t, err)
				if mode == "coverage_port_missing" {
					require.ErrorIs(t, err, asset.ErrCoverageSnapshotPortMissing)
				}
				var a model.Asset
				require.NoError(t, e.db.First(&a, id).Error)
				assert.Equal(t, "sw-cov-rollback", a.Name, "名稱維持變更前")
				assert.Equal(t, []string{"sw-a"}, e.mounted(id), "歸屬維持變更前")
				assert.Empty(t, e.mountAudits(id))
			})
		}
	})
}
