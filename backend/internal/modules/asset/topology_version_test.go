package asset

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// recordingTopologyPort 記錄呼叫順序、在 authz_state 測試表上推進版本，並記錄取鎖呼叫之前
// 同一個交易（以連線句柄辨識）是否已發過任何語句，用來驗「取鎖是交易第一個動作」。
type recordingTopologyPort struct {
	db          *gorm.DB
	calls       []string
	stmtsByTx   map[any]int
	lockFirst   []bool
	failAdvance error
	// failAfterAdvance 版本與事件都已在交易內寫入之後才回錯，用來驗證回滾連同版本與事件一起還原。
	failAfterAdvance error
}

func newRecordingTopologyPort(db *gorm.DB) *recordingTopologyPort {
	p := &recordingTopologyPort{db: db, stmtsByTx: map[any]int{}}
	count := func(tx *gorm.DB) { p.stmtsByTx[tx.Statement.ConnPool]++ }
	name := "topology_test_counter"
	_ = db.Callback().Query().Before("gorm:query").Register(name+"_q", count)
	_ = db.Callback().Create().Before("gorm:create").Register(name+"_c", count)
	_ = db.Callback().Update().Before("gorm:update").Register(name+"_u", count)
	_ = db.Callback().Delete().Before("gorm:delete").Register(name+"_d", count)
	_ = db.Callback().Raw().Before("gorm:raw").Register(name+"_r", count)
	_ = db.Callback().Row().Before("gorm:row").Register(name+"_w", count)
	return p
}

func (p *recordingTopologyPort) LockTopology(tx *gorm.DB) error {
	p.calls = append(p.calls, "lock")
	p.lockFirst = append(p.lockFirst, p.stmtsByTx[tx.Statement.ConnPool] == 0)
	return nil
}

func (p *recordingTopologyPort) BeginPermissionChange(tx *gorm.DB) error {
	p.calls = append(p.calls, "begin")
	// 與 authz.BeginPermissionChange 同一個 audit 入口；附證未啟用時為 no-op
	_, err := audit.RecordUntracedPermissionDrift(context.Background(), tx)
	return err
}

func (p *recordingTopologyPort) AdvanceVersion(tx *gorm.DB) error {
	p.calls = append(p.calls, "advance")
	if p.failAdvance != nil {
		return p.failAdvance
	}
	if err := tx.Exec("UPDATE authz_state SET version = version + 1 WHERE id = 1").Error; err != nil {
		return err
	}
	// 與 authz.AdvanceVersion 同一個 audit 入口；附證未啟用時為 no-op
	if err := audit.RecordPermissionStateEvent(context.Background(), tx, model.PermEventChange, ""); err != nil {
		return err
	}
	return p.failAfterAdvance
}

func (p *recordingTopologyPort) SettlePermissionChange(*gorm.DB) error {
	p.calls = append(p.calls, "settle")
	return nil
}

func (p *recordingTopologyPort) reset() { p.calls, p.lockFirst = nil, nil }

// TestTopologyAdvancesAuthzVersion 拓撲寫入（單筆建立、批次匯入、掛載更新）在同一交易內
// 取鎖並至多推進一次權限版本；掛載不變、只改名稱、零掛載建立不推進；後段失敗整筆回滾。
func TestTopologyAdvancesAuthzVersion(t *testing.T) {
	db := setupAccountDB(t)
	require.NoError(t, db.Exec("CREATE TABLE authz_state (id integer primary key, version integer not null)").Error)
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	assets, _ := newAccountServices(t)
	port := newRecordingTopologyPort(db)
	assets.SetTopologyPermissionPort(port)
	assets.SetAuthorizationRevoker(noopRevoker{})
	require.NoError(t, db.AutoMigrate(&model.AssetAuthorization{}, &model.ApproverScope{},
		&model.RoleBindingNode{}, &model.PermissionStateEvent{}))
	groups := NewAssetGroupService(db, audit.NewTxSink(), &cascadingGroupRevoker{})
	groups.SetTopologyPermissionPort(port)
	wireNodeTestPorts(groups)

	nodeA := &model.AssetGroup{Name: "node-a"}
	nodeB := &model.AssetGroup{Name: "node-b"}
	require.NoError(t, db.Create(nodeA).Error)
	require.NoError(t, db.Create(nodeB).Error)

	version := func() int64 {
		var v int64
		require.NoError(t, db.Raw("SELECT version FROM authz_state WHERE id = 1").Scan(&v).Error)
		return v
	}
	mounts := func(assetID uint) []uint {
		ids, err := assetNodeIDs(db, assetID)
		require.NoError(t, err)
		return ids
	}
	newAsset := func(name string, nodes []uint) *model.Asset {
		t.Helper()
		a, err := assets.Create(WithSystemCaller(adminCtx()), &CreateAssetRequest{
			Name: name, Protocol: model.ProtocolVNC, Host: "10.9.0.1", Port: 5900, CreatedBy: 1, NodeIDs: nodes})
		require.NoError(t, err)
		return a
	}
	update := func(id uint, req *UpdateAssetRequest) error {
		_, err := assets.Update(WithSystemCaller(adminCtx()), id, req)
		return err
	}
	ids := func(v ...uint) *[]uint { return &v }

	t.Run("create_with_mount_advances_once", func(t *testing.T) {
		port.reset()
		before := version()
		newAsset("create-mounted", []uint{nodeA.ID})
		require.Equal(t, before+1, version())
		require.Equal(t, []string{"lock", "begin", "advance"}, port.calls)
		require.Equal(t, []bool{true}, port.lockFirst, "取鎖必須是交易第一個動作")
	})

	t.Run("create_without_mount_does_not_advance", func(t *testing.T) {
		port.reset()
		before := version()
		newAsset("create-unmounted", nil)
		require.Equal(t, before, version())
		require.Equal(t, []string{"lock"}, port.calls)
		require.Equal(t, []bool{true}, port.lockFirst)
	})

	t.Run("import_three_rows_advances_once", func(t *testing.T) {
		port.reset()
		before := version()
		res, err := assets.ImportAssets(WithSystemCaller(adminCtx()), &ImportBatch{Source: ImportSourceForm, Rows: []ImportRow{
			{Name: "imp-1", Protocol: "ssh", Host: "10.9.1.1", NodeIDs: []uint{nodeA.ID}},
			{Name: "imp-2", Protocol: "ssh", Host: "10.9.1.2", NodeIDs: []uint{nodeA.ID, nodeB.ID}},
			{Name: "imp-3", Protocol: "ssh", Host: "10.9.1.3", NodeIDs: []uint{nodeB.ID}},
		}}, 1, "admin")
		require.NoError(t, err)
		require.Equal(t, 3, res.Created)
		require.Equal(t, before+1, version(), "三筆匯入只推進一次")
		require.Equal(t, []string{"lock", "begin", "advance"}, port.calls)
		require.Equal(t, []bool{true}, port.lockFirst)
	})

	t.Run("replace_mounts_advances", func(t *testing.T) {
		a := newAsset("replace-me", []uint{nodeA.ID})
		port.reset()
		before := version()
		require.NoError(t, update(a.ID, &UpdateAssetRequest{NodeIDs: ids(nodeB.ID)}))
		require.Equal(t, before+1, version())
		require.Equal(t, []uint{nodeB.ID}, mounts(a.ID))
		require.Equal(t, []string{"lock", "begin", "advance"}, port.calls)
		require.Equal(t, []bool{true}, port.lockFirst, "取鎖早於資產列鎖與其他語句")
	})

	t.Run("same_mounts_does_not_advance", func(t *testing.T) {
		a := newAsset("same-mounts", []uint{nodeA.ID, nodeB.ID})
		port.reset()
		before := version()
		require.NoError(t, update(a.ID, &UpdateAssetRequest{NodeIDs: ids(nodeB.ID, nodeA.ID)}))
		require.Equal(t, before, version())
		require.Equal(t, []string{"lock"}, port.calls)
	})

	t.Run("rename_only_does_not_lock_or_advance", func(t *testing.T) {
		a := newAsset("rename-src", []uint{nodeA.ID})
		port.reset()
		before := version()
		newName := "rename-dst"
		require.NoError(t, update(a.ID, &UpdateAssetRequest{Name: &newName}))
		require.Equal(t, before, version())
		require.Empty(t, port.calls)
	})

	t.Run("import_late_failure_rolls_back", func(t *testing.T) {
		var assetsBefore int64
		require.NoError(t, db.Model(&model.Asset{}).Count(&assetsBefore).Error)
		before := version()
		port.failAdvance = fmt.Errorf("injected advance failure")
		defer func() { port.failAdvance = nil }()
		_, err := assets.ImportAssets(WithSystemCaller(adminCtx()), &ImportBatch{Source: ImportSourceForm, Rows: []ImportRow{
			{Name: "imp-fail-1", Protocol: "ssh", Host: "10.9.2.1", NodeIDs: []uint{nodeA.ID}},
			{Name: "imp-fail-2", Protocol: "ssh", Host: "10.9.2.2", NodeIDs: []uint{nodeB.ID}},
		}}, 1, "admin")
		require.ErrorContains(t, err, "injected advance failure")
		var assetsAfter, nodesLeft int64
		require.NoError(t, db.Model(&model.Asset{}).Count(&assetsAfter).Error)
		require.NoError(t, db.Model(&model.Asset{}).Where("name LIKE ?", "imp-fail-%").Count(&nodesLeft).Error)
		require.Equal(t, assetsBefore, assetsAfter)
		require.Zero(t, nodesLeft)
		require.Equal(t, before, version())
	})

	t.Run("replace_late_failure_rolls_back", func(t *testing.T) {
		a := newAsset("replace-fail", []uint{nodeA.ID})
		before := version()
		port.failAdvance = fmt.Errorf("injected advance failure")
		defer func() { port.failAdvance = nil }()
		err := update(a.ID, &UpdateAssetRequest{NodeIDs: ids(nodeB.ID)})
		require.ErrorContains(t, err, "injected advance failure")
		require.Equal(t, []uint{nodeA.ID}, mounts(a.ID), "掛載維持交易前")
		require.Equal(t, before, version())
	})

	t.Run("port_missing_fails_and_rolls_back", func(t *testing.T) {
		bare, _ := newAccountServices(t)
		bare.SetTopologyPermissionPort(nil) // 未注入
		_, err := bare.Create(WithSystemCaller(adminCtx()), &CreateAssetRequest{
			Name: "no-port", Protocol: model.ProtocolVNC, Host: "10.9.3.1", Port: 5900, CreatedBy: 1, NodeIDs: []uint{nodeA.ID}})
		require.ErrorIs(t, err, ErrTopologyPermissionPortMissing)
		var n int64
		require.NoError(t, db.Model(&model.Asset{}).Where("name = ?", "no-port").Count(&n).Error)
		require.Zero(t, n)
	})

	// ---- 後半：刪除資產、節點搬移、節點刪除；不推進與回滾；附證啟用 ----
	events := func() int64 {
		var n int64
		require.NoError(t, db.Model(&model.PermissionStateEvent{}).Count(&n).Error)
		return n
	}
	parentOf := func(id uint) *uint {
		var g model.AssetGroup
		require.NoError(t, db.First(&g, id).Error)
		return g.ParentID
	}
	groupExists := func(id uint) bool {
		var n int64
		require.NoError(t, db.Model(&model.AssetGroup{}).Where("id = ?", id).Count(&n).Error)
		return n == 1
	}
	newNode := func(name string, parent *uint) *model.AssetGroup {
		t.Helper()
		g, err := groups.Create(context.Background(), &AssetGroupRequest{Name: name, ParentID: parent}, 1, "admin", "127.0.0.1")
		require.NoError(t, err)
		return g
	}
	grant := func(nodeID uint) {
		t.Helper()
		gid := nodeID
		uid := uint(1)
		require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &uid, AssetGroupID: &gid,
			Permission: model.PermissionConnect}).Error)
	}
	liveGrants := func(nodeID uint) int64 {
		var n int64
		require.NoError(t, db.Model(&model.AssetAuthorization{}).Where("asset_group_id = ?", nodeID).Count(&n).Error)
		return n
	}
	assetAlive := func(id uint) bool {
		var n int64
		require.NoError(t, db.Model(&model.Asset{}).Where("id = ?", id).Count(&n).Error)
		return n == 1
	}
	assertNoTopologyEffect := func(t *testing.T, before int64) {
		t.Helper()
		require.Equal(t, before, version())
		require.Empty(t, port.calls)
	}

	runWriteSuite := func(t *testing.T, suffix string, attested bool) {
		evBefore := func() int64 {
			if !attested {
				return 0
			}
			return events()
		}
		// 附證啟用時，每次成功的拓撲寫入恰好多一筆事件；未啟用時事件表恆空
		wantEvents := func(before, delta int64) {
			t.Helper()
			if !attested {
				require.Zero(t, events())
				return
			}
			require.Equal(t, before+delta, events())
		}

		t.Run("asset_delete_mounted_advances"+suffix, func(t *testing.T) {
			a := newAsset("del-mounted"+suffix, []uint{nodeA.ID, nodeB.ID})
			port.reset()
			v, e := version(), evBefore()
			require.NoError(t, assets.Delete(WithSystemCaller(context.Background()), a.ID))
			require.Equal(t, v+1, version())
			wantEvents(e, 1)
			require.Equal(t, []string{"lock", "begin", "advance"}, port.calls)
			require.Equal(t, []bool{true}, port.lockFirst, "取鎖是交易第一個動作")
			require.False(t, assetAlive(a.ID))
			require.Empty(t, mounts(a.ID))
		})

		t.Run("asset_delete_unmounted_does_not_advance"+suffix, func(t *testing.T) {
			a := newAsset("del-unmounted"+suffix, nil)
			port.reset()
			v, e := version(), evBefore()
			require.NoError(t, assets.Delete(WithSystemCaller(context.Background()), a.ID))
			require.Equal(t, v, version())
			wantEvents(e, 0)
			require.Equal(t, []string{"lock"}, port.calls, "零掛載只取鎖、不推進（與建立同口徑）")
			require.Equal(t, []bool{true}, port.lockFirst)
			require.False(t, assetAlive(a.ID))
		})

		t.Run("asset_delete_late_failure_rolls_back"+suffix, func(t *testing.T) {
			a := newAsset("del-fail"+suffix, []uint{nodeA.ID})
			v, e := version(), evBefore()
			port.failAfterAdvance = fmt.Errorf("injected late failure")
			defer func() { port.failAfterAdvance = nil }()
			err := assets.Delete(WithSystemCaller(context.Background()), a.ID)
			require.ErrorContains(t, err, "injected late failure")
			require.True(t, assetAlive(a.ID), "資產維持交易前")
			require.Equal(t, []uint{nodeA.ID}, mounts(a.ID), "掛載維持交易前")
			require.Equal(t, v, version())
			wantEvents(e, 0)
		})

		t.Run("node_move_advances"+suffix, func(t *testing.T) {
			p1, p2 := newNode("mv-p1"+suffix, nil), newNode("mv-p2"+suffix, nil)
			c := newNode("mv-c"+suffix, &p1.ID)
			port.reset()
			v, e := version(), evBefore()
			_, err := groups.Move(context.Background(), c.ID, &p2.ID, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			require.Equal(t, v+1, version())
			wantEvents(e, 1)
			require.Equal(t, []string{"lock", "begin", "advance"}, port.calls)
			require.Equal(t, []bool{true}, port.lockFirst, "取鎖是交易第一個動作")
			require.Equal(t, p2.ID, *parentOf(c.ID))
		})

		t.Run("node_move_to_root_advances"+suffix, func(t *testing.T) {
			p := newNode("mvr-p"+suffix, nil)
			c := newNode("mvr-c"+suffix, &p.ID)
			port.reset()
			v := version()
			_, err := groups.Move(context.Background(), c.ID, nil, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			require.Equal(t, v+1, version())
			require.Nil(t, parentOf(c.ID))
		})

		t.Run("node_move_same_parent_does_not_advance"+suffix, func(t *testing.T) {
			p := newNode("mvs-p"+suffix, nil)
			c := newNode("mvs-c"+suffix, &p.ID)
			port.reset()
			v, e := version(), evBefore()
			_, err := groups.Move(context.Background(), c.ID, &p.ID, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			require.Equal(t, v, version())
			wantEvents(e, 0)
			require.Equal(t, []string{"lock"}, port.calls)
		})

		t.Run("node_move_late_failure_rolls_back"+suffix, func(t *testing.T) {
			p1, p2 := newNode("mvf-p1"+suffix, nil), newNode("mvf-p2"+suffix, nil)
			c := newNode("mvf-c"+suffix, &p1.ID)
			var logsBefore int64
			require.NoError(t, db.Model(&model.AuditLog{}).Count(&logsBefore).Error)
			v, e := version(), evBefore()
			port.failAfterAdvance = fmt.Errorf("injected late failure")
			defer func() { port.failAfterAdvance = nil }()
			_, err := groups.Move(context.Background(), c.ID, &p2.ID, 1, "admin", "127.0.0.1")
			require.ErrorContains(t, err, "injected late failure")
			require.Equal(t, p1.ID, *parentOf(c.ID), "拓撲維持交易前")
			require.Equal(t, v, version())
			wantEvents(e, 0)
			var logsAfter int64
			require.NoError(t, db.Model(&model.AuditLog{}).Count(&logsAfter).Error)
			require.Equal(t, logsBefore, logsAfter, "審計列隨交易回滾")
		})

		t.Run("node_delete_cascades_and_advances_once"+suffix, func(t *testing.T) {
			n := newNode("del-node"+suffix, nil)
			grant(n.ID)
			require.EqualValues(t, 1, liveGrants(n.ID))
			port.reset()
			v, e := version(), evBefore()
			revoked, err := groups.Delete(context.Background(), n.ID, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			require.EqualValues(t, 1, revoked)
			require.Zero(t, liveGrants(n.ID), "級聯撤銷在同交易")
			require.False(t, groupExists(n.ID))
			require.Equal(t, v+1, version(), "級聯加節點軟刪只推進一次")
			wantEvents(e, 1)
			require.Equal(t, []string{"lock", "begin", "advance"}, port.calls)
			require.Equal(t, []bool{true}, port.lockFirst, "取鎖是交易第一個動作")
		})

		t.Run("node_delete_not_empty_does_not_advance"+suffix, func(t *testing.T) {
			p := newNode("delne-p"+suffix, nil)
			newNode("delne-c"+suffix, &p.ID)
			port.reset()
			v, e := version(), evBefore()
			_, err := groups.Delete(context.Background(), p.ID, 1, "admin", "127.0.0.1")
			require.ErrorIs(t, err, ErrNodeNotEmpty)
			require.Equal(t, v, version())
			wantEvents(e, 0)
			require.Equal(t, []string{"lock"}, port.calls)
			require.True(t, groupExists(p.ID))
		})

		t.Run("node_delete_late_failure_rolls_back"+suffix, func(t *testing.T) {
			n := newNode("delf-node"+suffix, nil)
			grant(n.ID)
			v, e := version(), evBefore()
			port.failAfterAdvance = fmt.Errorf("injected late failure")
			defer func() { port.failAfterAdvance = nil }()
			_, err := groups.Delete(context.Background(), n.ID, 1, "admin", "127.0.0.1")
			require.ErrorContains(t, err, "injected late failure")
			require.True(t, groupExists(n.ID), "節點維持交易前")
			require.EqualValues(t, 1, liveGrants(n.ID), "級聯撤銷隨交易回滾")
			require.Equal(t, v, version())
			wantEvents(e, 0)
		})

		t.Run("node_create_locks_only_does_not_advance"+suffix, func(t *testing.T) {
			// 節點建立取拓撲鎖（交易第一個動作），但新節點不含資產，不 Begin、不推進版本（同零掛載建立）。
			p := newNode("crt-p"+suffix, nil)
			port.reset()
			v, e := version(), evBefore()
			child, err := groups.Create(context.Background(), &AssetGroupRequest{Name: "crt-c" + suffix, ParentID: &p.ID}, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			require.True(t, groupExists(child.ID))
			require.Equal(t, v, version())
			wantEvents(e, 0)
			require.Equal(t, []string{"lock"}, port.calls)
			require.Equal(t, []bool{true}, port.lockFirst, "取鎖是交易第一個動作")
		})

		t.Run("rename_and_describe_do_not_advance"+suffix, func(t *testing.T) {
			n := newNode("ren-src"+suffix, nil)
			port.reset()
			v, e := version(), evBefore()
			_, err := groups.Update(context.Background(), n.ID, &AssetGroupRequest{Name: "ren-dst" + suffix, Description: "d1"}, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			_, err = groups.Update(context.Background(), n.ID, &AssetGroupRequest{Name: "ren-dst" + suffix, Description: "d2"}, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			// 改名與改描述取拓撲鎖（範圍判定要讀鎖後拓撲），但不 Begin、不推進版本
			require.Equal(t, v, version())
			require.Equal(t, []string{"lock", "lock"}, port.calls)
			require.Equal(t, []bool{true, true}, port.lockFirst, "取鎖是交易第一個動作")
			wantEvents(e, 0)
		})

		t.Run("asset_update_same_mounts_and_metadata_do_not_advance"+suffix, func(t *testing.T) {
			a := newAsset("upd-same"+suffix, []uint{nodeA.ID})
			port.reset()
			v, e := version(), evBefore()
			desc := "changed"
			require.NoError(t, update(a.ID, &UpdateAssetRequest{Description: &desc}))
			require.Equal(t, v, version())
			wantEvents(e, 0)
			require.NotContains(t, port.calls, "advance")
		})

		t.Run("read_only_does_not_advance"+suffix, func(t *testing.T) {
			a := newAsset("ro-asset"+suffix, []uint{nodeA.ID})
			port.reset()
			v, e := version(), evBefore()
			_, err := groups.List()
			require.NoError(t, err)
			_, err = groups.ListWithAssets()
			require.NoError(t, err)
			_, err = assets.GetByID(a.ID)
			require.NoError(t, err)
			_ = mounts(a.ID)
			assertNoTopologyEffect(t, v)
			wantEvents(e, 0)
		})
	}

	t.Run("port_missing_group_write_fails_and_rolls_back", func(t *testing.T) {
		bare := NewAssetGroupService(db, audit.NewTxSink(), &cascadingGroupRevoker{}) // 未注入
		p1, p2 := newNode("bare-p1", nil), newNode("bare-p2", nil)
		c := newNode("bare-c", &p1.ID)
		leaf := newNode("bare-leaf", nil)
		_, err := bare.Move(context.Background(), c.ID, &p2.ID, 1, "admin", "127.0.0.1")
		require.ErrorIs(t, err, ErrTopologyPermissionPortMissing)
		require.Equal(t, p1.ID, *parentOf(c.ID))
		_, err = bare.Delete(context.Background(), leaf.ID, 1, "admin", "127.0.0.1")
		require.ErrorIs(t, err, ErrTopologyPermissionPortMissing)
		require.True(t, groupExists(leaf.ID))
		_, err = bare.Create(context.Background(), &AssetGroupRequest{Name: "bare-created"}, 1, "admin", "127.0.0.1")
		require.ErrorIs(t, err, ErrTopologyPermissionPortMissing)
		var created int64
		require.NoError(t, db.Model(&model.AssetGroup{}).Where("name = ?", "bare-created").Count(&created).Error)
		require.Zero(t, created)
		bareAssets, _ := newAccountServices(t)
		bareAssets.SetTopologyPermissionPort(nil)
		bareAssets.SetAuthorizationRevoker(noopRevoker{})
		a := newAsset("bare-asset", []uint{nodeA.ID})
		require.ErrorIs(t, bareAssets.Delete(WithSystemCaller(context.Background()), a.ID), ErrTopologyPermissionPortMissing)
		require.True(t, assetAlive(a.ID))
	})

	runWriteSuite(t, "", false)

	t.Run("attested", func(t *testing.T) {
		// 附證啟用 fixture：測試內的快照來源與 authz 的來源同形（被指派引用的節點與其是否已刪），
		// 其餘集合為空；首筆啟用事件由 audit 入口寫入，之後每次推進都延伸同一條鏈。
		versionOf := func(tx *gorm.DB) int64 {
			var v int64
			require.NoError(t, tx.Raw("SELECT version FROM authz_state WHERE id = 1").Scan(&v).Error)
			return v
		}
		authzPart := func(ctx context.Context, tx *gorm.DB) (audit.PermissionPart, error) {
			sets := map[string][]string{audit.PermSetRoles: {}, audit.PermSetUserRoles: {}, audit.PermSetGroupRoles: {},
				audit.PermSetBindingNodes: {}, audit.PermSetNodes: {}}
			var bns []model.RoleBindingNode
			if err := tx.Find(&bns).Error; err != nil {
				return audit.PermissionPart{}, err
			}
			for _, b := range bns {
				sets[audit.PermSetBindingNodes] = append(sets[audit.PermSetBindingNodes],
					audit.PermissionRow(b.SubjectKind, b.SubjectID, b.RoleID, b.NodeID))
			}
			var nodes []struct {
				ID      uint
				Deleted bool
			}
			if err := tx.Raw(`SELECT asset_groups.id AS id, (asset_groups.deleted_at IS NOT NULL) AS deleted FROM asset_groups
 WHERE asset_groups.id IN (SELECT node_id FROM role_binding_nodes)`).Scan(&nodes).Error; err != nil {
				return audit.PermissionPart{}, err
			}
			for _, n := range nodes {
				sets[audit.PermSetNodes] = append(sets[audit.PermSetNodes], audit.PermissionRow(n.ID, audit.PermBool(n.Deleted)))
			}
			return audit.PermissionPart{
				Meta: &audit.PermissionMeta{Model: audit.PermissionModelVersion, Catalog: "test", Version: versionOf(tx)},
				Sets: sets}, nil
		}
		identityPart := func(context.Context, *gorm.DB) (audit.PermissionPart, error) {
			return audit.PermissionPart{Sets: map[string][]string{audit.PermSetRoleMaps: {}, audit.PermSetGroupMaps: {},
				audit.PermSetMembers: {}, audit.PermSetGroups: {}, audit.PermSetPrincipals: {},
				audit.PermSetRoleDefs: {}, audit.PermSetRolePerms: {}}}, nil
		}
		audit.SetPermissionSources(authzPart, identityPart)
		t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			st, err := audit.ReadPermissionState(context.Background(), tx)
			if err != nil {
				return err
			}
			_, err = audit.EnsurePermissionActivation(context.Background(), tx, st, 1)
			return err
		}))
		require.EqualValues(t, 1, events(), "啟用事件是鏈起點")

		runWriteSuite(t, "-attested", true)

		t.Run("delete_referenced_node_head_state_marks_node_deleted", func(t *testing.T) {
			n := newNode("att-ref", nil)
			require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: "user", SubjectID: 1, RoleID: 7, NodeID: n.ID}).Error)
			// 先讓鏈頭反映「節點未刪、被指派引用」：一次不相關的合法拓撲寫入把鏈頭推到目前狀態
			p := newNode("att-ref-p", nil)
			c := newNode("att-ref-c", &p.ID)
			_, err := groups.Move(context.Background(), c.ID, nil, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			head := func() audit.PermissionState {
				var e model.PermissionStateEvent
				require.NoError(t, db.Order("seq DESC").Limit(1).Find(&e).Error)
				st, err := audit.DecodePermissionState([]byte(e.AfterBody))
				require.NoError(t, err)
				return *st
			}
			require.Contains(t, head().Sets[audit.PermSetNodes], audit.PermissionRow(n.ID, 0), "刪除前：節點被引用且未刪")
			e0, v0 := events(), version()
			// 被指派引用的節點可刪（節點為空葉）；指派列留著，快照要看到「引用的節點已刪」
			_, err = groups.Delete(context.Background(), n.ID, 1, "admin", "127.0.0.1")
			require.NoError(t, err)
			require.Equal(t, e0+1, events())
			require.Equal(t, v0+1, version())
			var last model.PermissionStateEvent
			require.NoError(t, db.Order("seq DESC").Limit(1).Find(&last).Error)
			require.Equal(t, v0+1, last.Version, "鏈頭事件版本等於推進後的權限版本")
			require.Contains(t, head().Sets[audit.PermSetNodes], audit.PermissionRow(n.ID, 1), "事件鏈頭的事後狀態含該節點已刪")
			require.NotContains(t, head().Sets[audit.PermSetNodes], audit.PermissionRow(n.ID, 0))
		})
	})
}
