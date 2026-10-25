package asset_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產批次操作的服務層行為：真判定器、真拓撲序列化鎖、真涵蓋快照（夾具見 scoped_asset_write_env_test.go）。
//
//	go test ./internal/modules/asset/ -run '^(TestAssetBatchMove|TestAssetBatchAddTags|TestAssetBatchDelete)$' -count=1 -v

// abTopo 計次的拓撲窄 port，其餘委派真實作。
type abTopo struct {
	inner    asset.TopologyPermissionPort
	begins   atomic.Int32
	advances atomic.Int32
}

func (p *abTopo) LockTopology(tx *gorm.DB) error { return p.inner.LockTopology(tx) }
func (p *abTopo) BeginPermissionChange(tx *gorm.DB) error {
	p.begins.Add(1)
	return p.inner.BeginPermissionChange(tx)
}
func (p *abTopo) AdvanceVersion(tx *gorm.DB) error {
	p.advances.Add(1)
	return p.inner.AdvanceVersion(tx)
}
func (p *abTopo) SettlePermissionChange(tx *gorm.DB) error { return p.inner.SettlePermissionChange(tx) }

func (e *swEnv) countTopo() *abTopo {
	c := &abTopo{inner: authz.TopologyPermissionAdapter{}}
	e.svc.SetTopologyPermissionPort(c)
	return c
}

// scopedUser 在指定節點持檢視、編輯、刪除的範圍化使用者。
func (e *swEnv) scopedUser(name string, nodes ...string) uint {
	e.t.Helper()
	u := e.user(name)
	e.grantNodes(u, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete), nodes...)
	return u
}

func (e *swEnv) taggedAsset(name, tags string, nodes ...string) uint {
	e.t.Helper()
	id := e.asset(name, nodes...)
	require.NoError(e.t, e.db.Model(&model.Asset{}).Where("id = ?", id).UpdateColumn("tags", tags).Error)
	return id
}

func (e *swEnv) tagsOf(id uint) string {
	e.t.Helper()
	var a model.Asset
	require.NoError(e.t, e.db.Where("id = ?", id).Limit(1).Find(&a).Error)
	return a.Tags
}

func (e *swEnv) auditTotal() int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Unscoped().Model(&model.AuditLog{}).Count(&n).Error)
	return n
}

// batchAudits 資產的批次審計列（details 帶批次鍵）。
func (e *swEnv) batchAudits(assetID uint) []model.AuditLog {
	e.t.Helper()
	var rows []model.AuditLog
	require.NoError(e.t, e.db.Where("resource = ? AND resource_id = ? AND details LIKE ?",
		model.ResourceAsset, assetID, `%"batch_id"%`).Order("id").Find(&rows).Error)
	return rows
}

func abDetails(t *testing.T, row model.AuditLog) model.AssetChangeDetails {
	t.Helper()
	var d model.AssetChangeDetails
	require.NoError(t, json.Unmarshal([]byte(row.Details), &d), row.Details)
	return d
}

func (e *swEnv) liveCount(ids ...uint) int {
	e.t.Helper()
	n := 0
	for _, id := range ids {
		if ok, _ := e.live(id); ok {
			n++
		}
	}
	return n
}

func requireUnavailable(t *testing.T, err error, count int, msg string) {
	t.Helper()
	var u *asset.BatchItemsUnavailableError
	require.True(t, errors.As(err, &u), "%s：應為批次無法操作，得到 %v", msg, err)
	assert.Equal(t, count, u.Count, msg)
}

func requireBlocked(t *testing.T, err error, count int, msg string) {
	t.Helper()
	var b *asset.BatchOutOfScopeNodesError
	require.True(t, errors.As(err, &b), "%s：應為批次受阻，得到 %v", msg, err)
	assert.Equal(t, count, b.Count, msg)
}

func TestAssetBatchMove(t *testing.T) {
	t.Run("merge_keeps_out_of_scope", func(t *testing.T) {
		e := newSwEnv(t)
		mgr := e.scopedUser("sw-mv-mgr", "sw-a", "sw-b")
		ac := e.asset("sw-mv-ac", "sw-a", "sw-c")
		a := e.asset("sw-mv-a", "sw-a")
		res, err := e.svc.BatchMove(e.ctx(mgr), []uint{ac, a, ac}, e.nodes["sw-b"])
		require.NoError(t, err)
		assert.Equal(t, asset.BatchResult{Affected: 2}, res, "重複 ID 只計一次")
		assert.Equal(t, []string{"sw-b", "sw-c"}, e.mounted(ac), "A 換成 B，範圍外的 C 保留")
		assert.Equal(t, []string{"sw-b"}, e.mounted(a))

		g := e.asset("sw-mv-global", "sw-a", "sw-c", "sw-far")
		res, err = e.svc.BatchMove(e.ctx(e.super), []uint{g}, e.nodes["sw-b"])
		require.NoError(t, err)
		assert.Equal(t, 1, res.Affected)
		assert.Equal(t, []string{"sw-b"}, e.mounted(g), "全域主體搬移後只剩目的節點")
	})

	t.Run("target_out_of_scope_equals_missing_and_unchanged_assets", func(t *testing.T) {
		e := newSwEnv(t)
		mgr := e.scopedUser("sw-mv-mgr", "sw-a", "sw-b")
		ac := e.asset("sw-mv-ac", "sw-a", "sw-c")
		_, errOut := e.svc.BatchMove(e.ctx(mgr), []uint{ac}, e.nodes["sw-c"])
		requireScopeDenied(t, errOut, "目的節點在範圍外")
		_, errMiss := e.svc.BatchMove(e.ctx(mgr), []uint{ac}, 987651)
		require.ErrorIs(t, errMiss, asset.ErrNodeNotFound, "目的節點不存在（HTTP 層與範圍外同形，見邊界測試）")
		assert.Equal(t, []string{"sw-a", "sw-c"}, e.mounted(ac), "歸屬不變")

		b := e.asset("sw-mv-b", "sw-b")
		before := e.auditTotal()
		topo := e.countTopo()
		res, err := e.svc.BatchMove(e.ctx(mgr), []uint{b}, e.nodes["sw-b"])
		require.NoError(t, err)
		assert.Equal(t, asset.BatchResult{Unchanged: 1}, res, "已在目的節點者計 unchanged")
		assert.Equal(t, before, e.auditTotal(), "已在 B 的資產無審計列")
		assert.Zero(t, topo.advances.Load(), "沒有實際變更不推進版本")
	})

	t.Run("same_as_single_updates", func(t *testing.T) {
		e := newSwEnv(t)
		g := e.groupGrantOn("sw-b")
		want := asset.CoverageGrant{Kind: model.BindingSubjectUserGroup, ID: g, Level: string(model.PermissionConnect)}
		mgr := e.scopedUser("sw-mv-mgr", "sw-a", "sw-b")
		batch1, batch2 := e.asset("sw-mv-b1", "sw-a", "sw-c"), e.asset("sw-mv-b2", "sw-a")
		single1, single2 := e.asset("sw-mv-s1", "sw-a", "sw-c"), e.asset("sw-mv-s2", "sw-a")

		topo := e.countTopo()
		_, err := e.svc.BatchMove(e.ctx(mgr), []uint{batch1, batch2}, e.nodes["sw-b"])
		require.NoError(t, err)
		assert.EqualValues(t, 1, topo.begins.Load())
		assert.EqualValues(t, 1, topo.advances.Load(), "版本推進點只被呼叫一次")
		require.NoError(t, e.setNodes(mgr, single1, "sw-b")())
		require.NoError(t, e.setNodes(mgr, single2, "sw-b")())

		for _, p := range [][2]uint{{batch1, single1}, {batch2, single2}} {
			assert.Equal(t, e.mounted(p[1]), e.mounted(p[0]), "歸屬與單筆更新相同")
			br, sr := e.mountAudits(p[0]), e.mountAudits(p[1])
			require.Len(t, br, 1)
			require.Len(t, sr, 1)
			bc, sc := coverageOf(t, br[0]), coverageOf(t, sr[0])
			assert.Equal(t, sc.Grants, bc.Grants, "每台涵蓋差異（授權列）與單筆相同")
			assert.Contains(t, bc.Grants.Gained.Items, want, "搬到帶群組授權的節點：群組為得到者")
			bd := abDetails(t, br[0])
			assert.NotEmpty(t, bd.BatchID)
			assert.Equal(t, 2, bd.BatchSize)
		}
		assert.Equal(t, abDetails(t, e.mountAudits(batch1)[0]).BatchID, abDetails(t, e.mountAudits(batch2)[0]).BatchID, "同一批同一識別")
	})

	t.Run("failures_roll_back_everything", func(t *testing.T) {
		for _, mode := range []string{"coverage_query_fails", "coverage_port_missing", "second_item_write_fails"} {
			t.Run(mode, func(t *testing.T) {
				e := newSwEnv(t)
				x, y := e.asset("sw-mv-x", "sw-a"), e.asset("sw-mv-y", "sw-a")
				topo := e.countTopo()
				ctx := e.ctx(e.super)
				switch mode {
				case "coverage_query_fails":
					e.covFail.Store(true)
				case "coverage_port_missing":
					e.svc.SetCoverageSnapshotPort(nil)
				case "second_item_write_fails":
					ctx = asset.WithAssetBatchTestHooksForTest(ctx, &asset.AssetBatchTestHooks{
						BeforeItemWrite: func(_ *gorm.DB, i int) error {
							if i == 1 {
								return errors.New("injected")
							}
							return nil
						}})
				}
				_, err := e.svc.BatchMove(ctx, []uint{x, y}, e.nodes["sw-b"])
				require.Error(t, err)
				if mode == "coverage_port_missing" {
					require.ErrorIs(t, err, asset.ErrCoverageSnapshotPortMissing)
				}
				assert.Equal(t, []string{"sw-a"}, e.mounted(x), "歸屬不變")
				assert.Equal(t, []string{"sw-a"}, e.mounted(y), "歸屬不變")
				assert.Zero(t, topo.advances.Load(), "失敗不推進版本")
			})
		}
		t.Run("audit_write_fails", func(t *testing.T) {
			e := newSwEnv(t)
			x, y := e.asset("sw-mv-x", "sw-a"), e.asset("sw-mv-y", "sw-a")
			topo := e.countTopo()
			e.auditFail.Store(true)
			_, err := e.svc.BatchMove(e.ctx(e.super), []uint{x, y}, e.nodes["sw-b"])
			require.ErrorIs(t, err, errSwAuditInjected)
			assert.Equal(t, []string{"sw-a"}, e.mounted(x))
			assert.Equal(t, []string{"sw-a"}, e.mounted(y))
			assert.Zero(t, topo.advances.Load())
		})
	})
}

// abTagRef 歸一參照來源替身：固定的可視資產集合。
type abTagRef struct{ ids []uint }

func (p abTagRef) VisibleAssetIDsTx(context.Context, *gorm.DB) ([]uint, bool, error) {
	return p.ids, true, nil
}

func TestAssetBatchAddTags(t *testing.T) {
	t.Run("union_audit_and_unchanged", func(t *testing.T) {
		e := newSwEnv(t)
		x := e.taggedAsset("sw-tg-x", "生產", "sw-a")
		y := e.taggedAsset("sw-tg-y", "生產,資料庫", "sw-a")
		before := e.auditTotal()
		res, err := e.svc.BatchAddTags(e.ctx(e.super), []uint{x, y, x}, []string{"資料庫"})
		require.NoError(t, err)
		assert.Equal(t, asset.BatchResult{Affected: 1, Unchanged: 1}, res)
		assert.Equal(t, "生產,資料庫", e.tagsOf(x))
		assert.Equal(t, "生產,資料庫", e.tagsOf(y), "已含者不動")
		assert.Empty(t, e.batchAudits(y), "已含標籤的資產無審計列")
		rows := e.batchAudits(x)
		require.Len(t, rows, 1, "成功的每台恰一列 update 審計")
		assert.Equal(t, model.ActionUpdate, rows[0].Action)
		d := abDetails(t, rows[0])
		require.Len(t, d.Changes, 1)
		assert.Equal(t, "tags", d.Changes[0].Field, "diff 只有 tags")
		assert.Equal(t, 2, d.BatchSize)
		assert.Equal(t, before+1, e.auditTotal(), "整批只新增一列")
	})

	t.Run("limit_exceeded_whole_batch_fails", func(t *testing.T) {
		e := newSwEnv(t)
		list := make([]string, 20)
		for i := range list {
			list[i] = fmt.Sprintf("t%02d", i)
		}
		full := e.taggedAsset("sw-tg-full", strings.Join(list, ","), "sw-a")
		small := e.taggedAsset("sw-tg-small", "a", "sw-a")
		before := e.auditTotal()
		_, err := e.svc.BatchAddTags(e.ctx(e.super), []uint{small, full}, []string{"new"})
		require.ErrorIs(t, err, asset.ErrTooManyTags)
		assert.Equal(t, "a", e.tagsOf(small), "所有資產標籤不變")
		assert.Equal(t, strings.Join(list, ","), e.tagsOf(full))
		assert.Equal(t, before, e.auditTotal(), "服務層沒有任何審計列")
	})

	t.Run("scoped_reference_spelling", func(t *testing.T) {
		e := newSwEnv(t)
		mgr := e.scopedUser("sw-tg-mgr", "sw-a")
		visible := e.taggedAsset("sw-tg-vis", "DBA", "sw-a")
		hidden := e.taggedAsset("sw-tg-hid", "Prod", "sw-c")
		target := e.taggedAsset("sw-tg-target", "web", "sw-a")
		_ = hidden
		e.svc.SetTagReferencePort(abTagRef{ids: []uint{visible, target}})
		_, err := e.svc.BatchAddTags(e.ctx(mgr), []uint{target}, []string{"dba", "prod"})
		require.NoError(t, err)
		assert.Equal(t, "web,DBA,prod", e.tagsOf(target), "可視字典內的寫法歸一，只在範圍外出現的寫法不被歸一")
	})

	t.Run("audit_failure_rolls_back", func(t *testing.T) {
		e := newSwEnv(t)
		x := e.taggedAsset("sw-tg-x", "a", "sw-a")
		y := e.taggedAsset("sw-tg-y", "b", "sw-a")
		e.auditFail.Store(true)
		_, err := e.svc.BatchAddTags(e.ctx(e.super), []uint{x, y}, []string{"z"})
		require.ErrorIs(t, err, errSwAuditInjected)
		assert.Equal(t, "a", e.tagsOf(x))
		assert.Equal(t, "b", e.tagsOf(y))
	})
}

func TestAssetBatchDelete(t *testing.T) {
	t.Run("blocked_by_out_of_scope_nodes", func(t *testing.T) {
		e := newSwEnv(t)
		x := e.asset("sw-bd-x", "sw-a", "sw-c")
		y := e.asset("sw-bd-y", "sw-a")
		uid := e.super
		xid := x
		require.NoError(t, e.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &xid,
			Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
		grants := e.connGrantCount(x)
		before := e.auditTotal()
		topo := e.countTopo()

		_, err := e.svc.BatchDelete(e.ctx(e.manager), []uint{x, y})
		requireBlocked(t, err, 1, "兩台中一台另掛範圍外節點")
		assert.NotContains(t, err.Error(), "sw-", "錯誤字串不含名稱")
		assert.Equal(t, 2, e.liveCount(x, y))
		assert.Equal(t, []string{"sw-a", "sw-c"}, e.mounted(x))
		assert.Equal(t, grants, e.connGrantCount(x))
		assert.Equal(t, before, e.auditTotal())
		assert.Zero(t, topo.begins.Load()+topo.advances.Load())

		p := e.asset("sw-bd-p", "sw-a", "sw-b", "sw-c", "sw-far")
		q := e.asset("sw-bd-q", "sw-a", "sw-b", "sw-c", "sw-far")
		_, err = e.svc.BatchDelete(e.ctx(e.manager), []uint{p, q})
		requireBlocked(t, err, 2, "每台各掛三個範圍外節點：count 是台數不是節點數")
	})

	t.Run("unavailable_before_blocked", func(t *testing.T) {
		e := newSwEnv(t)
		x := e.asset("sw-bd-x", "sw-a", "sw-c")
		y := e.asset("sw-bd-y", "sw-a")
		_, err := e.svc.BatchDelete(e.ctx(e.manager), []uint{x, y, 987651})
		requireUnavailable(t, err, 1, "同時含不存在 ID 與受阻資產：只回無法操作")

		// 把受阻那台移出範圍內節點後，同一組輸入變成無法操作
		require.NoError(t, e.setNodes(e.manager, x)())
		_, err = e.svc.BatchDelete(e.ctx(e.manager), []uint{x, y})
		requireUnavailable(t, err, 1, "移出範圍後原封再送")
		assert.Equal(t, 2, e.liveCount(x, y), "兩台皆未刪")
		res, err := e.svc.BatchDelete(e.ctx(e.manager), []uint{y})
		require.NoError(t, err, "排除該台後對剩下的另送新批次成功")
		assert.Equal(t, 1, res.Affected)
	})

	t.Run("ungrouped", func(t *testing.T) {
		e := newSwEnv(t)
		holder := e.user("sw-bd-global")
		e.grantGlobal(holder, e.role(authz.PermAssetView, authz.PermAssetUpdate, authz.PermAssetDelete))
		u1, u2, u3 := e.asset("sw-bd-u1"), e.asset("sw-bd-u2"), e.asset("sw-bd-u3")
		_, err := e.svc.BatchDelete(e.ctx(e.manager), []uint{u1})
		requireUnavailable(t, err, 1, "只持節點範圍刪除指派者含未分組資產")
		assert.Equal(t, 1, e.liveCount(u1))
		_, err = e.svc.BatchDelete(e.ctx(holder), []uint{u1})
		require.NoError(t, err, "持全域刪除指派的非超管成功")
		_, err = e.svc.BatchDelete(e.ctx(e.super), []uint{u2, u3})
		require.NoError(t, err, "超管成功")
		assert.Zero(t, e.liveCount(u1, u2, u3))
	})

	t.Run("execution_matches_single_and_audits", func(t *testing.T) {
		e := newSwEnv(t)
		mk := func(prefix string) []uint {
			ids := make([]uint, 3)
			for i := range ids {
				ids[i] = e.asset(fmt.Sprintf("%s-%d", prefix, i), "sw-a")
				uid, aid := e.manager, ids[i]
				require.NoError(t, e.db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid,
					Permission: model.PermissionConnect, GrantedBy: e.super}).Error)
			}
			return ids
		}
		batch, single := mk("sw-bd-b"), mk("sw-bd-s")
		topo := e.countTopo()
		res, err := e.svc.BatchDelete(e.ctx(e.manager), batch)
		require.NoError(t, err)
		assert.Equal(t, 3, res.Affected)
		assert.EqualValues(t, 1, topo.begins.Load())
		assert.EqualValues(t, 1, topo.advances.Load(), "權限版本推進點在該交易只被呼叫一次")
		for _, id := range single {
			require.NoError(t, e.del(e.manager, id)())
		}
		for i := range batch {
			assert.Zero(t, e.liveCount(batch[i]), "資產軟刪")
			assert.Empty(t, e.mounted(batch[i]), "asset_nodes 無殘列")
			assert.Zero(t, e.connGrantCount(batch[i]), "隨資產的授權已撤")
			assert.Equal(t, e.liveCount(single[i]), e.liveCount(batch[i]), "與逐台單筆刪除的結果相同")
			assert.Equal(t, e.mounted(single[i]), e.mounted(batch[i]))
			assert.Equal(t, e.connGrantCount(single[i]), e.connGrantCount(batch[i]))
		}
		// 每台一列帶批次鍵的刪除審計（另有模型刪除 hook 的一列，兩者以批次鍵區分）
		ids := map[string]bool{}
		for _, id := range batch {
			rows := e.batchAudits(id)
			require.Len(t, rows, 1)
			assert.Equal(t, model.ActionDelete, rows[0].Action)
			assert.Equal(t, model.ResourceAsset, rows[0].Resource)
			d := abDetails(t, rows[0])
			assert.Equal(t, 3, d.BatchSize)
			ids[d.BatchID] = true
		}
		assert.Len(t, ids, 1, "三列帶相同 batch_id")
		for _, id := range single {
			assert.Empty(t, e.batchAudits(id), "單筆刪除不帶批次鍵")
		}
	})

	t.Run("third_delete_fails_rolls_back_all", func(t *testing.T) {
		e := newSwEnv(t)
		ids := []uint{e.asset("sw-bd-1", "sw-a"), e.asset("sw-bd-2", "sw-a"), e.asset("sw-bd-3", "sw-a")}
		topo := e.countTopo()
		ctx := asset.WithAssetBatchTestHooksForTest(e.ctx(e.manager), &asset.AssetBatchTestHooks{
			BeforeItemWrite: func(_ *gorm.DB, i int) error {
				if i == 2 {
					return errors.New("injected")
				}
				return nil
			}})
		_, err := e.svc.BatchDelete(ctx, ids)
		require.Error(t, err)
		assert.Equal(t, 3, e.liveCount(ids...), "三台皆未刪")
		for _, id := range ids {
			assert.Equal(t, []string{"sw-a"}, e.mounted(id))
		}
		assert.Zero(t, topo.advances.Load(), "推進點未被呼叫")
	})
}
