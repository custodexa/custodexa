package authz

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// 交易內判定：Decide 在呼叫方交易內重解主體與拓撲，傳入主體只提供
// UserID 與 Facts。寫入方照正式寫入的順序先取拓撲序列化鎖再改表；判定方以新語句讀，
// 不沿用交易外或取鎖前的結果。

var wantTopoUnavailable = ScopeResult{Outcome: ScopeDenyScope, Reason: ScopeReasonTopologyUnavailable}

// newDecideFileFixture 檔案型 SQLite（WAL、多連線）上的判定夾具：交易開著時另一條連線
// 仍可讀到提交前的狀態，用來比對「交易內」與「交易外」的判定。
func newDecideFileFixture(t *testing.T) *decideFixture {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(3000)&_pragma=journal_mode(WAL)", filepath.Join(t.TempDir(), "decide.db"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })
	var mode string
	require.NoError(t, db.Raw("PRAGMA journal_mode").Scan(&mode).Error)
	require.Equal(t, "wal", mode, "多連線比對要 WAL：讀者不被未提交的寫者擋住")
	require.NoError(t, migrateWithAuthz(db,
		&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
	return newDecideFixtureOn(t, db)
}

// beginLocked 開交易並以拓撲序列化鎖為第一個動作；測試結束未收尾的交易一律回滾。
func (f *decideFixture) beginLocked(t *testing.T) *gorm.DB {
	t.Helper()
	tx := f.db.Begin()
	require.NoError(t, tx.Error)
	t.Cleanup(func() { _ = tx.Rollback().Error })
	require.NoError(t, LockScopeTopologyTx(tx))
	return tx
}

func decideTx(t *testing.T, ev *ScopeEvaluator, tx *gorm.DB, p *Principal, perm Permission, target ScopeTarget) ScopeResult {
	t.Helper()
	res, err := ev.Decide(tx, p, perm, target)
	require.NoError(t, err)
	return res
}

func execOne(t *testing.T, tx *gorm.DB, sql string, args ...interface{}) {
	t.Helper()
	r := tx.Exec(sql, args...)
	require.NoError(t, r.Error)
	require.EqualValues(t, 1, r.RowsAffected, sql)
}

// runDecideInTxSubtests 掛在 TestScopeEvaluationSameBinding 之下。
func runDecideInTxSubtests(t *testing.T) {
	t.Run("in_tx_mount_change_then_decide", func(t *testing.T) {
		f := newDecideFileFixture(t)
		ev := f.evaluator(f.catView)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[1]) // a1 掛 n3，在 n1 子樹內
		require.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, AssetTarget(f.a[1])))

		tx := f.beginLocked(t)
		execOne(t, tx, "UPDATE asset_nodes SET node_id = ? WHERE asset_id = ? AND node_id = ?", f.n[4], f.a[1], f.n[3])
		assert.Equal(t, wantOutScope, decideTx(t, ev, tx, &Principal{UserID: uid}, PermAssetView, AssetTarget(f.a[1])),
			"交易內已把掛載改到範圍外：依交易內拓撲判範圍拒絕")
		assert.Equal(t, wantAllow, f.decide(t, ev, uid, PermAssetView, AssetTarget(f.a[1])),
			"另一連線在提交前判定：仍依舊拓撲")
		require.NoError(t, tx.Commit().Error)
		assert.Equal(t, wantOutScope, f.decide(t, ev, uid, PermAssetView, AssetTarget(f.a[1])),
			"提交後下一次判定採新拓撲")
	})

	t.Run("outside_principal_scope_root_deleted_in_tx", func(t *testing.T) {
		f := newDecideFileFixture(t)
		ev := f.evaluator(f.catView)
		uid := f.user(t)
		f.bindDirect(t, uid, f.role(t, PermAssetView), f.n[2])
		p := mustResolve(t, f, ev, uid) // 交易外解析
		require.True(t, p.Has(PermAssetView))
		require.Equal(t, wantAllow, decideTx(t, ev, f.db, p, PermAssetView, AssetTarget(f.a[1])))

		tx := f.beginLocked(t)
		require.NoError(t, tx.Delete(&model.AssetGroup{}, f.n[2]).Error) // 範圍根軟刪
		assert.Equal(t, wantNoCap, decideTx(t, ev, tx, p, PermAssetView, AssetTarget(f.a[1])),
			"範圍根在交易內已刪：指派不再有有效節點，依交易內狀態為能力拒絕")
		assert.Equal(t, wantNoCap, decideTx(t, ev, tx, p, PermAssetView, NodeTarget(f.n[3])))
		assert.Equal(t, wantAllow, decideTx(t, ev, f.db, p, PermAssetView, AssetTarget(f.a[1])),
			"另一連線在提交前：範圍根仍在")
		require.NoError(t, tx.Commit().Error)
		assert.Equal(t, wantNoCap, decideTx(t, ev, f.db, p, PermAssetView, AssetTarget(f.a[1])))
	})

	// 交易外解析的主體帶著舊指派；範圍根仍存在，所以只重查有效節點而沿用舊指派的實作
	// 在這三案會放行。三案都必須依交易內重解的新主體判能力拒絕。
	t.Run("outside_principal_binding_change_in_tx", func(t *testing.T) {
		cases := []struct {
			name   string
			perm   Permission
			setup  func(t *testing.T, f *decideFixture, uid uint) uint
			change func(t *testing.T, f *decideFixture, tx *gorm.DB, uid, roleID uint)
			keep   Permission // 變更後仍應放行的權限點（空值不檢查）
		}{
			{
				name: "remove_node_assignment",
				perm: PermAssetView,
				setup: func(t *testing.T, f *decideFixture, uid uint) uint {
					r := f.role(t, PermAssetView)
					f.bindDirect(t, uid, r, f.n[1])
					return r
				},
				// 只移除指派列；綁定節點列與節點都還在，「只重查有效節點」仍查得到 n1
				change: func(t *testing.T, f *decideFixture, tx *gorm.DB, uid, roleID uint) {
					execOne(t, tx, "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", uid, roleID)
				},
			},
			{
				name: "remove_user_from_group",
				perm: PermAssetView,
				setup: func(t *testing.T, f *decideFixture, uid uint) uint {
					r := f.role(t, PermAssetView)
					f.bindGroup(t, uid, r, f.n[1])
					return r
				},
				change: func(t *testing.T, f *decideFixture, tx *gorm.DB, uid, roleID uint) {
					execOne(t, tx, "DELETE FROM user_group_members WHERE user_id = ?", uid)
				},
			},
			{
				name: "remove_permission_from_role",
				perm: PermAssetUpdate,
				setup: func(t *testing.T, f *decideFixture, uid uint) uint {
					r := f.role(t, PermAssetView, PermAssetUpdate)
					f.bindDirect(t, uid, r, f.n[1])
					return r
				},
				change: func(t *testing.T, f *decideFixture, tx *gorm.DB, uid, roleID uint) {
					execOne(t, tx, "DELETE FROM role_permissions WHERE role_id = ? AND permission_key = ?", roleID, string(PermAssetUpdate))
				},
				keep: PermAssetView,
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				f := newDecideFileFixture(t)
				ev := f.evaluator(f.catView)
				uid := f.user(t)
				// 另持一筆不含 asset 權限點的全域指派：移除後主體不是零指派（零指派依相容規則
				// 視同一般使用者範本，本身含 asset:view），被移除的那筆是唯一含該權限點的指派
				f.global(t, uid, f.role(t, PermAuditView))
				roleID := c.setup(t, f, uid)
				p := mustResolve(t, f, ev, uid) // 交易外解析
				require.True(t, p.Has(c.perm))
				target := AssetTarget(f.a[1])
				require.Equal(t, wantAllow, decideTx(t, ev, f.db, p, c.perm, target))

				tx := f.beginLocked(t)
				c.change(t, f, tx, uid, roleID)
				var live int64
				require.NoError(t, tx.Model(&model.AssetGroup{}).Where("id = ?", f.n[1]).Count(&live).Error)
				require.EqualValues(t, 1, live, "範圍根仍存在")
				assert.Equal(t, wantNoCap, decideTx(t, ev, tx, p, c.perm, target),
					"依交易內重解的新主體：能力拒絕，不是放行")
				// 對照：沿用交易外主體的舊指派（有效節點 n1 仍在）會放行，證明本案有鑑別力
				stale, _, err := ev.decideOn(tx, p, c.perm, target)
				require.NoError(t, err)
				assert.Equal(t, wantAllow, stale, "舊指派在交易內狀態下仍可放行，Decide 不得沿用它")
				if c.keep != "" {
					assert.Equal(t, wantAllow, decideTx(t, ev, tx, p, c.keep, target), "未移除的權限點照常")
				}
				assert.Equal(t, wantAllow, decideTx(t, ev, f.db, p, c.perm, target), "另一連線在提交前仍依舊指派")
				require.NoError(t, tx.Commit().Error)
				assert.Equal(t, wantNoCap, decideTx(t, ev, f.db, p, c.perm, target))
			})
		}
	})

	t.Run("topology_not_injected_in_tx", func(t *testing.T) {
		f := newDecideFileFixture(t)
		withTopo, noTopo := f.evaluator(f.catView), NewScopeEvaluator(f.catView, nil)
		nodeUser, globalUser, su := f.user(t), f.user(t), f.user(t)
		f.bindDirect(t, nodeUser, f.role(t, PermAssetView), f.n[1])
		f.global(t, globalUser, f.role(t, PermAssetView))
		f.global(t, su, f.builtinRole(t, model.BuiltinSuperAdmin))

		tx := f.beginLocked(t)
		require.Equal(t, wantAllow, decideTx(t, withTopo, tx, &Principal{UserID: nodeUser}, PermAssetView, AssetTarget(f.a[1])),
			"注入拓撲時節點範圍主體在範圍內放行")
		for _, target := range []ScopeTarget{AssetTarget(f.a[1]), NodeTarget(f.n[1]), AssetAccountTarget(f.a[1], f.acc[1])} {
			assert.Equal(t, wantTopoUnavailable, decideTx(t, noTopo, tx, &Principal{UserID: nodeUser}, PermAssetView, target),
				"未注入拓撲：只經節點範圍來源者一律範圍拒絕")
			assert.Equal(t, wantAllow, decideTx(t, noTopo, tx, &Principal{UserID: globalUser}, PermAssetView, target), "全域主體照常")
			assert.Equal(t, wantAllow, decideTx(t, noTopo, tx, &Principal{UserID: su}, PermAssetUpdate, target), "超管照常")
		}
		assert.Equal(t, wantNoCap, decideTx(t, noTopo, tx, &Principal{UserID: globalUser}, PermAssetUpdate, AssetTarget(f.a[1])),
			"全域主體沒有的權限點仍為能力拒絕")
		require.NoError(t, tx.Commit().Error)
	})
}
