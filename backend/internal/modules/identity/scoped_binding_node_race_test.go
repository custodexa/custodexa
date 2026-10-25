package identity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
)

// 範圍化角色指派與節點刪除的並發：兩者經同一把拓撲序列化鎖排成單一序列，後行者以取鎖後重讀的狀態為準。
// 未設 PG 連線字串時在 SQLite 執行；設了即在獨立 schema 的 PostgreSQL 執行（斷言實際方言）。
//
//	TEST_PG_DSN="host=... user=... password=... dbname=... sslmode=disable" \
//	  REQUIRE_INTEGRATION=1 go test ./internal/modules/identity -run '^TestScopedBindingNodeRace$' -count=1 -v
//
// PostgreSQL 的先後以拓撲鎖取得後的停點固定：先行交易停住時，後行交易的 backend pid 由取鎖語句之前的回呼記下，
// 等待以限定 database、classid、objid、pid 的 pg_locks 與 pg_blocking_pids 正向證明。

const nodeRaceRounds = 50

type nodeRaceProbe struct {
	mu   sync.Mutex
	pids []int64
}

func (p *nodeRaceProbe) pid(t *testing.T, i int) int64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		if len(p.pids) > i {
			v := p.pids[i]
			p.mu.Unlock()
			return v
		}
		p.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("第 %d 個交易未在 5 秒內嘗試取拓撲鎖", i+1)
	return 0
}

type nodeRaceEnv struct {
	*scopedEnv
	assets *asset.AssetGroupService
	obs    *gorm.DB // 觀測連線；SQLite 為 nil
	pg     bool
	probe  atomic.Pointer[nodeRaceProbe]

	confirmedAssignFirst int
	confirmedDeleteFirst int
	seq                  int
}

func openNodeRaceDB(t *testing.T) (db, obs *gorm.DB) {
	t.Helper()
	dsn := os.Getenv(testgate.EnvPGDSN)
	if dsn == "" {
		return nil, nil
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	schema := fmt.Sprintf("nrace_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error
		if s, e := admin.DB(); e == nil {
			_ = s.Close()
		}
	})
	open := func(extra string) *gorm.DB {
		h, err := gorm.Open(postgres.Open(dsn+" search_path="+schema+extra), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := h.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(8)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return h
	}
	db = open(" lock_timeout=30000")
	obs = open("")
	require.Equal(t, "postgres", db.Dialector.Name(), "設了 PG 連線字串時不得回退 SQLite")
	return db, obs
}

func newNodeRaceEnv(t *testing.T) *nodeRaceEnv {
	t.Helper()
	pgDB, obs := openNodeRaceDB(t)
	var base *roleDefEnv
	if pgDB == nil {
		base = newRoleDefEnv(t)
	} else {
		base = newRoleDefEnvOn(t, pgDB)
	}
	db := base.db
	require.NoError(t, db.AutoMigrate(&model.PasswordHistory{}, &model.RefreshToken{}, &model.UserRoleMappingRuleSupport{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.UserRoleMapping{},
		&model.Asset{}, &model.AssetNode{}, &model.ApproverScope{}, &model.Credential{}, &model.UserExternalIdentity{}))

	guard := NewAssignmentGuard(FullCatalog())
	guard.SetNodeExistenceReader(asset.NewNodeExistenceReader())
	revoker := authz.NewAssetAuthorizationService(db)
	users := NewUserService(db, revoker)
	users.SetOwnerTransferGuard(authz.SelfGrantGuard{})
	users.SetAssignmentGuard(guard)
	groups := NewUserGroupService(db, audit.NewTxSink(), revoker)
	groups.SetAssignmentGuard(guard)

	topo := asset.NewScopeTopologyReader()
	assets := asset.NewAssetGroupService(db, audit.NewTxSink(), revoker)
	assets.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	assets.SetNodeWriteScopePort(authz.NewNodeWriteScope(authz.NewScopeEvaluator(authz.ProductCatalogue(), topo)))
	assets.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	assets.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(topo))

	e := &nodeRaceEnv{
		scopedEnv: &scopedEnv{groupBindEnv: &groupBindEnv{guardEnv: &guardEnv{roleDefEnv: base, users: users}, svc: groups}},
		assets:    assets, obs: obs, pg: pgDB != nil,
	}
	e.idAdmin = e.admin
	e.create(t, "assetmgr", permStrings(authz.ScopedTemplateAssetAdminPermissions())...)
	if e.pg {
		require.NoError(t, db.Callback().Raw().Before("gorm:raw").Register("nrace:pid", func(d *gorm.DB) {
			p := e.probe.Load()
			if p == nil || !strings.Contains(d.Statement.SQL.String(), "pg_advisory_xact_lock") ||
				len(d.Statement.Vars) == 0 || fmt.Sprint(d.Statement.Vars[0]) != fmt.Sprint(authz.TopologySerializationLockClass) {
				return
			}
			var pid int64
			if err := d.Statement.ConnPool.QueryRowContext(d.Statement.Context, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				_ = d.AddError(err)
				return
			}
			p.mu.Lock()
			p.pids = append(p.pids, pid)
			p.mu.Unlock()
		}))
	}
	return e
}

func (e *nodeRaceEnv) deleteNode(id uint) error {
	ctx := authz.ContextWithPrincipal(context.Background(), &authz.Principal{UserID: e.admin})
	_, err := e.assets.Delete(ctx, id, e.admin, "race", "127.0.0.1")
	return err
}

// proveWaiting 證明 waiter 正在等 holder 持有的拓撲序列化鎖（上限 5 秒）。
func (e *nodeRaceEnv) proveWaiting(t *testing.T, waiter, holder int64) {
	t.Helper()
	const q = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2 AND pid = ? AND %s`
	deadline := time.Now().Add(5 * time.Second)
	var waiting int64
	for time.Now().Before(deadline) {
		require.NoError(t, e.obs.Raw(fmt.Sprintf(q, "NOT granted"), int64(authz.TopologySerializationLockClass), waiter).Scan(&waiting).Error)
		if waiting == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.EqualValues(t, 1, waiting, "後行交易 pid=%d 未在 5 秒內出現在拓撲鎖的等待列", waiter)
	var blocked bool
	require.NoError(t, e.obs.Raw("SELECT ?::int = ANY(pg_blocking_pids(?::int))", holder, waiter).Scan(&blocked).Error)
	require.True(t, blocked, "後行交易 pid=%d 須被先行交易 pid=%d 擋住", waiter, holder)
	var held int64
	require.NoError(t, e.obs.Raw(fmt.Sprintf(q, "granted"), int64(authz.TopologySerializationLockClass), holder).Scan(&held).Error)
	require.EqualValues(t, 1, held, "先行交易 pid=%d 須恰持有一列拓撲鎖", holder)
	fmt.Printf("NODE-RACE waiter_pid=%d holder_pid=%d waiting=%d blocked=%v held=%d\n", waiter, holder, waiting, blocked, held)
}

// runOrdered 以拓撲鎖取得後的停點強制順序：first 取得拓撲序列化鎖後停住，second 此時才開始並被擋在同一把鎖上，
// 確認後放行 first。回兩者的錯誤。PostgreSQL 以 pg_locks 證明等待；SQLite 以 second 在放行前未完成為準。
func (e *nodeRaceEnv) runOrdered(t *testing.T, first, second func() error) (error, error) {
	t.Helper()
	probe := &nodeRaceProbe{}
	e.probe.Store(probe)
	defer e.probe.Store(nil)
	var armed atomic.Bool
	entered, release := make(chan int64, 1), make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open()
	restore := authz.SetTopologyLockAcquiredHookForTest(func(tx *gorm.DB) {
		if !armed.CompareAndSwap(false, true) {
			return
		}
		var pid int64
		if e.pg {
			if err := tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
				pid = -1
			}
		}
		entered <- pid
		<-release
	})
	defer restore()

	c1, c2 := make(chan error, 1), make(chan error, 1)
	go func() { c1 <- first() }()
	var holder int64
	select {
	case holder = <-entered:
	case err := <-c1:
		t.Fatalf("先行交易未到達拓撲鎖停點即結束：%v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("先行交易未到達拓撲鎖停點")
	}
	go func() { c2 <- second() }()
	if e.pg {
		require.Greater(t, holder, int64(0))
		waiter := probe.pid(t, 1)
		require.Equal(t, holder, probe.pid(t, 0), "先行交易的 pid 須等於第一次取鎖嘗試的 pid")
		require.NotEqual(t, holder, waiter)
		e.proveWaiting(t, waiter, holder)
	} else {
		select {
		case err := <-c2:
			open()
			<-c1
			t.Fatalf("後行交易在先行交易放行前完成：%v", err)
		case <-time.After(200 * time.Millisecond):
		}
	}
	open()
	return <-c1, <-c2
}

func (e *nodeRaceEnv) orphanBindings(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Raw(`SELECT count(*) FROM role_binding_nodes rbn
		JOIN asset_groups g ON g.id = rbn.node_id WHERE g.deleted_at IS NOT NULL`).Scan(&n).Error)
	return n
}

func (e *nodeRaceEnv) bindingRows(t *testing.T, node uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.RoleBindingNode{}).Where("node_id = ?", node).Count(&n).Error)
	return n
}

func (e *nodeRaceEnv) nodeDeleted(t *testing.T, id uint) bool {
	t.Helper()
	var g model.AssetGroup
	require.NoError(t, e.db.Unscoped().First(&g, id).Error)
	return g.DeletedAt.Valid
}

func noDeadlock(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			assert.NotContains(t, err.Error(), "40P01")
			assert.NotContains(t, err.Error(), "deadlock detected")
		}
	}
}

func (e *nodeRaceEnv) count(assignFirst bool) {
	if !e.pg {
		return
	}
	if assignFirst {
		e.confirmedAssignFirst++
	} else {
		e.confirmedDeleteFirst++
	}
}

func TestScopedBindingNodeRace(t *testing.T) {
	e := newNodeRaceEnv(t)
	op := func(uid uint, node uint) func() error {
		return func() error {
			_, err := e.assign(uid, []string{"assetmgr"}, map[string]RoleNodesValue{"assetmgr": nodesOf(node)})
			return err
		}
	}

	for _, path := range []struct {
		name   string
		rounds int
	}{{"direct", nodeRaceRounds}, {"group", 10}} {
		t.Run(path.name+"_assign_vs_delete_node", func(t *testing.T) {
			for i := 0; i < path.rounds; i++ {
				assignFirst := i%2 == 0
				e.seq++
				node := e.node(t, fmt.Sprintf("race-%s-%d", path.name, e.seq))
				var assign func() error
				var user uint
				if path.name == "direct" {
					user = e.mkUser(t, fmt.Sprintf("race-u-%d", e.seq))
					assign = op(user, node)
				} else {
					user = e.mkUser(t, fmt.Sprintf("race-gm-%d", e.seq))
					gid := e.group(t, fmt.Sprintf("race-g-%d", e.seq), user)
					rid := e.rid(t, "assetmgr")
					assign = func() error {
						_, err := e.svc.ReplaceRoleBindings(e.op(e.admin), gid, GroupRoleBindingsRequest{
							RoleIDs: []uint{rid}, RoleNodes: map[uint]RoleNodesValue{rid: nodesOf(node)}})
						return err
					}
				}
				del := func() error { return e.deleteNode(node) }
				var aErr, dErr error
				if assignFirst {
					aErr, dErr = e.runOrdered(t, assign, del)
				} else {
					dErr, aErr = e.runOrdered(t, del, assign)
				}
				e.count(assignFirst)
				noDeadlock(t, aErr, dErr)
				if assignFirst {
					require.NoError(t, aErr, "round %d", i)
					var ref *asset.NodeScopeReferencedError
					require.True(t, errors.As(dErr, &ref), "指派先提交：刪除回被引用，得到 %v", dErr)
					assert.False(t, e.nodeDeleted(t, node))
					assert.EqualValues(t, 1, e.bindingRows(t, node))
				} else {
					require.NoError(t, dErr, "round %d", i)
					assertCode(t, aErr, apierror.CodeValidationRoleBindingNodesInvalid)
					assert.True(t, e.nodeDeleted(t, node))
					assert.Zero(t, e.bindingRows(t, node), "刪除先提交：沒有指向已刪節點的新指派")
				}
				// 每輪恰一方成功
				assert.Equal(t, 1, boolInt(aErr == nil)+boolInt(dErr == nil), "round %d 恰一方成功", i)
			}
			assert.Zero(t, e.orphanBindings(t), "結束時沒有指向已刪節點的指派")
		})
	}

	// 並存降為僅映射（改回全域並清節點列）走對象鎖與拓撲鎖：兩種先後都不留孤兒列。
	t.Run("demotion_reset_vs_delete_node", func(t *testing.T) {
		channel := model.RoleMappingChannelKindProvider + ":1"
		for i := 0; i < 10; i++ {
			assignFirst := i%2 == 0
			e.seq++
			node := e.node(t, fmt.Sprintf("race-demote-%d", e.seq))
			user := e.mkUser(t, fmt.Sprintf("race-d-%d", e.seq))
			role := e.rid(t, "assetmgr")
			require.NoError(t, op(user, node)())
			require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
				_, err := GrantMappedRole(tx, user, role, channel, time.Now())
				return err
			}))
			demote := func() error {
				_, err := e.assign(user, []string{}, nil)
				return err
			}
			del := func() error { return e.deleteNode(node) }
			var aErr, dErr error
			if assignFirst {
				aErr, dErr = e.runOrdered(t, demote, del)
			} else {
				dErr, aErr = e.runOrdered(t, del, demote)
			}
			e.count(assignFirst)
			noDeadlock(t, aErr, dErr)
			require.NoError(t, aErr, "round %d", i)
			src, exists, err := model.UserRoleSourceOf(e.db, user, role)
			require.NoError(t, err)
			require.True(t, exists)
			assert.Equal(t, model.RoleSourceMapped, src)
			kind, ids := e.userScope(t, user, "assetmgr")
			assert.Equal(t, model.ScopeKindGlobal, kind)
			assert.Empty(t, ids)
			if assignFirst {
				require.NoError(t, dErr, "降級先提交：引用已清，刪除成功")
				assert.True(t, e.nodeDeleted(t, node))
			} else {
				var ref *asset.NodeScopeReferencedError
				require.True(t, errors.As(dErr, &ref), "刪除先提交：節點仍被引用，得到 %v", dErr)
				assert.False(t, e.nodeDeleted(t, node))
			}
			assert.Zero(t, e.bindingRows(t, node))
		}
		assert.Zero(t, e.orphanBindings(t))
	})

	t.Run("delete_node_only_referenced_by_deleted_user", func(t *testing.T) {
		node, other := e.node(t, "race-ref-node"), e.node(t, "race-ref-other")
		u, keep := e.mkUser(t, "race-ref-u"), e.mkUser(t, "race-ref-keep")
		require.NoError(t, op(u, node)())
		require.NoError(t, op(keep, other)())
		var ref *asset.NodeScopeReferencedError
		err := e.deleteNode(node)
		require.True(t, errors.As(err, &ref))
		assert.Equal(t, 1, ref.References.Count)

		_, err = e.users.DeleteWithSummaryBy(e.op(e.admin), u)
		require.NoError(t, err)
		has, err := authz.SubjectHasBindingNodes(e.db, model.BindingSubjectUser, u)
		require.NoError(t, err)
		assert.False(t, has, "使用者刪除同交易清除其節點範圍列")
		hasKeep, err := authz.SubjectHasBindingNodes(e.db, model.BindingSubjectUser, keep)
		require.NoError(t, err)
		assert.True(t, hasKeep, "他人的節點範圍列不受影響")
		refs, err := authz.NewNodeScopeReferenceReader().NodeScopeReferences(e.db, node)
		require.NoError(t, err)
		assert.Zero(t, refs.Count, "節點引用查詢回 0 筆")
		require.NoError(t, e.deleteNode(node))
		assert.True(t, e.nodeDeleted(t, node))
	})

	t.Run("reader_not_injected_rejects_without_writes", func(t *testing.T) {
		bare := NewUserService(e.db, authz.NewAssetAuthorizationService(e.db))
		bare.SetAssignmentGuard(NewAssignmentGuard(FullCatalog()))
		node, u := e.node(t, "race-noreader"), e.mkUser(t, "race-noreader-u")
		v0 := e.version(t)
		_, err := bare.AssignRolesBy(e.op(e.admin), u, []string{"assetmgr"},
			DirectAssignOptions{RoleNodes: map[string]RoleNodesValue{"assetmgr": nodesOf(node)}})
		assertCode(t, err, apierror.CodeValidationRoleBindingScopeUnsupported)
		assert.Equal(t, v0, e.version(t), "零寫入：權限版本不變")
		var n int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Where("user_id = ?", u).Count(&n).Error)
		assert.Zero(t, n)
		assert.Zero(t, e.bindingRows(t, node))
	})

	if e.pg && !t.Failed() {
		require.Equal(t, "postgres", e.db.Dialector.Name())
		require.Greater(t, e.confirmedAssignFirst, 0)
		require.Greater(t, e.confirmedDeleteFirst, 0)
		fmt.Printf("EVIDENCE dialect=postgres confirmed_assign_first=%d confirmed_delete_first=%d\n",
			e.confirmedAssignFirst, e.confirmedDeleteFirst)
		t.Log("EVIDENCE dialect=postgres")
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
