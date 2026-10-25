package authz

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/testgate"
)

// 嚴格等待證明（共通規則）：後行 pid 在本 database、拓撲鎖 key 上有一列未取得，
// 先行 pid 在同一 key 上取得恰 1 列，且先行 pid 在後行 pid 的阻擋者之中。
const (
	topologyLockWaitSQL = `SELECT count(*) FROM pg_locks
 WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
   AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2 AND pid = ? AND NOT granted`
	topologyLockHeldSQL = `SELECT count(*) FROM pg_locks
 WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
   AND classid::bigint = ? AND objid::bigint = 1 AND objsubid = 2 AND pid = ? AND granted`
	blockedBySQL = `SELECT ?::int = ANY(pg_blocking_pids(?::int))`
)

// TestScopeDecideRereadAfterTopologyLockPG 序列化函式的 PostgreSQL 案例：
// 第二個交易取鎖前已讀過一次主體，在拓撲鎖上被第一個交易擋住；第一個交易持鎖時直接寫表
// 移除第二個交易主體唯一含該權限點的節點範圍指派並提交，第二個交易取鎖後的判定為能力拒絕
// （依取鎖後重讀的主體，不是鎖前讀到的主體）。
func TestScopeDecideRereadAfterTopologyLockPG(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	adminPool, _ := admin.DB()
	t.Cleanup(func() { _ = adminPool.Close() })
	schema := fmt.Sprintf("p3a_decide_reread_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { admin.Exec("DROP SCHEMA " + schema + " CASCADE") })

	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	pool, _ := db.DB()
	pool.SetMaxOpenConns(6)
	t.Cleanup(func() { _ = pool.Close() })
	require.Equal(t, "postgres", db.Dialector.Name())
	require.NoError(t, migrateWithAuthz(db,
		&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.Asset{}, &model.AssetNode{}, &model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{},
		&model.RolePermission{}))
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)

	cat, err := CatalogueWithScopedEnforcedForTest(PermAssetView, PermAssetUpdate)
	require.NoError(t, err)
	ev := NewScopeEvaluator(cat, asset.NewScopeTopologyReader())
	n1 := mkNode(t, db, "n1", nil)
	a1 := mkAsset(t, db, "a1")
	require.NoError(t, db.Create(&model.AssetNode{AssetID: a1.ID, NodeID: n1.ID}).Error)
	u := mkUser(t, db, "u-reread")
	role := mkCustomRole(t, db, "r-view", PermAssetView)
	assignDirect(t, db, u.ID, role.ID, model.ScopeKindNodes)
	// 另一筆不含 asset 權限點的全域指派：移除節點範圍指派後主體不是零指派（零指派視同一般使用者範本）
	assignDirect(t, db, u.ID, mkCustomRole(t, db, "r-audit", PermAuditView).ID, model.ScopeKindGlobal)
	require.NoError(t, db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u.ID, RoleID: role.ID, NodeID: n1.ID}).Error)
	target := AssetTarget(a1.ID)
	before, err := ev.Decide(db, &Principal{UserID: u.ID}, PermAssetView, target)
	require.NoError(t, err)
	require.Equal(t, wantAllow, before, "開跑前：唯一的節點範圍指派使主體在範圍內放行")

	// 第一個交易：取拓撲鎖（序列化點）
	t1 := db.Begin()
	require.NoError(t, t1.Error)
	t.Cleanup(func() { _ = t1.Rollback().Error })
	var pid1 int64
	require.NoError(t, t1.Raw("SELECT pg_backend_pid()").Scan(&pid1).Error)
	require.NoError(t, LockScopeTopologyTx(t1))

	// 第二個交易：取鎖前讀一次主體，再取鎖，取鎖後判定
	type outcome struct {
		res ScopeResult
		err error
	}
	pid2Ch := make(chan int64, 1)
	preRead := make(chan *Principal, 1)
	locked := make(chan struct{})
	done := make(chan outcome, 1)
	go func() {
		t2 := db.Begin()
		if t2.Error != nil {
			pid2Ch <- 0
			done <- outcome{err: t2.Error}
			return
		}
		defer func() { _ = t2.Rollback().Error }()
		var pid2 int64
		var iso string
		if err := t2.Raw("SELECT pg_backend_pid()").Scan(&pid2).Error; err != nil {
			pid2Ch <- 0
			done <- outcome{err: err}
			return
		}
		pid2Ch <- pid2
		if err := t2.Raw("SHOW transaction_isolation").Scan(&iso).Error; err != nil || iso != "read committed" {
			preRead <- nil
			done <- outcome{err: fmt.Errorf("第二個交易的隔離等級應為 read committed，實際 %q（%v）", iso, err)}
			return
		}
		p0, err := ResolveUserOnWithCatalogue(t2, cat, u.ID, TokenFacts{})
		if err != nil {
			preRead <- nil
			done <- outcome{err: err}
			return
		}
		preRead <- p0
		if err := LockScopeTopologyTx(t2); err != nil {
			done <- outcome{err: err}
			return
		}
		close(locked)
		res, err := ev.Decide(t2, p0, PermAssetView, target)
		done <- outcome{res: res, err: err}
	}()
	pid2 := <-pid2Ch
	require.NotZero(t, pid2)
	p0 := <-preRead
	require.NotNil(t, p0, "第二個交易的鎖前讀取失敗")
	require.True(t, p0.Has(PermAssetView), "鎖前讀到的主體仍持該權限點")
	t.Logf("EVIDENCE dialect=postgres pid1=%d pid2=%d isolation=read_committed pre_lock_has=%v", pid1, pid2, p0.Has(PermAssetView))

	// 嚴格等待證明：(甲) 後行 pid 在拓撲鎖 key 上 NOT granted；(乙) 先行 pid 是其阻擋者，且先行持有恰 1 列
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting, held int64
		var blocked bool
		require.NoError(t, db.Raw(topologyLockWaitSQL, TopologySerializationLockClass, pid2).Scan(&waiting).Error)
		require.NoError(t, db.Raw(topologyLockHeldSQL, TopologySerializationLockClass, pid1).Scan(&held).Error)
		require.NoError(t, db.Raw(blockedBySQL, pid1, pid2).Scan(&blocked).Error)
		if waiting == 1 && held == 1 && blocked {
			t.Logf("EVIDENCE waiting pid=%d granted=false blocked_by=%d holder_granted_rows=%d class=%d objid=1 objsubid=2",
				pid2, pid1, held, TopologySerializationLockClass)
			break
		}
		require.True(t, time.Now().Before(deadline), "5 秒內沒有證明第二個交易在等第一個交易的拓撲鎖（waiting=%d held=%d blocked=%v）", waiting, held, blocked)
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-locked:
		t.Fatal("第一個交易未提交，第二個交易不得取得拓撲鎖")
	case o := <-done:
		t.Fatalf("第二個交易在第一個交易提交前就結束：%+v", o)
	case <-time.After(200 * time.Millisecond):
	}

	// 第一個交易持序列化點直接寫表：移除第二個交易主體唯一含該權限點的節點範圍指派（範圍根與綁定節點列保留）
	r := t1.Exec("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", u.ID, role.ID)
	require.NoError(t, r.Error)
	require.EqualValues(t, 1, r.RowsAffected)
	require.NoError(t, t1.Commit().Error)

	var o outcome
	select {
	case o = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("第一個交易提交後，第二個交易沒有在 10 秒內完成判定")
	}
	require.NoError(t, o.err)
	assert.Equal(t, wantNoCap, o.res, "取鎖後依重讀的主體：能力拒絕，不是鎖前讀到的主體")
	t.Logf("EVIDENCE after_lock outcome=%v reason=%v", o.res.Outcome, o.res.Reason)

	// 對照：鎖前讀到的主體在提交後的拓撲上仍會放行，證明本案有鑑別力
	stale, _, err := ev.decideOn(db, p0, PermAssetView, target)
	require.NoError(t, err)
	assert.Equal(t, wantAllow, stale, "沿用鎖前主體會放行，Decide 不得沿用它")
}
