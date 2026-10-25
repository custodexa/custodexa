package authz

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// UserCredentialLockForProbeTest identity 的使用者憑證鎖入口。authz 的內部測試不能 import identity
// （identity 依賴 authz），由外部測試套件 lock_order_probe_bridge_test.go 於 init 注入
// identity.WithUserCredentialLock：傳入交易句柄時它以 SAVEPOINT 開巢狀交易，在同一條資料庫交易內
// 呼叫 withUserCredentialLockTx，守衛看到的是同一筆交易。
var UserCredentialLockForProbeTest func(db *gorm.DB, userID uint, fn func(tx *gorm.DB) error) error

var errProbeRollback = errors.New("probe test rollback")

// probeCollector 測試替身：收集守衛回報的違規，不讓套件失敗。
type probeCollector struct {
	mu  sync.Mutex
	got []LockOrderViolation
}

func (c *probeCollector) add(v LockOrderViolation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, v)
}

func (c *probeCollector) list() []LockOrderViolation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]LockOrderViolation(nil), c.got...)
}

type ruleIDs struct {
	Rule string
	IDs  []uint
}

func summarize(vs []LockOrderViolation) []ruleIDs {
	out := make([]ruleIDs, 0, len(vs))
	for _, v := range vs {
		out = append(out, ruleIDs{Rule: v.Rule, IDs: v.IDs})
	}
	return out
}

// withProbeGuard 安裝一份新的守衛替身、執行 fn、還原，回傳 fn 期間收到的違規。
func withProbeGuard(fn func()) []LockOrderViolation {
	c := &probeCollector{}
	restore := SetLockOrderGuardForTest(c.add)
	func() {
		defer restore()
		fn()
	}()
	return c.list()
}

// fakeTxConn 只用於守衛規則的單元案例：讓句柄看起來在交易內（實作 TxCommitter），不連資料庫。
type fakeTxConn struct{ gorm.ConnPool }

func (*fakeTxConn) Commit() error   { return nil }
func (*fakeTxConn) Rollback() error { return nil }

func fakeTxHandle(dialector gorm.Dialector) *gorm.DB {
	return &gorm.DB{Config: &gorm.Config{Dialector: dialector}, Statement: &gorm.Statement{ConnPool: &fakeTxConn{}}}
}

func runLockOrderProbeSubtests(t *testing.T) {
	t.Run("lock_order_probe_fires", func(t *testing.T) {
		require.NotNil(t, UserCredentialLockForProbeTest, "identity 憑證鎖入口未注入（lock_order_probe_bridge_test.go）")
		db := newPrincipalDB(t)
		ucl := func(t *testing.T, tx *gorm.DB, id uint) {
			t.Helper()
			require.NoError(t, UserCredentialLockForProbeTest(tx, id, func(*gorm.DB) error { return nil }))
		}
		topo := func(t *testing.T, tx *gorm.DB) {
			t.Helper()
			require.NoError(t, LockScopeTopologyTx(tx))
		}
		// inTx 在一筆會回滾的交易內執行 fn，回傳守衛替身收到的違規。
		inTx := func(t *testing.T, fn func(tx *gorm.DB)) []ruleIDs {
			t.Helper()
			var vs []LockOrderViolation
			vs = withProbeGuard(func() {
				err := db.Transaction(func(tx *gorm.DB) error {
					fn(tx)
					return errProbeRollback
				})
				require.ErrorIs(t, err, errProbeRollback)
			})
			for _, v := range vs {
				assert.NotEmpty(t, v.Stack, "違規須帶取鎖位置")
			}
			return summarize(vs)
		}
		one := func(rule string, ids ...uint) []ruleIDs { return []ruleIDs{{Rule: rule, IDs: ids}} }
		none := []ruleIDs{}

		t.Run("lock_user_rows_after_topology", func(t *testing.T) {
			assert.Equal(t, one(LockRuleTopologyThenUser, 5), inTx(t, func(tx *gorm.DB) {
				topo(t, tx)
				require.NoError(t, lockUserRows(tx, []uint{5}))
			}), "已取拓撲鎖後取帳號列鎖：記一筆")
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				require.NoError(t, lockUserRows(tx, []uint{5}))
			}), "未取拓撲鎖：不記")
		})
		t.Run("user_id_descending", func(t *testing.T) {
			assert.Equal(t, one(LockRuleUserIDDescending, 10), inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "20 之後取 10：記一筆編號倒退")
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 10)
				ucl(t, tx, 20)
			}), "10、20 升冪：不記")
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 20)
				ucl(t, tx, 20)
			}), "同一使用者重入：不記")
		})
		t.Run("held_user_after_topology", func(t *testing.T) {
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 10)
				topo(t, tx)
				ucl(t, tx, 10)
			}), "已持有者在拓撲鎖之後重入：不記")
			assert.Equal(t, one(LockRuleTopologyThenUser, 11), inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 10)
				topo(t, tx)
				ucl(t, tx, 11)
			}), "拓撲鎖之後取新使用者：記一筆")
		})
		t.Run("late_joiner_numbering", func(t *testing.T) {
			const g = 7
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				LockOrderExemptLateJoinerHook()(tx, LateJoinerGroupDelete, g, 10)
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "登記（群組 g、使用者 10）後依 20、10：不記")
			assert.Equal(t, one(LockRuleUserIDDescending, 10), inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "未登記：記一筆")
			assert.Equal(t, one(LockRuleUserIDDescending, 10), inTx(t, func(tx *gorm.DB) {
				LockOrderExemptLateJoinerHook()(tx, LateJoinerGroupDelete, g, 11)
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "登記的是另一位使用者：記一筆")
			assert.Equal(t, one(LockRuleUserIDDescending, 10), inTx(t, func(tx *gorm.DB) {
				// 另一筆交易的登記不影響本交易（巢狀交易仍是同一筆，故另開連線外的句柄做對照）
				other := fakeTxHandle(tx.Dialector)
				LockOrderExemptLateJoinerHook()(other, LateJoinerGroupDelete, g, 10)
				LockOrderExemptMappingRevocationHook()(other)
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "登記在另一筆交易：記一筆")
		})
		t.Run("late_joiner_topology", func(t *testing.T) {
			const g = 7
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				topo(t, tx)
				LockOrderExemptLateJoinerHook()(tx, LateJoinerGroupRoleReplace, g, 10)
				ucl(t, tx, 10)
			}), "拓撲鎖之後對已登記的使用者取鎖：不記")
			assert.Equal(t, one(LockRuleTopologyThenUser, 10), inTx(t, func(tx *gorm.DB) {
				topo(t, tx)
				ucl(t, tx, 10)
			}), "未登記：記一筆")
			assert.Equal(t, one(LockRuleTopologyThenUser, 10), inTx(t, func(tx *gorm.DB) {
				topo(t, tx)
				LockOrderExemptLateJoinerHook()(tx, LateJoinerGroupRoleReplace, g, 11)
				ucl(t, tx, 10)
			}), "登記的是另一位使用者：記一筆")
			assert.Equal(t, one(LockRuleTopologyThenUser, 10), inTx(t, func(tx *gorm.DB) {
				topo(t, tx)
				LockOrderExemptLateJoinerHook()(tx, LateJoinerGroupDelete, g, 10)
				ucl(t, tx, 10)
			}), "群組刪除補取點只屬第一類：持拓撲鎖照常記")
		})
		t.Run("mapping_revocation", func(t *testing.T) {
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				LockOrderExemptMappingRevocationHook()(tx)
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "已標記映射撤銷：依 20、10 不記")
			assert.Equal(t, one(LockRuleUserIDDescending, 10), inTx(t, func(tx *gorm.DB) {
				ucl(t, tx, 20)
				ucl(t, tx, 10)
			}), "未標記：記一筆")
			assert.Equal(t, one(LockRuleTopologyThenUser, 10), inTx(t, func(tx *gorm.DB) {
				LockOrderExemptMappingRevocationHook()(tx)
				topo(t, tx)
				ucl(t, tx, 10)
			}), "映射撤銷標記不放行拓撲規則")
		})
		t.Run("group_lock_after_topology", func(t *testing.T) {
			probe := func(tx *gorm.DB) { LockOrderProbeHook()(tx, LockLayerGroup, 3) }
			assert.Equal(t, one(LockRuleTopologyThenUser, 3), inTx(t, func(tx *gorm.DB) {
				topo(t, tx)
				probe(tx)
			}), "拓撲鎖之後取群組列鎖：記一筆")
			assert.Equal(t, none, inTx(t, func(tx *gorm.DB) {
				probe(tx)
				topo(t, tx)
				probe(tx)
			}), "群組列鎖先於拓撲鎖、之後重入：不記")
		})
		t.Run("postgres_ua_followed_by_ur", func(t *testing.T) {
			pg := postgres.Dialector{Config: &postgres.Config{}}
			require.Equal(t, "postgres", pg.Name())
			run := func(d gorm.Dialector, fn func(tx *gorm.DB, probe LockOrderProbeFunc)) []ruleIDs {
				vs := withProbeGuard(func() { fn(fakeTxHandle(d), LockOrderProbeHook()) })
				return summarize(vs)
			}
			assert.Equal(t, none, run(pg, func(tx *gorm.DB, p LockOrderProbeFunc) {
				p(tx, LockLayerUserCredential, 10)
				p(tx, LockLayerUserRow, 10)
				p(tx, LockLayerUserCredential, 20)
				p(tx, LockLayerUserRow, 20)
			}), "每位先 Ua 後 Ur、升冪：不記")
			assert.Equal(t, one(LockRuleUaNotFollowedByUr, 20), run(pg, func(tx *gorm.DB, p LockOrderProbeFunc) {
				p(tx, LockLayerUserCredential, 10)
				p(tx, LockLayerUserCredential, 20)
				p(tx, LockLayerUserRow, 20)
			}), "Ua(10) 之後是 Ua(20)：記一筆")
			assert.Equal(t, one(LockRuleUaNotFollowedByUr, 11), run(pg, func(tx *gorm.DB, p LockOrderProbeFunc) {
				exempt := LockOrderExemptLateJoinerHook()
				exempt(tx, LateJoinerGroupRoleReplace, 7, 10)
				exempt(tx, LateJoinerGroupRoleReplace, 7, 11)
				LockOrderExemptMappingRevocationHook()(tx)
				p(tx, LockLayerUserCredential, 10)
				p(tx, LockLayerUserRow, 11)
			}), "豁免不放行「Ua 緊接 Ur」")
			assert.Equal(t, none, run(sqliteNameOnly{}, func(tx *gorm.DB, p LockOrderProbeFunc) {
				p(tx, LockLayerUserCredential, 10)
				p(tx, LockLayerUserCredential, 20)
			}), "SQLite 沒有帳號列鎖：不檢查此條")
			assert.Equal(t, none, run(pg, func(_ *gorm.DB, p LockOrderProbeFunc) {
				outside := &gorm.DB{Config: &gorm.Config{Dialector: pg}, Statement: &gorm.Statement{}}
				p(outside, LockLayerUserCredential, 20)
				p(outside, LockLayerUserCredential, 10)
			}), "交易外的句柄不登記")
		})
		t.Run("hooks_nil_without_guard", func(t *testing.T) {
			restore := SetLockOrderGuardForTest(nil)
			defer restore()
			assert.Nil(t, LockOrderProbeHook())
			assert.Nil(t, LockOrderExemptLateJoinerHook())
			assert.Nil(t, LockOrderExemptMappingRevocationHook())
			assert.Nil(t, loadTopologyLockAcquiredHook())
		})
		t.Run("topology_lock_acquired_hook", func(t *testing.T) {
			var seen []gorm.ConnPool
			restore := SetTopologyLockAcquiredHookForTest(func(tx *gorm.DB) { seen = append(seen, tx.Statement.ConnPool) })
			var conn gorm.ConnPool
			err := db.Transaction(func(tx *gorm.DB) error {
				conn = tx.Statement.ConnPool
				require.NoError(t, LockScopeTopologyTx(tx))
				return errProbeRollback
			})
			restore()
			require.ErrorIs(t, err, errProbeRollback)
			assert.Equal(t, []gorm.ConnPool{conn}, seen, "停點在取鎖後以同一交易呼叫一次")
			assert.Nil(t, loadTopologyLockAcquiredHook(), "還原後恢復為 nil")
		})
		t.Run("explicit_lock_sites_covered", runLockSiteCoverage)
	})
}

// sqliteNameOnly 只回報方言名稱的替身。
type sqliteNameOnly struct{ gorm.Dialector }

func (sqliteNameOnly) Name() string { return "sqlite" }
