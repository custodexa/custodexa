package identity

import (
	"math"
	"regexp"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// namedDialector 只改 Name()，用來模擬沒有互斥實作的 dialect。
type namedDialector struct {
	gorm.Dialector
	name string
}

func (d namedDialector) Name() string { return d.name }

var userRowLockSQLRe = regexp.MustCompile(`(?i)\bFROM\s+"?users"?\b.*\bFOR\s+(NO KEY )?UPDATE\b`)

func openSQLiteForLockTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	return db
}

// TestUserRowLockPrimitive 驗使用者層鎖的最小單元：users 列鎖 primitive、單人 helper 與
// 多人預取的值域、順序、軟刪與不存在列、dialect 行為。
func TestUserRowLockPrimitive(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		db := openSQLiteForLockTest(t)

		t.Run("range_rejected_before_callback", func(t *testing.T) {
			called := false
			err := WithUserCredentialLock(db, uint(math.MaxUint32)+1, func(*gorm.DB) error {
				called = true
				return nil
			})
			require.Error(t, err)
			require.False(t, called)
		})

		t.Run("callback_runs_without_users_row_lock", func(t *testing.T) {
			var stmts []string
			require.NoError(t, db.Callback().Raw().After("gorm:raw").Register("row_lock_primitive_sqlite", func(tx *gorm.DB) {
				stmts = append(stmts, tx.Statement.SQL.String())
			}))
			defer db.Callback().Raw().Remove("row_lock_primitive_sqlite")
			called := false
			require.NoError(t, WithUserCredentialLock(db, 7, func(*gorm.DB) error {
				called = true
				return nil
			}))
			require.True(t, called, "SQLite 下 callback 必須執行")
			for _, s := range stmts {
				require.False(t, userRowLockSQLRe.MatchString(s), "SQLite 不得發出 users 列鎖語句：%s", s)
			}
			// 預取在非 postgres 為 no-op：不回錯、不發任何語句
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
				return lockUsersCredentialUpfrontTx(tx, []uint{3, 1, 3, 2})
			}))
			for _, s := range stmts {
				require.False(t, userRowLockSQLRe.MatchString(s), "預取在 SQLite 不得發出 users 列鎖語句：%s", s)
			}
		})
	})

	t.Run("unknown_dialect", func(t *testing.T) {
		db := openSQLiteForLockTest(t)
		db.Dialector = namedDialector{Dialector: db.Dialector, name: "mystery"}
		called := false
		err := WithUserCredentialLock(db, 1, func(*gorm.DB) error {
			called = true
			return nil
		})
		require.Error(t, err)
		require.False(t, called, "未知 dialect 必須拒絕且不執行受保護區段")
	})

	t.Run("postgres", func(t *testing.T) {
		e := newLockOrderEnv(t)
		a := e.humanUser(t, "lo-prim-a")
		b := e.humanUser(t, "lo-prim-b")
		c := e.humanUser(t, "lo-prim-c")
		require.Less(t, a, b)
		require.Less(t, b, c)
		class := int64(userCredentialLockClass)

		t.Run("range_validated_before_any_lock", func(t *testing.T) {
			var held int64 = -1
			err := e.dbA.Transaction(func(tx *gorm.DB) error {
				// 合法的 a 排在越界值之前：驗句要求「先驗完整個輸入」，a 也不得被取鎖
				lockErr := lockUsersCredentialUpfrontTx(tx, []uint{a, uint(math.MaxUint32) + 1})
				require.Error(t, lockErr)
				require.NoError(t, tx.Raw(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND classid = ?`, class).Scan(&held).Error)
				return lockErr
			})
			require.Error(t, err)
			require.EqualValues(t, 0, held, "越界輸入被拒時本交易不得持有任何使用者憑證 advisory 鎖")
			t.Logf("EVIDENCE dialect=postgres subcase=user_row_lock_primitive/range held_advisory=%d", held)
		})

		t.Run("dedupe_and_ascending_pairs", func(t *testing.T) {
			get, stopSQL := collectSQL(e.dbA, "row_lock_primitive_order")
			require.NoError(t, e.dbA.Transaction(func(tx *gorm.DB) error {
				return lockUsersCredentialUpfrontTx(tx, []uint{c, a, c, b})
			}))
			stopSQL()
			var seq []string
			for _, r := range get() {
				s := r.sql
				if strings.Contains(s, "SAVEPOINT") {
					continue
				}
				ids := numericVars(r.vars)
				switch {
				case isUserAdvisory(s, r.vars):
					require.Len(t, ids, 2)
					seq = append(seq, "adv:"+itoa(ids[1]))
				case userRowLockSQLRe.MatchString(s):
					require.Len(t, ids, 1)
					require.Contains(t, s, "FOR NO KEY UPDATE")
					seq = append(seq, "row:"+itoa(ids[0]))
				default:
					seq = append(seq, "other:"+s)
				}
			}
			want := []string{"adv:" + itoa(a), "row:" + itoa(a), "adv:" + itoa(b), "row:" + itoa(b), "adv:" + itoa(c), "row:" + itoa(c)}
			require.Equal(t, want, seq, "每位一組（advisory、列鎖），去重後依編號升冪，組間沒有其他使用者的鎖語句")
			t.Logf("EVIDENCE dialect=postgres subcase=user_row_lock_primitive/order sequence=%v", seq)
		})

		t.Run("soft_deleted_locked_missing_ignored", func(t *testing.T) {
			require.NoError(t, e.dbA.Exec("UPDATE users SET deleted_at = now() WHERE id = ?", b).Error)
			missing := c + 1000
			ran := false
			require.NoError(t, e.dbA.Transaction(func(tx *gorm.DB) error {
				if err := withUserCredentialLockTx(tx, b, func(*gorm.DB) error {
					// 另一連線對同一列 NOWAIT：已軟刪的列仍被鎖住
					probe := e.dbB.Transaction(func(tx2 *gorm.DB) error {
						return tx2.Exec(`SELECT id FROM users WHERE id = ? FOR NO KEY UPDATE NOWAIT`, b).Error
					})
					require.Error(t, probe)
					require.Contains(t, probe.Error(), "55P03", "軟刪列必須被鎖住（負向探測，不是死結證據）")
					return nil
				}); err != nil {
					return err
				}
				return withUserCredentialLockTx(tx, missing, func(*gorm.DB) error {
					ran = true
					return nil
				})
			}))
			require.True(t, ran, "不存在的編號不回錯，callback 照常執行")
			t.Logf("EVIDENCE dialect=postgres subcase=user_row_lock_primitive/soft_deleted probe_sqlstate=55P03 missing_user_callback_ran=%v", ran)
		})

		t.Run("provider_only_takes_no_users_row_lock", func(t *testing.T) {
			p := e.mappingProvider(t, "lo-prim-provider")
			get, stopSQL := collectSQL(e.dbA, "row_lock_primitive_provider")
			require.NoError(t, WithOIDCProviderLock(e.dbA, p.ID, func(*gorm.DB) error { return nil }))
			stopSQL()
			providerLocks := 0
			for _, r := range get() {
				require.False(t, userRowLockSQLRe.MatchString(r.sql), "只取 provider 鎖時不得發出 users 列鎖：%s", r.sql)
				if strings.Contains(r.sql, "oidc_providers") && strings.Contains(r.sql, "FOR UPDATE") {
					providerLocks++
				}
			}
			require.Equal(t, 1, providerLocks, "必須恰有一句 provider 列鎖")
			t.Logf("EVIDENCE dialect=postgres subcase=user_row_lock_primitive/provider_only provider_row_locks=%d users_row_locks=0", providerLocks)
		})
	})
}
