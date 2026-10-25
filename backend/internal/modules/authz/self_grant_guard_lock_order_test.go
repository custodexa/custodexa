package authz

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

var selfGuardLockSQLRe = regexp.MustCompile(`(?is)\bFROM\s+"?users"?\b.*\bORDER BY\s+(?:"?users"?\.)?"?id"?(?:\s+ASC)?\s+FOR NO KEY UPDATE\b`)

// TestSelfGrantGuardLockOrder 驗規則主體守衛對使用者列的取鎖：一律依編號升冪、模式為
// FOR NO KEY UPDATE，與輸入順序無關；自我授權的判定結果不因取鎖方式而變。
func TestSelfGrantGuardLockOrder(t *testing.T) {
	// 判定結果：主體含本人、含本人擁有的 agent、皆不含，三種在兩種輸入順序下結果一致
	judge := func(t *testing.T, db *gorm.DB, operator uint, self, ownedAgent, other []uint) {
		t.Helper()
		g := SelfGrantGuard{}
		for _, ids := range [][]uint{self, reverseUints(self)} {
			require.ErrorIs(t, g.CheckRuleSubjects(db, operator, ids, nil), ErrSelfSubjectGrant, "主體含本人：%v", ids)
		}
		for _, ids := range [][]uint{ownedAgent, reverseUints(ownedAgent)} {
			require.ErrorIs(t, g.CheckRuleSubjects(db, operator, ids, nil), ErrSelfSubjectGrant, "主體含本人擁有的 agent：%v", ids)
		}
		for _, ids := range [][]uint{other, reverseUints(other)} {
			require.NoError(t, g.CheckRuleSubjects(db, operator, ids, nil), "主體皆不含：%v", ids)
		}
	}

	t.Run("sqlite", func(t *testing.T) {
		_, db := selfGuardEnv(t)
		// user 1 操作者；agent 4 為其擁有；user 2、3 他人
		judge(t, db, 1, []uint{1, 2}, []uint{4, 2}, []uint{2, 3})
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		adminPool, _ := admin.DB()
		t.Cleanup(func() { adminPool.Close() })
		schema := fmt.Sprintf("self_guard_lock_order_%d", time.Now().UnixNano())
		require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
		t.Cleanup(func() { admin.Exec("DROP SCHEMA " + schema + " CASCADE") })
		open := func() *gorm.DB {
			db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
			require.NoError(t, err)
			pool, _ := db.DB()
			t.Cleanup(func() { pool.Close() })
			return db
		}
		a, b := open(), open()
		require.NoError(t, a.AutoMigrate(&model.User{}))
		operator := uint(1)
		seed := []model.User{
			{ID: 1, Username: "operator", Active: true, Kind: model.KindHuman},
			{ID: 10, Username: "u10", Active: true, Kind: model.KindHuman},
			{ID: 20, Username: "u20", Active: true, Kind: model.KindHuman},
			{ID: 30, Username: "bot", Active: true, Kind: model.KindAgent, OwnerUserID: &operator},
		}
		for i := range seed {
			require.NoError(t, a.Create(&seed[i]).Error)
		}

		t.Run("judgement_matches_sqlite", func(t *testing.T) {
			judge(t, a, 1, []uint{1, 10}, []uint{30, 10}, []uint{10, 20})
		})

		t.Run("lock_statement_shape", func(t *testing.T) {
			for _, ids := range [][]uint{{20, 10}, {10, 20}} {
				var stmts []string
				name := fmt.Sprintf("self_guard_lock_order_%v", ids)
				require.NoError(t, a.Callback().Query().After("gorm:query").Register(name, func(tx *gorm.DB) {
					if tx.Statement != nil {
						stmts = append(stmts, tx.Statement.SQL.String())
					}
				}))
				err := SelfGrantGuard{}.CheckRuleSubjects(a, operator, ids, nil)
				require.NoError(t, a.Callback().Query().Remove(name))
				require.NoError(t, err)
				locking := 0
				for _, s := range stmts {
					if strings.Contains(s, "FOR ") {
						locking++
						require.Regexp(t, selfGuardLockSQLRe, s, "鎖定語句必須含 ORDER BY id 與 FOR NO KEY UPDATE：%s", s)
					}
				}
				require.Equal(t, 1, locking, "輸入 %v 必須恰有一句鎖定語句", ids)
				t.Logf("EVIDENCE dialect=postgres subcase=self_guard_lock_order input=%v locking_statements=%d", ids, locking)
			}
		})

		t.Run("opposite_orders_concurrently", func(t *testing.T) {
			restore := SetLockOrderHookForTest(func(point string, _ *gorm.DB, _ ...uint) {
				if point == "user_rows_locked" {
					time.Sleep(3 * time.Millisecond) // 拉長持鎖時間，讓兩邊確實交疊
				}
			})
			defer restore()
			const rounds = 25
			var wg sync.WaitGroup
			errs := make(chan error, 2*rounds)
			run := func(db *gorm.DB, ids []uint) {
				defer wg.Done()
				for i := 0; i < rounds; i++ {
					err := db.Transaction(func(tx *gorm.DB) error {
						return SelfGrantGuard{}.CheckRuleSubjects(tx, operator, ids, nil)
					})
					if err != nil {
						errs <- err
					}
				}
			}
			wg.Add(2)
			go run(a, []uint{10, 20})
			go run(b, []uint{20, 10})
			wg.Wait()
			close(errs)
			for err := range errs {
				var msg string
				if err != nil {
					msg = err.Error()
				}
				require.False(t, errors.Is(err, ErrSelfSubjectGrant) || strings.Contains(msg, "40P01"), "不得出現死結或誤判：%v", err)
				require.NoError(t, err)
			}
			t.Logf("EVIDENCE dialect=postgres subcase=self_guard_lock_order/opposite_orders rounds=%d sqlstate=none", rounds)
		})
	})
}

func reverseUints(in []uint) []uint {
	out := make([]uint, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
