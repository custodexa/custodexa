package authz

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// sqliteTopologyConn 開一條檔案型 SQLite 連線組（glebarez 驅動），busy timeout 在 DSN 以
// _pragma 明示，開好後讀回比對。每個句柄允許兩條實體連線，使「交易開著時另行讀 PRAGMA」不卡住。
func sqliteTopologyConn(t *testing.T, path string, busyMs int, wal bool) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)", path, busyMs)
	if wal {
		dsn += "&_pragma=journal_mode(WAL)"
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = sqlDB.Close() })

	var got int
	require.NoError(t, db.Raw("PRAGMA busy_timeout").Scan(&got).Error)
	require.Equal(t, busyMs, got, "busy_timeout 讀回必須等於 DSN 設定值")
	return db
}

// runSQLiteTopologyWriteLockCases 拓撲鎖在 SQLite 的實測：glebarez 是測試側唯一能執行的
// SQLite 驅動（mattn 需要 CGO，兩種映像都沒有編譯器，不跑）。
func runSQLiteTopologyWriteLockCases(t *testing.T) {
	for _, mode := range []struct {
		name string
		wal  bool
	}{{"rollback_journal", false}, {"wal", true}} {
		mode := mode
		t.Run(mode.name, func(t *testing.T) {
			const nShort = 2000 // 非預設值 5000
			path := filepath.Join(t.TempDir(), "topology.db")
			db1 := sqliteTopologyConn(t, path, 3000, mode.wal)
			db2 := sqliteTopologyConn(t, path, nShort, mode.wal)
			db3 := sqliteTopologyConn(t, path, 0, mode.wal)

			var journal string
			require.NoError(t, db1.Raw("PRAGMA journal_mode").Scan(&journal).Error)
			if mode.wal {
				require.Equal(t, "wal", strings.ToLower(journal))
			} else {
				require.Equal(t, "delete", strings.ToLower(journal))
			}
			t.Logf("journal_mode=%s", journal)

			// 只有檔案型多連線庫才算證據
			var dbFile struct {
				Seq  int
				Name string
				File string
			}
			require.NoError(t, db1.Raw("PRAGMA database_list").Scan(&dbFile).Error)
			require.NotEmpty(t, dbFile.File, "必須是檔案庫，不得是 :memory:")
			require.NotContains(t, path, "cache=shared")

			require.NoError(t, db1.AutoMigrate(&model.RoleBindingNode{}))
			require.NoError(t, db1.Exec("CREATE TABLE authz_state (id integer primary key, version integer not null)").Error)
			require.NoError(t, db1.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error)
			require.NoError(t, db1.Exec("CREATE TABLE topo_probe (id integer primary key, v integer not null)").Error)
			require.NoError(t, db1.Exec("INSERT INTO topo_probe (id, v) VALUES (1, 1)").Error)

			immediate := func() (time.Duration, error) {
				conn, err := db3.WithContext(context.Background()).DB()
				require.NoError(t, err)
				c, err := conn.Conn(context.Background())
				require.NoError(t, err)
				defer c.Close()
				start := time.Now()
				_, err = c.ExecContext(context.Background(), "BEGIN IMMEDIATE")
				d := time.Since(start)
				if err == nil {
					_, _ = c.ExecContext(context.Background(), "ROLLBACK")
				}
				return d, err
			}

			t.Run("S1_write_lock_held", func(t *testing.T) {
				tx1 := db1.Begin()
				require.NoError(t, tx1.Error)
				defer tx1.Rollback()                         // 已提交或已回滾時為 no-op
				require.NoError(t, LockScopeTopologyTx(tx1)) // 交易第一個語句
				d, err := immediate()
				require.Error(t, err, "鎖持有期間，另一連線的 BEGIN IMMEDIATE 必須立刻失敗")
				require.Contains(t, err.Error(), "SQLITE_BUSY")
				require.Less(t, d, 500*time.Millisecond)
				t.Logf("持鎖期間 BEGIN IMMEDIATE：err=%q 耗時=%s", err.Error(), d)
				require.NoError(t, tx1.Commit().Error)
				d, err = immediate()
				require.NoError(t, err, "提交後 BEGIN IMMEDIATE 成功")
				t.Logf("提交後 BEGIN IMMEDIATE：成功 耗時=%s", d)
			})

			t.Run("S2_first_statement_waits_and_rereads", func(t *testing.T) {
				tx1 := db1.Begin()
				require.NoError(t, tx1.Error)
				defer tx1.Rollback() // 已提交或已回滾時為 no-op
				require.NoError(t, LockScopeTopologyTx(tx1))
				type res struct {
					v   int
					err error
					at  time.Duration
				}
				done := make(chan res, 1)
				start := time.Now()
				go func() {
					tx2 := db2.Begin()
					if tx2.Error != nil {
						done <- res{err: tx2.Error}
						return
					}
					if err := LockScopeTopologyTx(tx2); err != nil {
						tx2.Rollback()
						done <- res{err: err, at: time.Since(start)}
						return
					}
					var v int
					err := tx2.Raw("SELECT v FROM topo_probe WHERE id = 1").Scan(&v).Error
					tx2.Rollback()
					done <- res{v: v, err: err, at: time.Since(start)}
				}()
				select {
				case r := <-done:
					t.Fatalf("連線 1 提交前連線 2 不得前進：%+v", r)
				case <-time.After(400 * time.Millisecond):
				}
				require.NoError(t, tx1.Exec("UPDATE topo_probe SET v = 2 WHERE id = 1").Error)
				require.NoError(t, tx1.Commit().Error)
				r := <-done
				require.NoError(t, r.err)
				require.Equal(t, 2, r.v, "鎖後重讀必須看到連線 1 提交的資料")
				require.Less(t, r.at, time.Duration(nShort)*time.Millisecond)
				t.Logf("等待後前進：耗時=%s 讀到 v=%d", r.at, r.v)
			})

			t.Run("S3_read_then_lock", func(t *testing.T) {
				// 連線 1 持鎖；連線 2 先讀再取鎖
				tx1 := db1.Begin()
				require.NoError(t, tx1.Error)
				defer tx1.Rollback() // 已提交或已回滾時為 no-op
				require.NoError(t, LockScopeTopologyTx(tx1))
				tx2 := db2.Begin()
				require.NoError(t, tx2.Error)
				defer tx2.Rollback() // 已提交或已回滾時為 no-op
				var v int
				require.NoError(t, tx2.Raw("SELECT v FROM topo_probe WHERE id = 1").Scan(&v).Error)
				start := time.Now()
				err := LockScopeTopologyTx(tx2)
				d := time.Since(start)
				require.Error(t, err, "先讀後取鎖遇競爭必須回錯，不得在舊資料上前進")
				require.Contains(t, err.Error(), "SQLITE_BUSY")
				require.Less(t, d, time.Duration(nShort)*time.Millisecond/2, "不經 busy handler，應遠小於 busy timeout")
				t.Logf("先讀後取鎖（持鎖者未提交）：err=%q 耗時=%s（busy_timeout=%dms）", err.Error(), d, nShort)
				tx2.Rollback()
				require.NoError(t, tx1.Rollback().Error)

				if mode.wal {
					// 變體：連線 2 先讀，連線 1 其後提交，連線 2 才取鎖
					tx2 := db2.Begin()
					require.NoError(t, tx2.Error)
					defer tx2.Rollback() // 已提交或已回滾時為 no-op
					require.NoError(t, tx2.Raw("SELECT v FROM topo_probe WHERE id = 1").Scan(&v).Error)
					tx1 := db1.Begin()
					require.NoError(t, tx1.Error)
					defer tx1.Rollback() // 已提交或已回滾時為 no-op
					require.NoError(t, LockScopeTopologyTx(tx1))
					require.NoError(t, tx1.Exec("UPDATE topo_probe SET v = v + 1 WHERE id = 1").Error)
					require.NoError(t, tx1.Commit().Error)
					start := time.Now()
					err := LockScopeTopologyTx(tx2)
					d := time.Since(start)
					require.Error(t, err)
					require.Contains(t, err.Error(), "(517)", "SQLITE_BUSY_SNAPSHOT")
					t.Logf("WAL 變體（其後被提交）：err=%q 耗時=%s", err.Error(), d)
					tx2.Rollback()
				}
			})
		})
	}
}
