package asset_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/testgate"
)

// 批次操作的提交時重算與競態：預檢後被移出範圍、批次刪除與並發加掛範圍外節點的兩種提交順序、
// 鎖後重讀主體；PostgreSQL 跑法另驗撤權發生在鎖後，以及序列化鎖先於列鎖。
//
//	go test ./internal/modules/asset/ -run '^TestAssetBatchRecheckRace$' -count=1 -v
//	TEST_PG_DSN=... REQUIRE_INTEGRATION=1 go test ./internal/modules/asset/ -run '^TestAssetBatchRecheckRace$' -count=1 -v

// abRun 以動作名稱呼叫對應的批次服務；move 的目的節點固定為 sw-a。
func (e *swEnv) abRun(ctx context.Context, act string, ids []uint) error {
	var err error
	switch act {
	case "move":
		_, err = e.svc.BatchMove(ctx, ids, e.nodes["sw-a"])
	case "tags":
		_, err = e.svc.BatchAddTags(ctx, ids, []string{"race-tag"})
	default:
		_, err = e.svc.BatchDelete(ctx, ids)
	}
	return err
}

func (e *swEnv) abBatchDelete(actor uint, ids ...uint) func() error {
	return func() error { return e.abRun(e.ctx(actor), "delete", ids) }
}

// assertBatchDecisions 受限主體每筆刪除裁決：成功者裁決當下不得有範圍外歸屬；被拒者裁決當下須已有範圍外歸屬。
func assertBatchDecisions(t *testing.T, e *swEnv, wantRejected bool) {
	t.Helper()
	ds := e.rec.decisions(e.manager, asset.AssetWriteDelete)
	require.NotEmpty(t, ds)
	rejected := false
	for _, d := range ds {
		t.Logf("decision actor=manager op=delete current=%v err=%v", e.names(d.current), d.err)
		if d.err == nil {
			assert.Equal(t, []string{"sw-a"}, e.names(d.current), "裁決成功時歸屬只有範圍內的 sw-a")
			continue
		}
		rejected = true
		assert.Contains(t, e.names(d.current), "sw-b", "拒絕只應發生在已有範圍外歸屬時")
	}
	assert.Equal(t, wantRejected, rejected)
}

func TestAssetBatchRecheckRace(t *testing.T) {
	for _, act := range []string{"move", "tags", "delete"} {
		t.Run("moved_out_after_flag_"+act, func(t *testing.T) {
			e := newSwEnv(t)
			x, y := e.asset("sw-rc-x", "sw-a"), e.asset("sw-rc-y", "sw-a")
			// 預檢（列表旗標）當下兩台皆可操作；另一交易隨後把 y 移到範圍外
			require.NoError(t, e.setNodes(e.super, y, "sw-b")())
			err := e.abRun(e.ctx(e.manager), act, []uint{x, y})
			requireUnavailable(t, err, 1, "提交時重算")
			assert.Equal(t, []string{"sw-a"}, e.mounted(x), "零變更")
			assert.Equal(t, []string{"sw-b"}, e.mounted(y))
			assert.Empty(t, e.tagsOf(x))
			assert.Empty(t, e.tagsOf(y))
			assert.Equal(t, 2, e.liveCount(x, y))
		})
	}

	t.Run("delete_vs_superadmin_mount", func(t *testing.T) {
		t.Run("mount_commits_first", func(t *testing.T) {
			e := newSwEnv(t)
			x, y := e.asset("sw-rc-x", "sw-a"), e.asset("sw-rc-y", "sw-a")
			errMount, errDel := runOrdered(t, e.setNodes(e.super, y, "sw-a", "sw-b"), e.abBatchDelete(e.manager, x, y))
			require.NoError(t, errMount)
			requireBlocked(t, errDel, 1, "加掛先提交：批次刪除看到範圍外歸屬")
			assert.Equal(t, 2, e.liveCount(x, y), "兩台皆未刪")
			assert.Equal(t, []string{"sw-a", "sw-b"}, e.mounted(y))
			assertBatchDecisions(t, e, true)
		})
		t.Run("delete_commits_first", func(t *testing.T) {
			e := newSwEnv(t)
			x, y := e.asset("sw-rc-x", "sw-a"), e.asset("sw-rc-y", "sw-a")
			errDel, errMount := runOrdered(t, e.abBatchDelete(e.manager, x, y), e.setNodes(e.super, y, "sw-a", "sw-b"))
			require.NoError(t, errDel, "批次刪除先提交：裁決時只有範圍內歸屬")
			require.Error(t, errMount, "資產已不存在，後到的加掛失敗")
			assert.Zero(t, e.liveCount(x, y), "兩台皆刪除")
			assert.Empty(t, e.mounted(y), "asset_nodes 無新列")
			assertBatchDecisions(t, e, false)
		})
	})

	// 撤權發生在取得序列化鎖之後、重讀主體之前：依重讀結果整批單一 forbidden，零刪除。
	revokeAfterLock := func(t *testing.T, otherConn bool) {
		e := newSwEnv(t)
		u := e.scopedUser("sw-rc-rev", "sw-a")
		x, y := e.asset("sw-rc-x", "sw-a"), e.asset("sw-rc-y", "sw-a")
		ctx := asset.WithAssetBatchTestHooksForTest(e.ctx(u), &asset.AssetBatchTestHooks{
			AfterLock: func(tx *gorm.DB) error {
				db := tx
				if otherConn {
					db = e.db // 另一條連線提交撤銷；撤權不取序列化鎖，不被擋
				}
				return db.Where("user_id = ?", u).Delete(&model.UserRole{}).Error
			}})
		err := e.abRun(ctx, "delete", []uint{x, y})
		require.Error(t, err)
		var unavailable *asset.BatchItemsUnavailableError
		var blocked *asset.BatchOutOfScopeNodesError
		assert.False(t, errors.As(err, &unavailable), "是能力拒絕，不是批次無法操作：%v", err)
		assert.False(t, errors.As(err, &blocked), "不是受阻：%v", err)
		assert.Equal(t, 2, e.liveCount(x, y), "零刪除")
	}
	t.Run("revoke_after_lock_same_tx", func(t *testing.T) { revokeAfterLock(t, false) })
	t.Run("pg_revoke_after_lock", func(t *testing.T) {
		if os.Getenv(testgate.EnvPGDSN) == "" {
			t.Skip("另一條連線提交撤銷需要 PostgreSQL；SQLite 跑法以 revoke_after_lock_same_tx 涵蓋同一語意")
		}
		revokeAfterLock(t, true)
	})

	t.Run("lock_before_row_locks", func(t *testing.T) {
		if os.Getenv(testgate.EnvPGDSN) == "" {
			t.Skip("SQLite 沒有列鎖與 advisory 鎖：本子案例只在 PostgreSQL 跑法執行")
		}
		runBatchLockBeforeRowLocks(t)
	})

	if !t.Failed() && os.Getenv(testgate.EnvPGDSN) != "" {
		fmt.Println("EVIDENCE dialect=postgres")
		t.Log("EVIDENCE dialect=postgres")
	}
}

// runBatchLockBeforeRowLocks 另一條連線持拓撲序列化鎖時，三種批次各自啟動：先正向確認批次交易正在等這把鎖、
// 擋住它的正是持鎖連線，且第一筆列寫入尚未發生；再由第三條連線以 FOR UPDATE NOWAIT 探測所涉列皆未被鎖住。
func runBatchLockBeforeRowLocks(t *testing.T) {
	e := newSwEnv(t)
	require.Equal(t, "postgres", e.db.Dialector.Name(), "設了 PG 連線字串時不得回退 SQLite")
	moving := e.asset("sw-rc-mv", "sw-a", "sw-c")
	tagging := e.asset("sw-rc-tg", "sw-a")
	deleting := e.asset("sw-rc-del", "sw-a", "sw-c")

	pool := &swPidPool{DB: swOpenSQL(t, e.dsn)}
	pool.DB.SetMaxOpenConns(6)
	writerDB, err := gorm.Open(postgres.New(postgres.Config{Conn: pool}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	database.DB = writerDB // 寫入方走 pid 連線池；newSwEnv 的 Cleanup 還原
	side := swOpenSQL(t, e.dsn)
	side.SetMaxOpenConns(4)

	var written atomic.Bool
	hooked := func() context.Context {
		return asset.WithAssetBatchTestHooksForTest(e.ctx(e.super), &asset.AssetBatchTestHooks{
			BeforeItemWrite: func(*gorm.DB, int) error { written.Store(true); return nil }})
	}
	assetRow := `SELECT id FROM assets WHERE id = $1 FOR UPDATE NOWAIT`
	nodeRows := `SELECT asset_id FROM asset_nodes WHERE asset_id = $1 FOR UPDATE NOWAIT`
	cases := []struct {
		name   string
		run    func() error
		probes func(t *testing.T)
	}{
		{"move", func() error {
			_, err := e.svc.BatchMove(hooked(), []uint{moving}, e.nodes["sw-b"])
			return err
		}, func(t *testing.T) {
			swProbe(t, side, "搬移：asset_nodes 列", nodeRows, moving)
			swProbe(t, side, "搬移：資產列", assetRow, moving)
		}},
		{"tags", func() error {
			_, err := e.svc.BatchAddTags(hooked(), []uint{tagging}, []string{"lock-tag"})
			return err
		}, func(t *testing.T) {
			swProbe(t, side, "加標籤：資產列", assetRow, tagging)
		}},
		{"delete", func() error {
			_, err := e.svc.BatchDelete(hooked(), []uint{deleting})
			return err
		}, func(t *testing.T) {
			swProbe(t, side, "刪除：資產列", assetRow, deleting)
			swProbe(t, side, "刪除：asset_nodes 列", nodeRows, deleting)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			written.Store(false)
			holder := swHoldTopologyLock(t, side)
			pool.reset()
			done := make(chan error, 1)
			go func() { done <- c.run() }()
			released := false
			defer func() {
				if !released {
					holder.release(t)
					<-done
				}
			}()
			pid := swProveWaiting(t, side, pool, holder)
			t.Logf("batch %s pid=%d waiting on topology lock held by pid=%d", c.name, pid, holder.pid)
			assert.False(t, written.Load(), "等鎖期間第一筆列寫入尚未發生")
			c.probes(t)
			holder.release(t)
			released = true
			select {
			case err := <-done:
				require.NoError(t, err, "放行後批次完成")
			case <-time.After(30 * time.Second):
				t.Fatal("放行後批次未完成")
			}
			assert.True(t, written.Load(), "放行後確實寫入")
		})
	}
}
