package authz

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/testgate"
)

// 觀測查詢一律回單列 count，並限定 pid：GORM 的 Raw().Scan 遇零列時不寫入目的變數，
// 回多列的查詢重用切片會殘留上一次的結果，「提交後不含 holder」因而無法成立或被假性滿足。
// key 的限定（database、classid、objid=1、objsubid=2）沿用 scope_decide_reread_pg_test.go
// 的 topologyLockWaitSQL／topologyLockHeldSQL／blockedBySQL。
const topologyLockHolderActivitySQL = `SELECT coalesce(state, ''), backend_xid IS NULL FROM pg_stat_activity WHERE pid = ?`

// TestTopologyLockPG 拓撲鎖在 PostgreSQL 的取得物：兩參數 advisory 鎖（class, 1），
// 交易內才能取、交易結束釋放，第二個交易排隊等待。
func TestTopologyLockPG(t *testing.T) {
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	// holder 提交後連線回池須保持開啟：預設 idle 上限 2 會把它關掉，釋放就分不清是提交還是斷線
	sqlDB.SetMaxIdleConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })

	// 觀測者固定一條專屬連線，不與 holder／waiter 共用，pg_stat_activity 讀到的 holder 狀態才是 holder 自己的
	obsConn, err := sqlDB.Conn(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = obsConn.Close() })
	obs, err := gorm.Open(postgres.New(postgres.Config{Conn: obsConn}), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	var obsPID int64
	require.NoError(t, obs.Raw("SELECT pg_backend_pid()").Scan(&obsPID).Error)
	require.NotZero(t, obsPID)

	require.ErrorIs(t, LockScopeTopologyTx(db), ErrTopologyLockOutsideTx, "交易外取鎖必須回錯")

	held := func(pid int64) int64 {
		var n int64
		require.NoError(t, obs.Raw(topologyLockHeldSQL, TopologySerializationLockClass, pid).Scan(&n).Error)
		return n
	}

	holder := db.Begin()
	require.NoError(t, holder.Error)
	t.Cleanup(func() { _ = holder.Rollback().Error })
	var holderPID int64
	require.NoError(t, holder.Raw("SELECT pg_backend_pid()").Scan(&holderPID).Error)
	require.NotZero(t, holderPID)
	require.NotEqual(t, obsPID, holderPID)
	require.NoError(t, LockScopeTopologyTx(holder))
	require.EqualValues(t, 1, held(holderPID), "pg_locks 正向證據：holder 持有 (class, objid=1) 的 advisory 鎖恰 1 列")
	t.Logf("EVIDENCE granted pid=%d class=%d objid=1 objsubid=2 rows=1", holderPID, TopologySerializationLockClass)

	pidCh := make(chan int64, 1)
	done := make(chan error, 1)
	go func() {
		tx := db.Begin()
		if tx.Error != nil {
			pidCh <- 0
			done <- tx.Error
			return
		}
		var pid int64
		if err := tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
			_ = tx.Rollback().Error
			pidCh <- 0
			done <- err
			return
		}
		pidCh <- pid
		err := LockScopeTopologyTx(tx)
		_ = tx.Rollback().Error
		done <- err
	}()
	var waiterPID int64
	select {
	case waiterPID = <-pidCh:
	case <-time.After(10 * time.Second):
		t.Fatal("第二個交易 10 秒內未開始")
	}
	require.NotZero(t, waiterPID, "第二個交易開始失敗")
	require.NotEqual(t, holderPID, waiterPID)
	require.NotEqual(t, obsPID, waiterPID)

	// 等待證明：waiter 在本 key 上恰有 1 列未取得，且 holder 在其阻擋者之中（上限 10 秒）
	waitDeadline := time.After(10 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting int64
		var blocked bool
		require.NoError(t, obs.Raw(topologyLockWaitSQL, TopologySerializationLockClass, waiterPID).Scan(&waiting).Error)
		require.NoError(t, obs.Raw(blockedBySQL, holderPID, waiterPID).Scan(&blocked).Error)
		if waiting == 1 && blocked {
			break
		}
		select {
		case <-tick.C:
		case <-waitDeadline:
			t.Fatalf("第二個交易沒有在鎖上排隊：waiter pid=%d 未取得列 %d、被 holder 擋住=%v", waiterPID, waiting, blocked)
		}
	}
	require.EqualValues(t, 1, held(holderPID))
	t.Logf("EVIDENCE waiting pid=%d granted=false blocked_by=%d", waiterPID, holderPID)
	select {
	case err := <-done:
		t.Fatalf("holder 未提交，第二個交易不得前進：%v", err)
	case <-time.After(200 * time.Millisecond):
	}

	require.NoError(t, holder.Commit().Error)
	// 釋放與 COMMIT 同步完成（COMMIT 回應前鎖已釋放），提交回來後立刻量，不輪詢
	require.EqualValues(t, 0, held(holderPID), "提交後鎖釋放：holder pid 在本 key 上不得再有 granted 列")
	var state string
	var noXid bool
	require.NoError(t, obs.Raw(topologyLockHolderActivitySQL, holderPID).Row().Scan(&state, &noXid),
		"holder 連線提交後仍須存在：釋放來自交易結束，不是斷線")
	require.Equal(t, "idle", state, "holder 提交後回到 idle（不在交易中）")
	require.True(t, noXid, "holder 提交後不再持有交易 id")
	t.Logf("EVIDENCE released holder pid=%d granted_rows=0 state=%s backend_xid_null=%v observer_pid=%d", holderPID, state, noXid, obsPID)

	select {
	case err := <-done:
		require.NoError(t, err, "holder 提交後第二個交易應取得鎖")
	case <-time.After(10 * time.Second):
		t.Fatalf("holder 提交後第二個交易 10 秒內未取得鎖（holder 殘留列 %d）", held(holderPID))
	}
	require.EqualValues(t, 0, held(waiterPID), "第二個交易回滾後其鎖亦釋放")
}
