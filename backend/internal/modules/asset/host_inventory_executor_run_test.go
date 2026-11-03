package asset

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
)

// dialRecorder 取代撥號：只記下每次「會撥號」時的帳號名與時間，並以登入失敗結束。
type dialRecorder struct {
	mu    sync.Mutex
	users []string
	times []time.Time
}

func (d *dialRecorder) install(e *execInvEnv) {
	e.svc.collect = func(_ context.Context, _ uint, _ string, c *AssetCredentials, _ ssh.HostKeyCallback, _ string) (*invScanResult, *inventoryError) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.users = append(d.users, c.Username)
		d.times = append(d.times, time.Now())
		return nil, &inventoryError{Reason: model.InventoryLoginFailed}
	}
}

func (d *dialRecorder) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.users)
}

func lastScanReason(t *testing.T, e *execInvEnv) string {
	t.Helper()
	var s model.HostAccountScan
	require.NoError(t, e.db.Where("asset_id = ?", e.assetID).Order("id DESC").First(&s).Error)
	return s.FailureReason
}

// advanceEffectiveVersion 複製就位版本並讓掛載指向它，等同整組輪替完成後版本前進。
func advanceEffectiveVersion(t *testing.T, e *execInvEnv) uint {
	t.Helper()
	m := e.mount(t)
	var v model.CredentialSecretVersion
	require.NoError(t, e.db.First(&v, *m.EffectiveVersionID).Error)
	v.ID, v.VersionNo = 0, v.VersionNo+100
	require.NoError(t, e.db.Create(&v).Error)
	require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", m.ID).Update("effective_version_id", v.ID).Error)
	return v.ID
}

func TestInventoryExecutorExecution(t *testing.T) {
	run := func(t *testing.T, e *execInvEnv) {
		t.Helper()
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
	}
	t.Run("正常只以專用帳號撥號", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		run(t, e)
		require.Equal(t, 1, rec.count())
		assert.Equal(t, delegExecutorUser, rec.users[0])
		assert.Zero(t, e.fetch.calls.Load(), "不取預設帳號密文")
		assert.Equal(t, model.InventoryLoginFailed, lastScanReason(t, e))
	})
	t.Run("等待期間清除", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		e.svc.beforeExecutorLock = func() { require.NoError(t, e.db.Delete(&model.AssetAccount{}, e.mount(t).ID).Error) }
		run(t, e)
		assert.Zero(t, rec.count())
		assert.Equal(t, model.InventoryExecutorChanged, lastScanReason(t, e))
		assert.Zero(t, e.fetch.calls.Load(), "預設帳號零嘗試")
	})
	t.Run("等待期間輪替版本前進則用新版本", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		var newVer uint
		e.svc.beforeExecutorLock = func() { newVer = advanceEffectiveVersion(t, e) }
		run(t, e)
		require.Equal(t, 1, rec.count())
		assert.NotZero(t, newVer)
		assert.Equal(t, model.InventoryLoginFailed, lastScanReason(t, e))
	})
	t.Run("等待期間轉為輪替中", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		e.svc.beforeExecutorLock = func() {
			require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.mount(t).CredentialID).Update("active_rotation_id", 7).Error)
		}
		run(t, e)
		assert.Zero(t, rec.count())
		assert.Equal(t, model.InventoryExecutorBusy, lastScanReason(t, e))
	})
	t.Run("帳號名含不允許字元", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		e.svc.beforeExecutorLock = func() {
			require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", e.mount(t).ID).Update("username", "bad:name").Error)
		}
		run(t, e)
		assert.Zero(t, rec.count())
		assert.Equal(t, model.InventoryExecutorUnavailable, lastScanReason(t, e))
	})
	t.Run("以預設帳號發起後新設專用帳號仍用預設帳號", func(t *testing.T) {
		e := newExecInvEnv(t, false)
		rec := &dialRecorder{}
		rec.install(e)
		// 佔滿工作池，讓執行排在發起之後
		for range cap(e.svc.slots) {
			e.svc.slots <- struct{}{}
		}
		s, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		require.Equal(t, model.HostAccountIdentityDefault, s.IdentityMode)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		for range cap(e.svc.slots) {
			<-e.svc.slots
		}
		e.svc.Wait()
		require.Equal(t, 1, rec.count())
		assert.Equal(t, delegTargetUser, rec.users[0], "以發起時記下的預設帳號登入")
		assert.Zero(t, e.resolve.calls.Load(), "不碰專用帳號取密")
	})
	t.Run("執行開頭重讀掛載出錯", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		// 相符查詢第 1 次是發起，第 2 次是執行開頭的重讀
		inj := installExecutorInjector(t, e.db, 2)
		inj.armed.Store(true)
		run(t, e)
		inj.armed.Store(false)
		assert.Equal(t, model.InventoryInterrupted, lastScanReason(t, e))
		assert.Zero(t, rec.count())
		assert.Zero(t, e.fetch.calls.Load())
		assert.Zero(t, e.resolve.calls.Load(), "沒走到解封")
		assert.EqualValues(t, 2, inj.matched.Load(), "相符查詢：發起 1 次、執行開頭 1 次")
		assert.EqualValues(t, 1, inj.fired.Load(), "注入恰觸發一次")
		assert.GreaterOrEqual(t, inj.assetReads.Load(), int32(2), "發起與執行都讀過資產")
		assert.Zero(t, inj.assetErrs.Load())
	})
}

func TestInventoryExecutorLockOrdering(t *testing.T) {
	t.Run("輪替成員派送先於盤點連線", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		mountID := e.mount(t).ID
		unlock, ok := tryLockRotationAccount(mountID)
		require.True(t, ok)
		released := make(chan time.Time, 1)
		go func() {
			time.Sleep(300 * time.Millisecond)
			released <- time.Now()
			unlock()
		}()
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
		require.Equal(t, 1, rec.count())
		assert.True(t, rec.times[0].After(<-released), "撥號發生在輪替釋放鎖之後")
	})
	t.Run("取鎖前整組輪替已結束則用新版本", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		e.svc.beforeExecutorLock = func() {
			unlock, ok := tryLockRotationAccount(e.mount(t).ID)
			require.True(t, ok)
			advanceEffectiveVersion(t, e)
			unlock()
		}
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
		assert.Equal(t, 1, rec.count())
		assert.Equal(t, model.InventoryLoginFailed, lastScanReason(t, e), "有撥號、認證才失敗")
	})
	t.Run("取鎖前整組輪替尚未結束則忙碌", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		e.svc.beforeExecutorLock = func() {
			unlock, ok := tryLockRotationAccount(e.mount(t).ID)
			require.True(t, ok)
			require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", e.mount(t).CredentialID).Update("active_rotation_id", 7).Error)
			unlock()
		}
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		e.svc.Wait()
		assert.Zero(t, rec.count())
		assert.Equal(t, model.InventoryExecutorBusy, lastScanReason(t, e))
	})
	t.Run("鎖被佔用時逾時且不持有交易", func(t *testing.T) {
		e := newExecInvEnv(t, true)
		rec := &dialRecorder{}
		rec.install(e)
		e.svc.executorLockWait = 300 * time.Millisecond
		mountID := e.mount(t).ID
		unlock, ok := tryLockRotationAccount(mountID)
		require.True(t, ok)
		defer unlock()
		start := time.Now()
		_, err := e.svc.Initiate(e.assetID, invAdmin)
		require.NoError(t, err)
		time.Sleep(100 * time.Millisecond)
		// 等鎖期間另一交易更新該掛載列，1 秒內完成
		upd := time.Now()
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", mountID).Update("updated_at", time.Now()).Error)
		assert.Less(t, time.Since(upd), time.Second)
		var idle int64
		require.NoError(t, e.db.Raw("SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' AND pid <> pg_backend_pid()").Scan(&idle).Error)
		assert.Zero(t, idle, "等鎖期間沒有 idle in transaction 的連線")
		e.svc.Wait()
		assert.LessOrEqual(t, time.Since(start), 300*time.Millisecond+time.Second)
		assert.Zero(t, rec.count())
		assert.Equal(t, model.InventoryExecutorBusy, lastScanReason(t, e))
	})
	t.Run("ctx 取消時立即回錯", func(t *testing.T) {
		unlock, ok := tryLockRotationAccount(987654)
		require.True(t, ok)
		defer unlock()
		ctx, cancel := context.WithCancel(context.Background())
		var done atomic.Int64
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		_, err := waitRotationAccountLock(ctx, 987654, 10*time.Second)
		done.Store(int64(time.Since(start)))
		assert.ErrorIs(t, err, errExecutorLockBusy)
		assert.Less(t, time.Duration(done.Load()), 50*time.Millisecond+100*time.Millisecond)
	})
}
