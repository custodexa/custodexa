package asset

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 撥號前查庫本身失敗（資料庫錯誤）與主機身分不符是兩回事：前者 fail-closed 不撥號，
// 但原因碼對映無法判定權限，不寫身分異動停止審計（root：TestCredentialRecoveryHostIdentityPin，前綴 3.4/成員/預檢查詢不可用）。

// failHostKeyReads 在 armed 為真時讓主機金鑰自身記錄表的所有查詢出錯（故障注入），回傳觸發次數。
func failHostKeyReads(t *testing.T, db *gorm.DB, armed *atomic.Bool) *atomic.Int32 {
	t.Helper()
	fired := &atomic.Int32{}
	name := "test:fail_host_key_reads"
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, func(tx *gorm.DB) {
		if armed.Load() && tx.Statement != nil && tx.Statement.Table == "asset_host_keys" {
			fired.Add(1)
			_ = tx.AddError(errors.New("injected: host key read failed"))
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove(name) })
	return fired
}

func runPrecheckLookupFailed(t *testing.T) {
	t.Run("直接守衛/讀工作列失敗與讀自身記錄失敗保留區別", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		asset, err := f.rotations.assets.GetByID(m.AssetID)
		require.NoError(t, err)

		// 讀工作列失敗
		g := f.rotations.memberVerifyGuard(rot, m)
		g.load = func() (hostIdentityStopInput, error) {
			return hostIdentityStopInput{}, errors.New("injected: load failed")
		}
		_, gerr := g.prepare(asset)
		require.Error(t, gerr)
		assert.True(t, errors.Is(gerr, ErrHostIdentityLookupFailed))
		assert.False(t, errors.Is(gerr, ErrHostIdentityChanged), "查詢不可用不是身分異動")
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, verifyFailureReason(gerr, "FALLBACK"))
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, precheckStopReason(gerr))

		// 讀自身記錄失敗
		armed := &atomic.Bool{}
		fired := failHostKeyReads(t, f.db, armed)
		armed.Store(true)
		g2 := f.rotations.memberVerifyGuard(rot, m)
		_, gerr2 := g2.prepare(asset)
		armed.Store(false)
		require.Error(t, gerr2)
		require.Positive(t, fired.Load(), "注入必須真的觸發")
		assert.True(t, errors.Is(gerr2, ErrHostIdentityLookupFailed))
		assert.False(t, errors.Is(gerr2, ErrHostIdentityChanged))
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, verifyFailureReason(gerr2, "FALLBACK"))

		// 對照：真的身分不符仍是身分異動
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		g3 := f.rotations.memberVerifyGuard(rot, m)
		_, gerr3 := g3.prepare(asset)
		require.Error(t, gerr3)
		assert.True(t, errors.Is(gerr3, ErrHostIdentityChanged))
		assert.False(t, errors.Is(gerr3, ErrHostIdentityLookupFailed))
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, verifyFailureReason(gerr3, "FALLBACK"))
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, precheckStopReason(gerr3))
	})

	t.Run("補跑Verify正式入口/讀自身記錄失敗回AUTHZ_UNAVAILABLE", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		armed := &atomic.Bool{}
		fired := failHostKeyReads(t, f.db, armed)
		armed.Store(true)
		base := f.server.authAttempts.Load()
		before := snapshotOf(f.member(t, rot.ID))

		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		armed.Store(false)
		require.Positive(t, fired.Load(), "注入必須真的觸發（否則為假綠）")
		assert.EqualValues(t, base, f.server.authAttempts.Load(), "不得送出任何認證")
		after := f.member(t, rot.ID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, after.State)
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, after.LastError, "不是主機身分變更")
		assert.Equal(t, before, snapshotOf(after), "快照不變")
		assert.Empty(t, memberStops(t, f.db), "查詢不可用不寫身分異動停止審計")
		cand, err := f.candidates.FindByAccount(f.accountID)
		require.NoError(t, err)
		require.NotNil(t, cand, "候選保留")
	})

	t.Run("立即Verify正式入口/下達後讀自身記錄失敗回AUTHZ_UNAVAILABLE", func(t *testing.T) {
		f := setupMemberBindFixture(t, "")
		rot := f.start(t, false)
		armed := &atomic.Bool{}
		fired := failHostKeyReads(t, f.db, armed)
		f.hookAfterRotate(func() { armed.Store(true) })

		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		armed.Store(false)
		require.Positive(t, fired.Load(), "注入必須真的觸發（否則為假綠）")
		m := f.member(t, rot.ID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, m.State, "已下達、驗證未完成")
		assert.NotNil(t, m.SecretSentAt)
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, m.LastError, "不是主機身分變更")
		assert.Empty(t, memberStops(t, f.db), "查詢不可用不寫身分異動停止審計")
		cand, err := f.candidates.FindByAccount(f.accountID)
		require.NoError(t, err)
		require.NotNil(t, cand, "候選保留")
	})
}
