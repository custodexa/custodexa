package asset

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
)

// 提交交易接入主機身分比對的子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.3/）。

// resetOnVerifyAuth 讓靶機在第二次認證嘗試（立即驗證的登入）內把該資產的主機金鑰自身列世代推進一格，
// 模擬「驗證通過後、本地提交前主機身分被換掉」。第一次認證（舊憑證下達）不動。回傳觸發次數。
func resetOnVerifyAuth(t *testing.T, f *csFixture) *atomic.Int32 {
	t.Helper()
	fired := &atomic.Int32{}
	var attempts atomic.Int32
	f.server.mu.Lock()
	f.server.onAuthAttempt = func() {
		if attempts.Add(1) != 2 {
			return
		}
		fired.Add(1)
		// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：驗證後世代被推進
		if err := f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).
			UpdateColumn("trust_generation", 99).Error; err != nil {
			t.Errorf("注入主機身分變更失敗: %v", err)
		}
	}
	f.server.mu.Unlock()
	return fired
}

func credentialVersionCount(t *testing.T, f *csFixture) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.CredentialSecretVersion{}).Count(&n).Error)
	return n
}

// runPromoteIdentityChanged 提交交易內主機身分比對不符：不提交、候選保留、caller 回新原因碼而非提交失敗。
func runPromoteIdentityChanged(t *testing.T) {
	t.Run("一般密碼經rotatePassword", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		versions := credentialVersionCount(t, f)
		fired := resetOnVerifyAuth(t, f)

		records := f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")
		assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
		assert.EqualValues(t, 1, f.candidateCount(t), "不提交：候選保留")
		assert.Equal(t, "oldpass123", f.storedPassword(t), "本地憑證不動")
		assert.Equal(t, versions, credentialVersionCount(t, f), "不新增版本")
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", f.accountID).First(&cand).Error)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, cand.LastError)
	})

	t.Run("一般SSH金鑰經rotateKey", func(t *testing.T) {
		f := keyRotationFixture(t)
		origKey := f.storedPrivateKey(t)
		versions := credentialVersionCount(t, f)
		fired := resetOnVerifyAuth(t, f)

		records := f.runner.RunPlan(f.keyPlan(t))
		require.Len(t, records, 1)
		require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")
		assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, records[0].Error)
		assert.EqualValues(t, 1, f.candidateCount(t), "不提交：候選保留")
		assert.Equal(t, origKey, f.storedPrivateKey(t), "本地私鑰不動")
		assert.Equal(t, versions, credentialVersionCount(t, f), "不新增版本")
	})

	t.Run("帶目標憑證候選經RetryOneAs的promoteToCredential", func(t *testing.T) {
		f := setupBatchFixture(t)
		_, acc1 := f.addHost(t, "h1", "10.3.3.1", "ops")
		a2, acc2 := f.addHost(t, "h2", "10.3.3.2", "ops")
		rec := newSecretRecorder()
		rec.verifyErr["10.3.3.2"] = errors.New("verify timeout")
		f.useExecutor(rec)
		batch, assetIDs, err := f.batches.Create(sharedBatchRequest("ops", "身分變更"), 1, "admin")
		require.NoError(t, err)
		records := f.runner.RunBatch(batch, assetIDs)
		require.Equal(t, model.ChangeSecretUnverified, recordByAsset(records, a2).Status)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		require.NotZero(t, cand.CredentialID)
		require.NotZero(t, cand.TargetVersionID)
		require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
		credBefore := f.bindingOf(t, acc2).CredentialID
		_ = acc1

		// 遠端恢復，但主機身分在驗證與提交之間被換掉
		rec.mu.Lock()
		delete(rec.verifyErr, "10.3.3.2")
		rec.mu.Unlock()
		// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：驗證與提交之間世代被推進
		require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", a2).
			UpdateColumn("trust_generation", 99).Error)

		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand), "身分不符：不轉正")
		kept := f.candidateOf(t, cand.ID)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, kept.LastError, "原因碼不是提交失敗")
		assert.Equal(t, credBefore, f.bindingOf(t, acc2).CredentialID, "未改綁")
		assert.EqualValues(t, 1, f.candidateCountFor(t, acc2), "候選保留")
	})
}

// runPinnedRotateIdentityChanged Pinned 回呼在舊憑證撥號拒絕（ErrHostIdentityChanged，含包裝）：
// 原因碼辨識為主機身分變更，而不是舊憑證登入失敗；憑證未送出。
func runPinnedRotateIdentityChanged(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	asset, err := f.assets.GetByID(f.assetID)
	require.NoError(t, err)
	rt := rotationTarget{
		asset: asset, channel: asset.EffectiveRotationChannel(), username: "root",
		secretType: model.ChangeSecretTypePassword, addr: rotationAddr(asset, asset.EffectiveRotationChannel()),
		hostKeyCB: func(string, net.Addr, ssh.PublicKey) error {
			return fmt.Errorf("pinned 比對: %w", ErrHostIdentityChanged)
		},
	}
	err = posixSSHExecutor{}.Rotate(context.Background(), rt, []byte("oldpass123"), []byte("newpass456"))
	var rejected *remoteRejectedError
	require.True(t, errors.As(err, &rejected), "err = %v", err)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, rejected.reason)
	assert.EqualValues(t, 0, f.server.authAttempts.Load(), "回呼拒絕時不得送出認證")
	assert.EqualValues(t, 0, f.server.chpasswdCalls.Load())
	reason, clean := classifyRotationError(err)
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, reason)
	assert.True(t, clean, "憑證未送出：遠端確定未變更")
	assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, oldCredentialLoginReason(fmt.Errorf("a: %w", fmt.Errorf("b: %w", ErrHostIdentityChanged))))
}
