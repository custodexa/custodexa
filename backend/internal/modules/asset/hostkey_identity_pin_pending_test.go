package asset

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 握手前中斷、尚未綁定（pending）的候選重試：該候選從未送出過秘密，重試就是首次派送，
// 必須在送出任何認證之前用綁定回呼把當下的主機身分綁到候選列（root：TestCredentialRecoveryHostIdentityPin，前綴 3.4/retry）。

// interruptBeforeHandshake 在握手之前就中斷的執行器（例如服務關閉、情境取消）：Rotate 不碰遠端，回非確定性錯誤。
type interruptBeforeHandshake struct{ rotationExecutor }

func (interruptBeforeHandshake) Rotate(context.Context, rotationTarget, []byte, []byte) error {
	return context.Canceled
}

// newPendingRetryScenario 首次派送在握手前被中斷，候選以 pending 保留（遠端狀態未知）；之後靶機可連。
func newPendingRetryScenario(t *testing.T) *csFixture {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.retry.WithManagementAuthorizer(newAllowAllAuthorizer())
	f.retry.WithAuditSink(audit.NewTxSink())
	require.NoError(t, f.db.AutoMigrate(&model.AssetHostKeyMismatch{}))
	f.hostKeys.SetAuditTxSink(audit.NewTxSink())
	f.hostKeys.SetSystemAlertSink(newFakeAlertSink())

	orig := f.runner.executors
	f.runner.executors = func(ch string) rotationExecutor { return interruptBeforeHandshake{orig(ch)} }
	records := f.runner.RunPlan(f.plan(t, nil))
	f.runner.executors = orig
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
	require.EqualValues(t, 0, f.server.authAttempts.Load(), "首次派送在握手前中斷")

	cand := candidateOfAccount(t, f)
	require.Equal(t, model.HostKeyBindingPending, cand.HostKeyBinding, "握手前中斷：尚未綁定")
	require.False(t, cand.Applied, "秘密從未送出")
	require.EqualValues(t, 0, f.hostKeyRows(t), "靶機從未被連上：沒有自身列")
	return f
}

func (f *csFixture) hostKeyRows(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", f.assetID).Count(&n).Error)
	return n
}

func runRetryPendingBinding(t *testing.T) {
	t.Run("綁定先於認證", func(t *testing.T) {
		f := newPendingRetryScenario(t)
		w := watchAuth(f)
		cand := candidateOfAccount(t, f)
		// 讓候選密碼在靶機上可登入，重試才會走到轉正
		secret, err := f.candidates.Secret(context.Background(), &cand)
		require.NoError(t, err)
		require.NoError(t, withProtocolSecret(secret.Password, func(b []byte) error {
			f.server.setPassword(string(b))
			return nil
		}))
		secret.Destroy()

		require.True(t, f.retry.RetryOneAs(context.Background(), &cand))
		snaps := requireBoundAtAuth(t, f, w)
		assert.Len(t, snaps, 1, "重試的驗證只有一次認證")
		assert.EqualValues(t, 1, snaps[0].own.TrustGeneration)
		assert.EqualValues(t, 0, f.candidateCount(t), "驗證成功後轉正，候選刪除")
		assert.Empty(t, stopAuditDetails(t, f), "首次派送不是身分停止")
	})

	t.Run("綁定失敗則認證0次且候選保留", func(t *testing.T) {
		f := newPendingRetryScenario(t)
		// 故障注入（不寫任何綁定狀態）：正式綁定交易的條件式 UPDATE 一律出錯，交易回滾
		fired := failCandidateBindUpdate(t, f.db)
		cand := candidateOfAccount(t, f)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")
		assert.EqualValues(t, 0, f.server.authAttempts.Load(), "綁定失敗時不得送出任何認證")
		assert.EqualValues(t, 1, f.candidateCount(t), "候選保留")
		got := candidateOfAccount(t, f)
		assert.Equal(t, model.ChangeSecretReasonHostKeyCheckFailed, got.LastError)
		assert.False(t, got.Applied)
		assert.Equal(t, "oldpass123", f.storedPassword(t), "本地憑證不動")
		assert.Empty(t, stopAuditDetails(t, f), "綁定失敗不是身分停止")
	})

	t.Run("已綁定候選的重試仍走預期身分回呼而不重綁", func(t *testing.T) {
		f := newPendingRetryScenario(t)
		cand := candidateOfAccount(t, f)
		// 第一次重試：驗證因靶機密碼未變而失敗，但綁定已在認證前完成
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		bound := candidateOfAccount(t, f)
		require.Equal(t, model.HostKeyBindingBound, bound.HostKeyBinding)
		require.EqualValues(t, 1, f.server.authAttempts.Load())
		// 靶機身分換了：第二次重試被預期身分回呼擋下，不重綁
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		binds := 0
		f.hostKeys.bindTxBarrier = func(*gorm.DB) { binds++ }
		cand = candidateOfAccount(t, f)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		assert.Equal(t, 0, binds)
		assert.EqualValues(t, 1, f.server.authAttempts.Load(), "第二次沒有新的認證")
		after := candidateOfAccount(t, f)
		assert.Equal(t, bound.HostKeyFingerprint, after.HostKeyFingerprint, "快照不被覆寫")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after.LastError)
	})
}

// failCandidateBindUpdate 故障注入：把候選綁定為 bound 的 UPDATE 一律出錯（綁定交易回滾），回傳觸發次數。
// 只攔截正式綁定寫入的欄位組合，不寫入任何綁定狀態。
func failCandidateBindUpdate(t *testing.T, db *gorm.DB) *atomic.Int32 {
	t.Helper()
	fired := &atomic.Int32{}
	name := "test:fail_candidate_bind_update"
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Table != "change_secret_candidates" {
			return
		}
		if m, ok := tx.Statement.Dest.(map[string]interface{}); ok && m["host_key_binding"] == model.HostKeyBindingBound {
			fired.Add(1)
			_ = tx.AddError(errors.New("injected: candidate bind update failed"))
		}
	}))
	t.Cleanup(func() { _ = db.Callback().Update().Remove(name) })
	return fired
}
