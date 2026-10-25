package asset

import (
	"bytes"
	"context"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 輪替成員提交交易與下達標記的子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.3/）。

// bumpGenerationAfterVerify 讓替身在 host 的驗證成功之後、本地提交之前，把該資產主機金鑰自身列的世代推進一格，
// 模擬「驗證通過後主機身分被換掉」。回傳觸發次數；夾具的綁定與主機金鑰記錄都經替身的正式回呼建立。
func bumpGenerationAfterVerify(t *testing.T, f *batchFixture, rec *secretRecorder, host string, assetID uint) *atomic.Int32 {
	t.Helper()
	fired := &atomic.Int32{}
	rec.afterVerify = func(h string) {
		if h != host {
			return
		}
		fired.Add(1)
		// 直寫自身列（design 明准的壞資料／故障注入，非綁定也非採用）：驗證後世代被推進
		if err := f.db.Model(&model.AssetHostKey{}).Where("asset_id = ?", assetID).
			UpdateColumn("trust_generation", 99).Error; err != nil {
			t.Errorf("注入主機身分變更失敗: %v", err)
		}
	}
	return fired
}

// runMemberCommitIdentityChanged 整組與拆分的提交交易：身分不符 -> 不提交、成員停在已下達未驗證、
// 候選保留、原因碼是新碼而不是提交失敗；同批另一台照常就位。
func runMemberCommitIdentityChanged(t *testing.T) {
	t.Run("整組commitGroupApplied", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "身分整組", "ops", "old-shared", "10.33.1.1", "10.33.1.2")
		assetID := f.bindingOf(t, accounts[1]).AssetID
		effBefore := f.bindingOf(t, accounts[1]).EffectiveVersionID
		rec := newSecretRecorder()
		fired := bumpGenerationAfterVerify(t, f, rec, "10.33.1.2", assetID)
		f.useRotationExecutor(rec)

		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

		require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")
		bad := f.memberOf(t, rot.ID, accounts[1])
		require.Equal(t, model.HostKeyBindingBound, bad.HostKeyBinding, "綁定經替身的正式回呼建立")
		assert.Equal(t, model.CredentialMemberChangedUnverified, bad.State, "不提交：停在已下達未驗證")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, bad.LastError, "原因碼是身分變更而非提交失敗")
		assert.EqualValues(t, 1, f.candidateCountFor(t, accounts[1]), "候選保留")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, f.candidateByAccount(t, accounts[1]).LastError)
		assert.Equal(t, effBefore, f.bindingOf(t, accounts[1]).EffectiveVersionID, "就位版本不動")
		assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[0]).State, "另一台不受影響")
	})

	t.Run("拆分commitSplitApplied", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "身分拆分", "ops", "old-shared", "10.33.2.1", "10.33.2.2")
		assetID := f.bindingOf(t, accounts[1]).AssetID
		rec := newSecretRecorder()
		fired := bumpGenerationAfterVerify(t, f, rec, "10.33.2.2", assetID)
		f.useRotationExecutor(rec)

		rot, err := f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

		require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")
		bad := f.memberOf(t, rot.ID, accounts[1])
		require.Equal(t, model.HostKeyBindingBound, bad.HostKeyBinding, "綁定經替身的正式回呼建立")
		assert.Equal(t, model.CredentialMemberChangedUnverified, bad.State)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, bad.LastError)
		assert.EqualValues(t, 1, f.candidateCountFor(t, accounts[1]), "拆分候選是唯一副本：保留")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, f.candidateByAccount(t, accounts[1]).LastError)
		assert.Equal(t, credID, f.bindingOf(t, accounts[1]).CredentialID, "未改綁到專用憑證")
		assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[0]).State, "另一台不受影響")
		assert.NotEqual(t, credID, f.bindingOf(t, accounts[0]).CredentialID, "另一台已改綁")
	})
}

func (f *batchFixture) candidateByAccount(t *testing.T, accountID uint) *model.ChangeSecretCandidate {
	t.Helper()
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", accountID).First(&cand).Error)
	return &cand
}

// captureLog 暫時攔下標準 log 輸出，回傳讀取函式。
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return func() string { return buf.String() }
}

// runCandidateRetryIdempotent 轉正已成功之後再重試：候選列已不在，結果與先前一致，不重複提交、不誤報。
func runCandidateRetryIdempotent(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.rejectVerifyLogin = true
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = false
	f.server.mu.Unlock()
	var stale model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&stale).Error)

	require.True(t, f.retry.RetryOne(&stale), "第一次重試轉正")
	versions := credentialVersionCount(t, f)
	password := f.storedPassword(t)
	var successes int64
	require.NoError(t, f.db.Model(&model.ChangeSecretRecord{}).
		Where("status = ?", model.ChangeSecretSuccess).Count(&successes).Error)
	require.EqualValues(t, 1, successes)

	// 管理端按重試：先取候選，列已不在 -> 與先前同為「候選不存在」（呼叫端對應 404），沒有靜默成功
	_, err := f.candidates.Get(stale.ID)
	assert.ErrorIs(t, err, ErrCandidateNotFound)

	// 讀取與提交之間列已被轉正：拿過期物件（且在記憶體內已逾放棄期限，若被當作一般失敗會誤發放棄告警）再重試
	notifier := audit.NewAlertNotifier(f.db, nil)
	f.retry.notifier = notifier
	old := stale
	old.CreatedAt = time.Now().Add(-candidateRetryDeadline - time.Hour)
	assert.False(t, f.retry.RetryOne(&old), "沒有東西可再提交，不宣稱轉正")
	assert.EqualValues(t, 0, notifier.PendingNotifications(), "列已不在：不發放棄告警")
	assert.ErrorIs(t, f.candidates.Promote(context.Background(), &stale), ErrCandidateNotFound)
	assert.Equal(t, versions, credentialVersionCount(t, f), "不重複新增版本")
	assert.Equal(t, password, f.storedPassword(t), "本地憑證不變")
	var after int64
	require.NoError(t, f.db.Model(&model.ChangeSecretRecord{}).
		Where("status = ?", model.ChangeSecretSuccess).Count(&after).Error)
	assert.EqualValues(t, successes, after, "不重複補成功記錄")
	assert.EqualValues(t, 0, f.candidateCount(t))

	// 排程重入：到期清單已不含它
	promoted, failed := f.retry.RunDue()
	assert.Zero(t, promoted)
	assert.Zero(t, failed)
}

// runDeliveredMarkFailureDoesNotAbort 下達標記寫不進去只記 log，不中止輪替：密碼與 SSH 金鑰兩條路徑。
func runDeliveredMarkFailureDoesNotAbort(t *testing.T) {
	failMark := func(t *testing.T, f *csFixture) {
		t.Helper()
		require.NoError(t, f.db.Exec(`CREATE TRIGGER fail_mark_applied BEFORE UPDATE OF applied ON change_secret_candidates
			BEGIN SELECT RAISE(ABORT, 'mark failed'); END`).Error)
	}
	t.Run("密碼", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		failMark(t, f)
		logs := captureLog(t)
		records := f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		assert.Contains(t, logs(), "標記候選已下達失敗", "失敗必須進 log，而不是被吞掉")
		assert.Equal(t, f.server.currentPassword(), f.storedPassword(t))
	})
	t.Run("SSH金鑰", func(t *testing.T) {
		f := keyRotationFixture(t)
		failMark(t, f)
		logs := captureLog(t)
		records := f.runner.RunPlan(f.keyPlan(t))
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		assert.Contains(t, logs(), "標記候選已下達失敗", "失敗必須進 log，而不是被吞掉")
	})
}
