package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// restoreStopAudits 還原世代不符的停止審計筆數（details 內帶停止 operation 與該原因碼）。
func (f *batchFixture) restoreStopAudits(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.AuditLog{}).
		Where("details LIKE ? AND details LIKE ?", "%authorization_stop%", "%"+model.ChangeSecretReasonAuthzRestored+"%").
		Count(&n).Error)
	return n
}

// restoreGenerationCases 還原後重放還原前留下的改密意圖，會以過時狀態改動遠端秘密；
// 背景派送前比對授權脈絡的還原世代與目前世代，不符即停、告警、留痕，保留給人處理，
// 但不阻擋還原後新建立的工作，也不阻擋具權者手動確認。
func restoreGenerationCases(t *testing.T) {
	t.Run("排程：還原後舊意圖停止，遠端零觸碰，告警與審計各一次，計畫轉待重新授權", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		f.runner.WithAuditSink(audit.NewTxSink())
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.runner.notifier = notifier
		f.authz.setRestoreGeneration("gen-1")
		a1, _ := f.addHost(t, "h1", "10.9.30.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("還原前", []uint{a1}, "ops"))
		require.NoError(t, err)
		require.Equal(t, "gen-1", f.authRow(t, plan.AuthorizationID).RestoreGeneration, "授權脈絡記下建立當下的世代")

		ok := f.runner.RunPlan(plan)
		require.Len(t, ok, 1, "還原前正常執行")
		_, before, _ := rec.snapshotCalls()
		pendingBefore := notifier.PendingNotifications()

		f.authz.setRestoreGeneration("gen-2") // 還原
		assert.Empty(t, f.runner.RunPlan(plan), "還原後舊意圖不派送")
		_, after, _ := rec.snapshotCalls()
		assert.Equal(t, before, after, "遠端零新 I/O")
		assert.Equal(t, pendingBefore+1, notifier.PendingNotifications(), "沿既有停止告警通道")
		assert.EqualValues(t, 1, f.restoreStopAudits(t))
		got, err := f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Equal(t, model.PlanAuthNeedsReauthorization, got.AuthorizationState, "計畫保留，待具權者重新授權")
		assert.True(t, got.Enabled, "cron 與啟用設定保留")

		// 同一計畫不隨觸發週期重複告警與留痕
		assert.Empty(t, f.runner.RunPlan(plan))
		assert.Equal(t, pendingBefore+1, notifier.PendingNotifications())
		assert.EqualValues(t, 1, f.restoreStopAudits(t))
	})

	t.Run("還原後新建立的工作照常，舊計畫重新授權後恢復", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		f.authz.setRestoreGeneration("gen-1")
		a1, _ := f.addHost(t, "h1", "10.9.31.1", "ops")
		old, err := f.plans.Create(userCtx(5, "creator"), planRequest("舊計畫", []uint{a1}, "ops"))
		require.NoError(t, err)

		f.authz.setRestoreGeneration("gen-2")
		fresh, err := f.plans.Create(userCtx(5, "creator"), planRequest("新計畫", []uint{a1}, "ops"))
		require.NoError(t, err)
		got := f.runner.RunPlan(fresh)
		require.Len(t, got, 1, "還原後新建立的計畫不被阻擋")
		assert.Equal(t, model.ChangeSecretSuccess, got[0].Status, got[0].Error)

		assert.Empty(t, f.runner.RunPlan(old), "舊計畫被擋")
		done, skipped, err := f.plans.ReauthorizePending(userCtx(1, "superadmin"))
		require.NoError(t, err)
		assert.Equal(t, []uint{old.ID}, done)
		assert.Empty(t, skipped)
		old, err = f.plans.Get(old.ID)
		require.NoError(t, err)
		assert.Equal(t, "gen-2", f.authRow(t, old.AuthorizationID).RestoreGeneration, "重新授權記現行世代")
		again := f.runner.RunPlan(old)
		require.Len(t, again, 1)
		assert.Equal(t, model.ChangeSecretSuccess, again[0].Status, again[0].Error)

		// 還原後新建立的批次同樣照常
		batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		assert.Equal(t, "gen-2", f.authRow(t, batch.AuthorizationID).RestoreGeneration)
		require.NotEmpty(t, f.runner.RunBatch(batch, ids))
	})

	t.Run("候選重試：背景被擋並保留，告警與審計各一次；具權者手動重試重新授權後送出", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.authz.setRestoreGeneration("gen-1")
		f.addHost(t, "h1", "10.9.32.1", "ops")
		_, acc2 := f.addHost(t, "h2", "10.9.32.2", "ops")
		rec := newSecretRecorder()
		rec.verifyErr["10.9.32.2"] = errRemoteDropped
		f.useExecutor(rec)
		batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		f.runner.RunBatch(batch, ids)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		require.NotNil(t, cand.AuthorizationID)
		rec.verifyErr["10.9.32.2"] = nil
		f.retry.WithAuditSink(audit.NewTxSink())
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		_, _, verifyBefore := rec.snapshotCalls()

		f.authz.setRestoreGeneration("gen-2") // 還原
		assert.False(t, f.retry.RetryOne(&cand), "背景重試不送出")
		_, _, v := rec.snapshotCalls()
		assert.Equal(t, verifyBefore, v, "遠端零觸碰")
		require.NoError(t, f.db.Where("id = ?", cand.ID).First(&cand).Error)
		assert.Equal(t, model.ChangeSecretReasonAuthzRestored, cand.LastError, "候選保留並記原因")
		assert.EqualValues(t, 1, notifier.PendingNotifications())
		assert.EqualValues(t, 1, f.restoreStopAudits(t))

		assert.False(t, f.retry.RetryOne(&cand), "再次背景重試仍不送出")
		assert.EqualValues(t, 1, notifier.PendingNotifications(), "每個候選只告警一次")
		assert.EqualValues(t, 1, f.restoreStopAudits(t), "每個候選只留痕一次")

		assert.True(t, f.retry.RetryOneAs(userCtx(8, "operator"), &cand), "具權者手動重試重新確認後送出")
		var row model.CredentialJobAuthorization
		require.NoError(t, f.db.Where("auth_source = ?", model.JobAuthViaManualCandidate).First(&row).Error)
		assert.Equal(t, uint(8), row.ActorID)
		assert.Equal(t, "gen-2", row.RestoreGeneration, "新授權脈絡記現行世代")
	})

	t.Run("手動重試：無權的點擊者仍被擋", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.authz.setRestoreGeneration("gen-1")
		f.addHost(t, "h1", "10.9.33.1", "ops")
		_, acc2 := f.addHost(t, "h2", "10.9.33.2", "ops")
		rec := newSecretRecorder()
		rec.noHostKey = true // 失權的點擊者有限收斂要求主機身分綁定；本案例驗的是無權者被擋
		rec.verifyErr["10.9.33.2"] = errRemoteDropped
		f.useExecutor(rec)
		batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
		require.NoError(t, err)
		f.runner.RunBatch(batch, ids)
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
		rec.verifyErr["10.9.33.2"] = nil
		_, _, verifyBefore := rec.snapshotCalls()

		f.authz.setRestoreGeneration("gen-2")
		f.retry.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 9}}
		assert.False(t, f.retry.RetryOneAs(userCtx(9, "nopower"), &cand))
		_, _, v := rec.snapshotCalls()
		assert.Equal(t, verifyBefore, v, "無權者不能替還原前的意圖送出")
	})

	t.Run("輪替補跑：背景停止且遠端零 I/O；具權者手動補跑重新授權後繼續", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.authz.setRestoreGeneration("gen-1")
		credID, accounts := f.sharedOn(t, "還原共用", "ops", "old", "10.9.34.1", "10.9.34.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.34.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		var waitingID uint
		members, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		for _, m := range members {
			if m.AccountID == accounts[1] {
				require.Equal(t, model.CredentialMemberRetryWait, m.State)
				waitingID = m.ID
			}
		}
		require.NotZero(t, waitingID)
		rec.rotateErr["10.9.34.2"] = nil
		_, before, _ := rec.snapshotCalls()

		f.authz.setRestoreGeneration("gen-2")
		// 手動補跑先走：具權的點擊者重新確認後送出
		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, waitingID))
		after, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		for _, m := range after {
			if m.ID == waitingID {
				assert.NotEqual(t, model.CredentialMemberRetryWait, m.State, "手動補跑已推進")
			}
		}
		_, afterCalls, _ := rec.snapshotCalls()
		assert.Greater(t, afterCalls["10.9.34.2"], before["10.9.34.2"], "具權者確認後遠端有新呼叫")
		var row model.CredentialJobAuthorization
		require.NoError(t, f.db.Where("source_kind = ? AND source_id = ? AND actor_id = ?",
			model.JobAuthSourceRotation, rot.ID, 9).First(&row).Error)
		assert.Equal(t, "gen-2", row.RestoreGeneration)
		var reloaded model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
		require.NotNil(t, reloaded.AuthorizationID)
		assert.Equal(t, row.ID, *reloaded.AuthorizationID, "輪替改引用新的授權脈絡")
	})

	t.Run("輪替補跑：沒有點擊者的背景補跑停止", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.authz.setRestoreGeneration("gen-1")
		credID, accounts := f.sharedOn(t, "還原背景", "ops", "old", "10.9.35.1", "10.9.35.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.35.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		members, _ := f.rotations.Members(rot.ID)
		var waitingID uint
		for _, m := range members {
			if m.AccountID == accounts[1] {
				waitingID = m.ID
			}
		}
		require.NotZero(t, waitingID)
		rec.rotateErr["10.9.35.2"] = nil
		_, before, _ := rec.snapshotCalls()

		f.authz.setRestoreGeneration("gen-2")
		require.NoError(t, f.rotations.RunMember(context.Background(), rot.ID, waitingID))
		after, _ := f.rotations.Members(rot.ID)
		for _, m := range after {
			if m.ID == waitingID {
				assert.Equal(t, model.CredentialMemberTerminalFailed, m.State)
				assert.Equal(t, model.ChangeSecretReasonAuthzRestored, m.LastError)
			}
		}
		_, afterCalls, _ := rec.snapshotCalls()
		assert.Equal(t, before, afterCalls, "遠端零新 I/O")
	})

	t.Run("輪替補跑：無權的點擊者不能承接還原前的輪替", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.authz.setRestoreGeneration("gen-1")
		credID, accounts := f.sharedOn(t, "還原無權", "ops", "old", "10.9.37.1", "10.9.37.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.37.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		members, _ := f.rotations.Members(rot.ID)
		var waitingID uint
		for _, m := range members {
			if m.AccountID == accounts[1] {
				waitingID = m.ID
			}
		}
		require.NotZero(t, waitingID)
		rec.rotateErr["10.9.37.2"] = nil
		var before model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&before).Error)
		require.NotNil(t, before.AuthorizationID)
		_, callsBefore, _ := rec.snapshotCalls()

		f.authz.setRestoreGeneration("gen-2")
		f.rotations.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 9}}
		require.NoError(t, f.rotations.RunMember(userCtx(9, "nopower"), rot.ID, waitingID))

		_, callsAfter, _ := rec.snapshotCalls()
		assert.Equal(t, callsBefore, callsAfter, "無權者不能替還原前的輪替送出")
		var after model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&after).Error)
		require.NotNil(t, after.AuthorizationID)
		assert.Equal(t, *before.AuthorizationID, *after.AuthorizationID, "沒有承接：仍引用還原前的授權列")
		var n int64
		require.NoError(t, f.db.Model(&model.CredentialJobAuthorization{}).
			Where("source_kind = ? AND source_id = ? AND actor_id = ?", model.JobAuthSourceRotation, rot.ID, 9).
			Count(&n).Error)
		assert.Zero(t, n, "沒有承接：無權者名下沒有授權列")
	})

	t.Run("世代讀不到：fail closed，不以比對未啟用放行", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, _ := f.addHost(t, "h1", "10.9.36.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("讀不到", []uint{a1}, "ops"))
		require.NoError(t, err)
		f.authz.mu.Lock()
		f.authz.restoreErr = errors.New("db down")
		f.authz.mu.Unlock()
		assert.Empty(t, f.runner.RunPlan(plan))
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls, "遠端零觸碰")
		got, err := f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Empty(t, got.AuthorizationState, "暫時讀不到不把計畫標成待重新授權")
	})
}
