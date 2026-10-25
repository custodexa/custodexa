package asset

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// alertCapture 收集改密停止／承接未完成的推送（組裝根注入的同一個 func 形狀）。
type alertCapture struct {
	mu    sync.Mutex
	rules []string
}

func (a *alertCapture) fn(rule, _ string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, rule)
}

func (a *alertCapture) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.rules)
}

// rotationAuthRows 指定輪替、指定發起者名下的授權列筆數。
func rotationAuthRows(t *testing.T, f *batchFixture, rotationID, actorID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.CredentialJobAuthorization{}).
		Where("source_kind = ? AND source_id = ? AND actor_id = ?", model.JobAuthSourceRotation, rotationID, actorID).
		Count(&n).Error)
	return n
}

func memberByID(t *testing.T, f *batchFixture, rotationID, memberID uint) model.CredentialRotationMember {
	t.Helper()
	members, err := f.rotations.Members(rotationID)
	require.NoError(t, err)
	for _, m := range members {
		if m.ID == memberID {
			return m
		}
	}
	t.Fatalf("成員 %d 不存在", memberID)
	return model.CredentialRotationMember{}
}

// 承接（升級前無授權脈絡的輪替、還原前的輪替、暫停的計畫）與它的審計同生共死：
// 審計寫不進去就不承接、遠端不開始、候選保留、告警一次。
func TestCredentialTakeoverAuditIsAtomic(t *testing.T) {
	// legacyRotation 兩台共用憑證的輪替：第二台停在 state（retry_wait 或 changed_unverified），
	// 並抹掉輪替的授權脈絡引用模擬升級前資料
	legacyRotation := func(t *testing.T, host, state string) (*batchFixture, *secretRecorder, *model.CredentialRotation, uint, uint) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "承接審計-"+host, "ops", "old", host+".1", host+".2")
		rec := newSecretRecorder()
		if state == model.CredentialMemberRetryWait {
			rec.rotateErr[host+".2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		} else {
			rec.verifyErr[host+".2"] = errRemoteDropped
		}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		var stuckID uint
		members, err := f.rotations.Members(rot.ID)
		require.NoError(t, err)
		for _, m := range members {
			if m.AccountID == accounts[1] {
				require.Equal(t, state, m.State)
				stuckID = m.ID
			}
		}
		require.NotZero(t, stuckID)
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
			Update("authorization_id", nil).Error)
		rec.rotateErr[host+".2"] = nil
		rec.verifyErr[host+".2"] = nil
		return f, rec, rot, stuckID, accounts[1]
	}

	t.Run("升級前輪替（等待重試）：審計寫不進去即不承接，遠端不開始，告警一次", func(t *testing.T) {
		f, rec, rot, memberID, _ := legacyRotation(t, "10.9.60", model.CredentialMemberRetryWait)
		f.rotations.auditTx = failingAuditTxSink{}
		alerts := &alertCapture{}
		f.rotations.WithStopNotifier(alerts.fn)
		_, deliverBefore, verifyBefore := rec.snapshotCalls()

		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, memberID))

		_, deliverAfter, verifyAfter := rec.snapshotCalls()
		assert.Equal(t, deliverBefore, deliverAfter, "遠端零新 I/O")
		assert.Equal(t, verifyBefore, verifyAfter, "遠端零新 I/O")
		var reloaded model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
		assert.Nil(t, reloaded.AuthorizationID, "沒有承接：輪替引用未寫入")
		assert.Zero(t, rotationAuthRows(t, f, rot.ID, 9), "沒有承接：授權列隨交易回滾")
		m := memberByID(t, f, rot.ID, memberID)
		assert.Equal(t, model.CredentialMemberTerminalFailed, m.State, "成員停止，可再補跑")
		assert.Equal(t, model.ChangeSecretReasonAuthzUnavailable, m.LastError)
		assert.Equal(t, 1, alerts.count(), "告警一次")
	})

	t.Run("升級前輪替（已送出未驗證）：審計寫不進去即不承接，候選保留，不驗證", func(t *testing.T) {
		f, rec, rot, memberID, accountID := legacyRotation(t, "10.9.61", model.CredentialMemberChangedUnverified)
		f.rotations.auditTx = failingAuditTxSink{}
		alerts := &alertCapture{}
		f.rotations.WithStopNotifier(alerts.fn)
		_, deliverBefore, verifyBefore := rec.snapshotCalls()

		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, memberID))

		_, deliverAfter, verifyAfter := rec.snapshotCalls()
		assert.Equal(t, deliverBefore, deliverAfter)
		assert.Equal(t, verifyBefore, verifyAfter, "沒有承接就不登入驗證")
		assert.Zero(t, rotationAuthRows(t, f, rot.ID, 9))
		m := memberByID(t, f, rot.ID, memberID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, m.State, "成員維持已送出未驗證")
		var kept int64
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", accountID).Count(&kept).Error)
		assert.EqualValues(t, 1, kept, "候選保留")
		assert.Equal(t, 1, alerts.count(), "告警一次")

		// 同一原因不隨重試重複告警
		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, memberID))
		assert.Equal(t, 1, alerts.count(), "每件一次")
	})

	t.Run("還原前的輪替：審計寫不進去即不改引用新授權列，遠端不開始", func(t *testing.T) {
		f := setupBatchFixture(t)
		f.authz.setRestoreGeneration("gen-1")
		credID, accounts := f.sharedOn(t, "還原承接審計", "ops", "old", "10.9.62.1", "10.9.62.2")
		rec := newSecretRecorder()
		rec.rotateErr["10.9.62.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		var waitingID uint
		members, _ := f.rotations.Members(rot.ID)
		for _, m := range members {
			if m.AccountID == accounts[1] {
				waitingID = m.ID
			}
		}
		require.NotZero(t, waitingID)
		rec.rotateErr["10.9.62.2"] = nil
		var before model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&before).Error)
		require.NotNil(t, before.AuthorizationID)
		_, callsBefore, _ := rec.snapshotCalls()

		f.authz.setRestoreGeneration("gen-2")
		f.rotations.auditTx = failingAuditTxSink{}
		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, waitingID))

		_, callsAfter, _ := rec.snapshotCalls()
		assert.Equal(t, callsBefore, callsAfter, "遠端零新 I/O")
		var after model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&after).Error)
		require.NotNil(t, after.AuthorizationID)
		assert.Equal(t, *before.AuthorizationID, *after.AuthorizationID, "仍引用還原前的授權列")
		assert.Zero(t, rotationAuthRows(t, f, rot.ID, 9))
	})

	t.Run("暫停的計畫：審計寫不進去即不承接，維持暫停並列入略過，告警一次", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		f.useExecutor(rec)
		a1, _ := f.addHost(t, "h1", "10.9.63.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("承接審計", []uint{a1}, "ops"))
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.ChangeSecretPlan{}).Where("id = ?", plan.ID).
			Updates(map[string]any{"authorization_id": nil, "authorization_state": model.PlanAuthNeedsReauthorization}).Error)
		f.plans.WithAuditSink(failingAuditTxSink{})
		alerts := &alertCapture{}
		f.plans.WithAlertNotifier(alerts.fn)

		done, skipped, err := f.plans.ReauthorizePending(userCtx(1, "superadmin"))
		require.NoError(t, err, "不整批失敗")
		assert.Empty(t, done)
		assert.Equal(t, []uint{plan.ID}, skipped)
		got, err := f.plans.Get(plan.ID)
		require.NoError(t, err)
		assert.Equal(t, model.PlanAuthNeedsReauthorization, got.AuthorizationState, "維持暫停")
		assert.Nil(t, got.AuthorizationID, "授權列隨交易回滾")
		var n int64
		require.NoError(t, f.db.Model(&model.CredentialJobAuthorization{}).
			Where("source_kind = ? AND source_id = ? AND auth_source = ?",
				model.JobAuthSourcePlan, plan.ID, model.JobAuthViaReauthorized).Count(&n).Error)
		assert.Zero(t, n)
		assert.Equal(t, 1, alerts.count(), "告警一次")
		assert.Empty(t, f.runner.RunPlan(got), "未承接的計畫不執行")
		_, calls, _ := rec.snapshotCalls()
		assert.Empty(t, calls, "遠端零觸碰")
	})
}

// 升級前輪替的成員被無權者補跑後轉為已收束：具權者對該成員逐台補跑仍能承接並送出；
// 放棄本輪也不因成員已收束而失敗。
func TestLegacyRotationAbandonedMemberRecovery(t *testing.T) {
	setup := func(t *testing.T, host string) (*batchFixture, *secretRecorder, *model.CredentialRotation, uint) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "已收束-"+host, "ops", "old", host+".1", host+".2")
		rec := newSecretRecorder()
		rec.rotateErr[host+".2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
		f.rotations.executors = func(string) rotationExecutor { return rec }
		rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
		var id uint
		members, _ := f.rotations.Members(rot.ID)
		for _, m := range members {
			if m.AccountID == accounts[1] {
				id = m.ID
			}
		}
		require.NotZero(t, id)
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
			Update("authorization_id", nil).Error)
		rec.rotateErr[host+".2"] = nil
		// 背景先把等待重試的成員停成終局失敗；無權者再按補跑在重新排入前即被拒、不改狀態
		require.NoError(t, f.rotations.RunMember(context.Background(), rot.ID, id))
		require.Equal(t, model.CredentialMemberTerminalFailed, memberByID(t, f, rot.ID, id).State)
		inner := f.rotations.mgmt
		f.rotations.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 9}}
		require.ErrorIs(t, f.rotations.RunMember(userCtx(9, "nopower"), rot.ID, id), ErrCredentialBindForbidden)
		f.rotations.mgmt = inner
		require.Equal(t, model.CredentialMemberTerminalFailed, memberByID(t, f, rot.ID, id).State)
		// 夾具：成員經授權重驗停止而收束（脈絡缺失的背景推進落點）
		require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", id).
			Updates(map[string]any{"state": model.CredentialMemberAbandoned, "last_error": model.ChangeSecretReasonAuthzContextMissing}).Error)
		require.Equal(t, model.CredentialMemberAbandoned, memberByID(t, f, rot.ID, id).State)
		return f, rec, rot, id
	}

	t.Run("具權者對已收束的成員逐台補跑：承接並送出", func(t *testing.T) {
		f, rec, rot, id := setup(t, "10.9.64")
		_, before, _ := rec.snapshotCalls()
		require.NoError(t, f.rotations.RunMember(userCtx(8, "clicker"), rot.ID, id))
		_, after, _ := rec.snapshotCalls()
		assert.Greater(t, after["10.9.64.2"], before["10.9.64.2"], "承接後遠端有新呼叫")
		assert.EqualValues(t, 1, rotationAuthRows(t, f, rot.ID, 8))
		assert.NotEqual(t, model.CredentialMemberAbandoned, memberByID(t, f, rot.ID, id).State)
	})

	t.Run("放棄本輪不因成員已收束而失敗", func(t *testing.T) {
		f, _, rot, _ := setup(t, "10.9.65")
		require.NoError(t, f.rotations.Abandon(userCtx(1, "superadmin"), rot.ID))
		var reloaded model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
		assert.Equal(t, model.CredentialRotationAbandoned, reloaded.Status)
	})
}
