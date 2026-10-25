package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// interruptedRotation 兩台共用憑證的輪替，第二台停在「改密中」（模擬行程在下達途中結束）。
func interruptedRotation(t *testing.T, host string) (*batchFixture, *secretRecorder, *model.CredentialRotation, model.CredentialRotationMember) {
	t.Helper()
	f := setupBatchFixture(t)
	_, accounts := f.sharedOn(t, "重啟中斷-"+host, "ops", "old", host+".1", host+".2")
	rec := newSecretRecorder()
	rec.rotateErr[host+".2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	f.rotations.executors = func(string) rotationExecutor { return rec }
	rot, err := f.rotations.Start(userCtx(7, "owner"), accounts0Credential(t, f, accounts[0]), StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
	rec.rotateErr[host+".2"] = nil
	var stuck model.CredentialRotationMember
	members, err := f.rotations.Members(rot.ID)
	require.NoError(t, err)
	for _, m := range members {
		if m.AccountID == accounts[1] {
			stuck = m
		}
	}
	require.NotZero(t, stuck.ID)
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", stuck.ID).
		Updates(map[string]any{"state": model.CredentialMemberChanging, "next_attempt_at": nil}).Error)
	stuck.State = model.CredentialMemberChanging
	return f, rec, rot, stuck
}

func accounts0Credential(t *testing.T, f *batchFixture, accountID uint) uint {
	t.Helper()
	var acc model.AssetAccount
	require.NoError(t, f.db.Where("id = ?", accountID).First(&acc).Error)
	return acc.CredentialID
}

func interruptedAuditCount(t *testing.T, f *batchFixture) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.AuditLog{}).
		Where("details LIKE ?", "%rotation_interrupted%").Count(&n).Error)
	return n
}

// 服務重啟時停在改密中的成員：啟動時轉為已送出未驗證（候選與授權脈絡不動、遠端零 I/O），
// 留一筆審計並告警一次；之後逐台補跑只驗證、不再下達新變更。
func TestInterruptedRotationMembersRecoverOnStartup(t *testing.T) {
	t.Run("轉為已送出未驗證，留審計與一次告警，遠端零 I/O", func(t *testing.T) {
		f, rec, rot, stuck := interruptedRotation(t, "10.9.80")
		alerts := &alertCapture{}
		f.rotations.WithStopNotifier(alerts.fn)
		var before model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&before).Error)
		_, deliverBefore, verifyBefore := rec.snapshotCalls()

		n, err := f.rotations.RecoverInterruptedMembers()
		require.NoError(t, err)
		assert.Equal(t, 1, n)

		m := memberByID(t, f, rot.ID, stuck.ID)
		assert.Equal(t, model.CredentialMemberChangedUnverified, m.State)
		assert.Equal(t, model.ChangeSecretReasonInterrupted, m.LastError)
		assert.Nil(t, m.NextAttemptAt, "成員不另排退避：背景只由候選列的退避以新秘密登入驗證（與遠端結果未知的既有處置一致），不下達")
		assert.Equal(t, int64(1), interruptedAuditCount(t, f), "一筆審計")
		assert.Equal(t, 1, alerts.count(), "告警一次")
		_, deliverAfter, verifyAfter := rec.snapshotCalls()
		assert.Equal(t, deliverBefore, deliverAfter, "遠端零 I/O")
		assert.Equal(t, verifyBefore, verifyAfter, "遠端零 I/O")
		var after model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&after).Error)
		assert.Equal(t, before.AuthorizationID, after.AuthorizationID, "授權脈絡不動")

		// 再跑一次不重複處理、不再告警
		n, err = f.rotations.RecoverInterruptedMembers()
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Equal(t, 1, alerts.count())
		assert.Equal(t, int64(1), interruptedAuditCount(t, f))

		// 之後逐台補跑：只以新秘密驗證，不再下達
		require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, stuck.ID))
		_, deliverRetry, verifyRetry := rec.snapshotCalls()
		assert.Equal(t, deliverAfter["10.9.80.2"], deliverRetry["10.9.80.2"], "補跑不下達新變更")
		assert.Greater(t, verifyRetry["10.9.80.2"], verifyAfter["10.9.80.2"], "補跑做驗證")
		assert.Equal(t, model.CredentialMemberApplied, memberByID(t, f, rot.ID, stuck.ID).State)
	})

	t.Run("審計寫不進去就不轉換，成員維持原狀並告警", func(t *testing.T) {
		f, _, rot, stuck := interruptedRotation(t, "10.9.81")
		f.rotations.auditTx = failingAuditTxSink{}
		alerts := &alertCapture{}
		f.rotations.WithStopNotifier(alerts.fn)

		n, err := f.rotations.RecoverInterruptedMembers()
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Equal(t, model.CredentialMemberChanging, memberByID(t, f, rot.ID, stuck.ID).State, "整筆回滾")
		assert.Equal(t, 1, alerts.count())
	})

	t.Run("本行程內仍在推進的成員不碰", func(t *testing.T) {
		f, _, rot, stuck := interruptedRotation(t, "10.9.82")
		release := lockRotationAccount(stuck.AccountID)
		n, err := f.rotations.RecoverInterruptedMembers()
		release()
		require.NoError(t, err)
		assert.Zero(t, n)
		assert.Equal(t, model.CredentialMemberChanging, memberByID(t, f, rot.ID, stuck.ID).State)
		assert.Zero(t, interruptedAuditCount(t, f))
	})

	t.Run("已放棄的一輪同樣處理，且之後在憑證詳情可補跑", func(t *testing.T) {
		f, _, rot, stuck := interruptedRotation(t, "10.9.83")
		require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
		n, err := f.rotations.RecoverInterruptedMembers()
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, model.CredentialMemberChangedUnverified, memberByID(t, f, rot.ID, stuck.ID).State)
		got, err := f.rotations.UnsettledRotationID(rot.CredentialID)
		require.NoError(t, err)
		assert.Equal(t, rot.ID, got)
	})
}
