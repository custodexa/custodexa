package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 升級前建立的輪替沒有授權脈絡：背景補跑停止且遠端零 I/O；具權者手動補跑以其當下權限承接，
// 新增授權列並寫審計；無權的點擊者仍被拒。
func TestLegacyRotationWithoutContextIsAdoptedByAuthorizedClicker(t *testing.T) {
	setup := func(t *testing.T, host string) (*batchFixture, *secretRecorder, *model.CredentialRotation, uint) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "升級前輪替-"+host, "ops", "old", host+".1", host+".2")
		rec := newSecretRecorder()
		rec.rotateErr[host+".2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
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
		// 模擬升級前資料：輪替沒有授權脈絡引用
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
			Update("authorization_id", nil).Error)
		rec.rotateErr[host+".2"] = nil
		return f, rec, rot, waitingID
	}

	t.Run("背景補跑停止，遠端零新 I/O", func(t *testing.T) {
		f, rec, rot, waitingID := setup(t, "10.9.50")
		_, before, _ := rec.snapshotCalls()
		require.NoError(t, f.rotations.RunMember(context.Background(), rot.ID, waitingID))
		members, _ := f.rotations.Members(rot.ID)
		for _, m := range members {
			if m.ID == waitingID {
				assert.Equal(t, model.CredentialMemberTerminalFailed, m.State)
				assert.Equal(t, model.ChangeSecretReasonAuthzContextMissing, m.LastError)
			}
		}
		_, after, _ := rec.snapshotCalls()
		assert.Equal(t, before, after)
	})

	t.Run("具權者手動補跑承接並繼續，留授權列與審計", func(t *testing.T) {
		f, rec, rot, waitingID := setup(t, "10.9.51")
		_, before, _ := rec.snapshotCalls()
		require.NoError(t, f.rotations.RunMember(userCtx(9, "clicker"), rot.ID, waitingID))
		_, after, _ := rec.snapshotCalls()
		assert.Greater(t, after["10.9.51.2"], before["10.9.51.2"], "承接後遠端有新呼叫")
		var row model.CredentialJobAuthorization
		require.NoError(t, f.db.Where("source_kind = ? AND source_id = ? AND actor_id = ?",
			model.JobAuthSourceRotation, rot.ID, 9).First(&row).Error)
		assert.Equal(t, model.JobAuthViaReauthorized, row.AuthSource)
		assert.Equal(t, 1, row.Revision)
		var reloaded model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
		require.NotNil(t, reloaded.AuthorizationID)
		assert.Equal(t, row.ID, *reloaded.AuthorizationID)
		var n int64
		require.NoError(t, f.db.Model(&model.AuditLog{}).
			Where("details LIKE ?", "%rotation_reauthorized%").Count(&n).Error)
		assert.Equal(t, int64(1), n, "承接寫一筆審計")
	})

	t.Run("無權的點擊者不能承接", func(t *testing.T) {
		f, rec, rot, waitingID := setup(t, "10.9.52")
		f.rotations.mgmt = credentialManagementGate{authorizer: &perUserAuthorizer{inner: f.authz, denyUser: 9}}
		_, before, _ := rec.snapshotCalls()
		require.NoError(t, f.rotations.RunMember(userCtx(9, "nopower"), rot.ID, waitingID))
		_, after, _ := rec.snapshotCalls()
		assert.Equal(t, before, after, "無權者不能替沒有發起者的輪替送出")
		var reloaded model.CredentialRotation
		require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
		assert.Nil(t, reloaded.AuthorizationID, "沒有承接")
	})
}
