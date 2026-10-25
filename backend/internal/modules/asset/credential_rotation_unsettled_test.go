package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// unsettledRotation 三台共用憑證的輪替：第一台就位、第二台已送出未驗證、第三台等待重試，
// 回傳成員（依掛載順序）與錄製器。
func unsettledRotation(t *testing.T, host string) (*batchFixture, *secretRecorder, *model.CredentialRotation, uint, []model.CredentialRotationMember) {
	t.Helper()
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "放棄後補跑-"+host, "ops", "old", host+".1", host+".2", host+".3")
	rec := newSecretRecorder()
	rec.verifyErr[host+".2"] = errRemoteDropped
	rec.rotateErr[host+".3"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	f.rotations.executors = func(string) rotationExecutor { return rec }
	rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
	members, err := f.rotations.Members(rot.ID)
	require.NoError(t, err)
	byAccount := map[uint]model.CredentialRotationMember{}
	for _, m := range members {
		byAccount[m.AccountID] = m
	}
	ordered := []model.CredentialRotationMember{byAccount[accounts[0]], byAccount[accounts[1]], byAccount[accounts[2]]}
	require.Equal(t, model.CredentialMemberApplied, ordered[0].State)
	require.Equal(t, model.CredentialMemberChangedUnverified, ordered[1].State)
	require.Equal(t, model.CredentialMemberRetryWait, ordered[2].State)
	return f, rec, rot, credID, ordered
}

// 放棄一輪已動過主機的輪替後，那一輪在憑證詳情仍指得出來，逐台補跑可把剩下的主機
// （含放棄時從未動過而收束的那一台）推到收斂；收斂後入口消失。
func TestAbandonedRotationStaysReachableUntilConverged(t *testing.T) {
	f, rec, rot, credID, members := unsettledRotation(t, "10.9.70")
	require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))

	got, err := f.rotations.UnsettledRotationID(credID)
	require.NoError(t, err)
	assert.Equal(t, rot.ID, got, "放棄後仍指得出未收束的那一輪")
	detail, err := f.creds.Get(adminCtx(), credID)
	require.NoError(t, err)
	assert.Zero(t, detail.ActiveRotationID, "前置條件：進行中識別已清空")
	assert.Equal(t, rot.ID, detail.UnsettledRotationID, "詳情帶回那一輪")
	assert.Equal(t, model.CredentialMemberAbandoned, memberByID(t, f, rot.ID, members[2].ID).State,
		"前置條件：等待重試且從未下達的那一台在放棄時收束")

	rec.verifyErr["10.9.70.2"] = nil
	rec.rotateErr["10.9.70.3"] = nil
	require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, members[2].ID))
	assert.Equal(t, model.CredentialMemberApplied, memberByID(t, f, rot.ID, members[2].ID).State)
	got, err = f.rotations.UnsettledRotationID(credID)
	require.NoError(t, err)
	assert.Equal(t, rot.ID, got, "還有一台未就位，入口仍在")

	require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, members[1].ID))
	assert.Equal(t, model.CredentialMemberApplied, memberByID(t, f, rot.ID, members[1].ID).State)
	got, err = f.rotations.UnsettledRotationID(credID)
	require.NoError(t, err)
	assert.Zero(t, got, "全部就位即收斂，入口消失")
	cred, err := loadCredential(f.db, credID)
	require.NoError(t, err)
	assert.Nil(t, cred.PendingVersionID, "收斂後待生效版本已提升")
	var reloaded model.CredentialRotation
	require.NoError(t, f.db.Where("id = ?", rot.ID).First(&reloaded).Error)
	assert.Equal(t, model.CredentialRotationCompleted, reloaded.Status)
}

// 不再需要補跑的已放棄輪替不給入口：待生效版本已被取代、或未就位的掛載都已卸下。
func TestAbandonedRotationWithoutUnsettledMembersIsNotSurfaced(t *testing.T) {
	t.Run("待生效版本已被取代", func(t *testing.T) {
		f, _, rot, credID, _ := unsettledRotation(t, "10.9.71")
		require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
		require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", credID).
			Update("pending_version_id", nil).Error)
		got, err := f.rotations.UnsettledRotationID(credID)
		require.NoError(t, err)
		assert.Zero(t, got)
	})
	t.Run("未就位的掛載都已卸下", func(t *testing.T) {
		f, _, rot, credID, members := unsettledRotation(t, "10.9.72")
		require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
		require.NoError(t, f.db.Delete(&model.AssetAccount{}, []uint{members[1].AccountID, members[2].AccountID}).Error)
		got, err := f.rotations.UnsettledRotationID(credID)
		require.NoError(t, err)
		assert.Zero(t, got)
	})
	t.Run("仍在執行時以進行中那一輪為準", func(t *testing.T) {
		f, _, _, credID, _ := unsettledRotation(t, "10.9.73")
		got, err := f.rotations.UnsettledRotationID(credID)
		require.NoError(t, err)
		assert.Zero(t, got)
	})
}

// 放棄後給補跑的成員狀態：就位與改密中以外；拆分模式的已收束成員看候選還在不在
// （放棄時未動過的連候選都清掉了，無物可推；動過遠端後才被停成收束的候選仍在，照給）。
func TestMemberRetryableAfterAbandon(t *testing.T) {
	for _, state := range credentialMemberStates {
		for _, kept := range []bool{false, true} {
			group := memberRetryableAfterAbandon(model.CredentialRotationModeGroup, state, kept)
			split := memberRetryableAfterAbandon(model.CredentialRotationModeSplit, state, kept)
			switch state {
			case model.CredentialMemberApplied, model.CredentialMemberChanging:
				assert.False(t, group, state)
				assert.False(t, split, state)
			case model.CredentialMemberAbandoned:
				assert.True(t, group, state)
				assert.Equal(t, kept, split, "%s kept=%v", state, kept)
			default:
				assert.True(t, group, state)
				assert.True(t, split, state)
			}
		}
	}
}
