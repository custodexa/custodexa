package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 誰來推進輪替，以及未收斂狀態的出口。
//
// 停在等待重試的成員不會自己動：推進者是既有的候選重試排程（不另造排程器）。
// 而輪替引擎建立的候選**一律交回成員路徑**——舊的單帳號轉正會在共用憑證上多開版本、
// 繞過成員轉移表這個就位版本的唯一寫入點。

// useRotationExecutor 讓三條路徑（逐帳號、重試、輪替）共用同一個假執行器
func (f *batchFixture) useRotationExecutor(rec *secretRecorder) {
	f.useExecutor(rec)
	f.rotations.executors = func(string) rotationExecutor { return rec }
}

func (f *batchFixture) memberOf(t *testing.T, rotationID, accountID uint) *model.CredentialRotationMember {
	t.Helper()
	var m model.CredentialRotationMember
	require.NoError(t, f.db.Where("rotation_id = ? AND account_id = ?", rotationID, accountID).
		First(&m).Error)
	return &m
}

// setMemberNextAttempt 直接改寫成員的下次嘗試時刻（測試要控制「到期」這件事，
// 而退避常數是分鐘級的）
func (f *batchFixture) setMemberNextAttempt(t *testing.T, memberID uint, at time.Time) {
	t.Helper()
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).
		Where("id = ?", memberID).Update("next_attempt_at", at).Error)
}

// 到期的輪替成員由既有的候選重試排程推進；未到期的不動
func TestRetryRunnerAdvancesRotationMembers(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "待推進", "ops", "old-shared",
		"10.5.0.1", "10.5.0.2", "10.5.0.3")
	rec := newSecretRecorder()
	// 乙、丙的遠端確定拒絕：兩者都退成等待重試，且候選被清除
	// （故此刻只有成員列記得它們還沒改完）
	rec.rotateErr["10.5.0.2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	rec.rotateErr["10.5.0.3"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	f.useRotationExecutor(rec)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	memberB := f.memberOf(t, rot.ID, accounts[1])
	memberC := f.memberOf(t, rot.ID, accounts[2])
	require.Equal(t, model.CredentialMemberRetryWait, memberB.State)
	require.Equal(t, model.CredentialMemberRetryWait, memberC.State)
	assert.Zero(t, f.candidateCount(t), "乾淨失敗的候選已清除，只有成員列記得")

	// 遠端恢復，且只有乙到期
	rec.mu.Lock()
	delete(rec.rotateErr, "10.5.0.2")
	delete(rec.rotateErr, "10.5.0.3")
	rec.mu.Unlock()
	f.setMemberNextAttempt(t, memberB.ID, time.Now().Add(-time.Minute))
	f.setMemberNextAttempt(t, memberC.ID, time.Now().Add(time.Hour))

	f.retry.RunDue()

	assert.Equal(t, model.CredentialMemberApplied,
		f.memberOf(t, rot.ID, accounts[1]).State, "到期的成員被推進")
	assert.Equal(t, model.CredentialMemberRetryWait,
		f.memberOf(t, rot.ID, accounts[2]).State, "未到期的成員不動")
	_, rotateCalls, _ := rec.snapshotCalls()
	assert.Equal(t, 2, rotateCalls["10.5.0.2"], "到期者重下一次改密")
	assert.Equal(t, 1, rotateCalls["10.5.0.3"], "未到期者零額外遠端往返")
}

// 輪替來源的候選到期時走成員路徑：共用憑證的版本數不變，就位版本只由轉移表改
func TestRetryRunnerRoutesRotationCandidatesToMember(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "候選歸屬", "ops", "old-shared", "10.5.1.1", "10.5.1.2")
	accB := accounts[1]
	rec := newSecretRecorder()
	rec.verifyErr["10.5.1.2"] = errRemoteDropped
	f.useRotationExecutor(rec)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	pendingVersion := *rot.TargetVersionID
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	memberB := f.memberOf(t, rot.ID, accB)
	require.Equal(t, model.CredentialMemberChangedUnverified, memberB.State)
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", accB).First(&cand).Error)

	// 舊的單帳號轉正路徑對輪替來源的候選必須零觸發（含 admin 手動觸發）
	assert.False(t, f.retry.RetryOne(&cand), "輪替來源的候選不得走單帳號轉正")
	assert.EqualValues(t, 2, f.versionCountOf(t, credID), "單帳號轉正若跑了，這裡會多一版")

	// 讓候選到期、成員未到期：唯一還能推進它的就是候選列的歸屬分流
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
		Update("next_attempt_at", time.Now().Add(-time.Minute)).Error)
	f.setMemberNextAttempt(t, memberB.ID, time.Now().Add(time.Hour))
	rec.mu.Lock()
	delete(rec.verifyErr, "10.5.1.2")
	rec.mu.Unlock()

	f.retry.RunDue()

	assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accB).State,
		"候選經成員路徑推進到就位")
	binding := f.bindingOf(t, accB)
	require.NotNil(t, binding.EffectiveVersionID)
	assert.Equal(t, pendingVersion, *binding.EffectiveVersionID,
		"就位版本是本輪的待生效版本，不是另開的一版")
	assert.EqualValues(t, 2, f.versionCountOf(t, credID), "共用憑證的版本數不變")
	cred := f.credentialOf(t, credID)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, pendingVersion, *cred.CurrentVersionID, "全部就位後收斂")
	assert.Nil(t, cred.PendingVersionID)
	assert.Zero(t, f.candidateCount(t))
}

// 放棄後的輪替仍可逐台補跑至收斂：重用同一個待生效版本，版本表只多一列
func TestAbandonedRotationMemberRerunConverges(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "放棄後補跑", "ops", "old-shared", "10.5.2.1", "10.5.2.2")
	rec := newSecretRecorder()
	rec.verifyErr["10.5.2.1"] = errRemoteDropped
	rec.verifyErr["10.5.2.2"] = errRemoteDropped
	f.useRotationExecutor(rec)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	pendingVersion := *rot.TargetVersionID
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
	require.NoError(t, f.rotations.Abandon(adminCtx(), rot.ID))

	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	require.Equal(t, CredentialAggregateOutOfSync, state, "已下達未驗證者使本輪進入未同步")

	rec.mu.Lock()
	delete(rec.verifyErr, "10.5.2.1")
	delete(rec.verifyErr, "10.5.2.2")
	rec.mu.Unlock()
	for _, accountID := range accounts {
		member := f.memberOf(t, rot.ID, accountID)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID),
			"放棄後仍可逐台補跑")
	}

	for _, accountID := range accounts {
		assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accountID).State)
		binding := f.bindingOf(t, accountID)
		require.NotNil(t, binding.EffectiveVersionID)
		assert.Equal(t, pendingVersion, *binding.EffectiveVersionID, "補跑重用同一個待生效版本")
	}
	assert.EqualValues(t, 2, f.versionCountOf(t, credID), "版本表只多一列")

	cred := f.credentialOf(t, credID)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, pendingVersion, *cred.CurrentVersionID, "全部就位即提升現行版本")
	assert.Nil(t, cred.PendingVersionID, "清空待生效指標")
	done, err := loadRotation(f.db, rot.ID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationCompleted, done.Status, "輪替標記完成")

	state, err = f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.Equal(t, CredentialAggregateIdle, state)
}

// 全員終局失敗時聚合態不得誤報「改密進行中」
func TestAggregateStateAllTerminalFailed(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "全員失敗", "ops", "old-shared", "10.5.3.1", "10.5.3.2")
	rec := newSecretRecorder()
	rec.verifyErr["10.5.3.1"] = errRemoteDropped
	rec.verifyErr["10.5.3.2"] = errRemoteDropped
	f.useRotationExecutor(rec)

	rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
	require.NoError(t, err)
	// 本輪已逾重試期限：驗證再失敗即轉終局失敗
	require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
		Update("started_at", time.Now().Add(-2*candidateRetryDeadline)).Error)
	require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))

	for _, accountID := range accounts {
		require.Equal(t, model.CredentialMemberTerminalFailed,
			f.memberOf(t, rot.ID, accountID).State)
	}
	state, err := f.rotations.AggregateState(credID)
	require.NoError(t, err)
	assert.NotEqual(t, CredentialAggregateChanging, state,
		"沒有任何一台還在動，報成進行中會讓操作者等一個不會發生的進展")
	assert.Equal(t, CredentialAggregateOutOfSync, state)
}

// 脫離共用的新秘密來源是二擇一：空值一律拒絕，不得預設成隨機
func TestDetachRejectsEmptySource(t *testing.T) {
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "脫離來源", "ops", "old-shared", "10.5.4.1", "10.5.4.2")
	rec := newSecretRecorder()
	f.useRotationExecutor(rec)

	_, err := f.rotations.Detach(adminCtx(), credID, accounts[0], DetachCredentialRequest{})
	assert.ErrorIs(t, err, ErrCredentialDetachSourceInvalid, "空值不得被讀成隨機")
	_, err = f.rotations.Detach(adminCtx(), credID, accounts[0],
		DetachCredentialRequest{Source: "whatever"})
	assert.ErrorIs(t, err, ErrCredentialDetachSourceInvalid)

	var rotations int64
	require.NoError(t, f.db.Model(&model.CredentialRotation{}).Count(&rotations).Error)
	assert.Zero(t, rotations, "被拒的請求不得留下輪替列")
	assert.Empty(t, rec.secretOf("10.5.4.1"), "遠端零觸碰")

	// 明示的隨機來源仍照常運作
	_, err = f.rotations.Detach(adminCtx(), credID, accounts[0],
		DetachCredentialRequest{Source: DetachSourceRandom})
	require.NoError(t, err)
	assert.NotEqual(t, credID, f.bindingOf(t, accounts[0]).CredentialID, "脫離成功即改綁")
}
