package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 背景排程（到期成員掃描與候選重試排程）只推進本輪仍待處理的成員；最終失敗、已收束的
// 成員只由有人在場的逐台補跑重新下達。

// unknownRotation 兩台共用憑證的整組輪替：第二台遠端結果未知（候選保留、已送出未驗證）。
func unknownRotation(t *testing.T, host string) (*batchFixture, *secretRecorder, *model.CredentialRotation, model.CredentialRotationMember) {
	t.Helper()
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "背景推進-"+host, "ops", "old", host+".1", host+".2")
	rec := newSecretRecorder()
	rec.rotateErr[host+".2"] = &remoteStateUnknownError{reason: model.ChangeSecretReasonRemoteStateUnknown}
	f.rotations.executors = func(string) rotationExecutor { return rec }
	f.useExecutor(rec)
	rot, err := f.rotations.Start(userCtx(7, "owner"), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
	rec.rotateErr[host+".2"] = nil
	stuck := *f.memberOf(t, rot.ID, accounts[1])
	require.Equal(t, model.CredentialMemberChangedUnverified, stuck.State)
	cand, err := f.candidates.FindByAccount(stuck.AccountID)
	require.NoError(t, err)
	require.NotNil(t, cand, "前置：遠端結果未知，候選保留")
	return f, rec, rot, stuck
}

// interruptStuck 把成員改回「改密中」並跑啟動時的收束（模擬行程在下達途中結束後重啟）。
func interruptStuck(t *testing.T, f *batchFixture, member model.CredentialRotationMember) {
	t.Helper()
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", member.ID).
		Updates(map[string]any{"state": model.CredentialMemberChanging, "next_attempt_at": nil}).Error)
	n, err := f.rotations.RecoverInterruptedMembers()
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func makeCandidateDue(t *testing.T, f *batchFixture, accountID uint) {
	t.Helper()
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", accountID).
		Update("next_attempt_at", time.Now().Add(-time.Minute)).Error)
}

func candidateOf(t *testing.T, f *batchFixture, accountID uint) *model.ChangeSecretCandidate {
	t.Helper()
	cand, err := f.candidates.FindByAccount(accountID)
	require.NoError(t, err)
	return cand
}

// 最終失敗的成員：背景不重新排入、不再下達；候選保留並延後，具權者補跑照常可重新下達。
func TestBackgroundNeverRedeliversTerminalMember(t *testing.T) {
	cases := []struct {
		name      string
		interrupt bool
	}{
		{"一般的已送出未驗證逾期轉最終失敗", false},
		{"重啟時中斷轉入、之後逾期轉最終失敗", true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := []string{"10.9.90", "10.9.91"}[i]
			f, rec, rot, stuck := unknownRotation(t, host)
			if tc.interrupt {
				interruptStuck(t, f, stuck)
			}
			// 本輪起始已逾期限、候選仍在自己的期限內（成員重試過幾輪才下達就會這樣）
			require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
				Update("started_at", time.Now().Add(-25*time.Hour)).Error)
			rec.verifyErr[host+".2"] = errRemoteDropped

			makeCandidateDue(t, f, stuck.AccountID)
			f.retry.RunDue()
			require.Equal(t, model.CredentialMemberTerminalFailed, memberByID(t, f, rot.ID, stuck.ID).State,
				"前置：驗證失敗且逾期，轉最終失敗")
			_, rotate1, verify1 := rec.snapshotCalls()
			require.Equal(t, 1, rotate1[host+".2"], "前置：至此只下達過一次")

			for round := 0; round < 3; round++ {
				makeCandidateDue(t, f, stuck.AccountID)
				f.retry.RunDue()
			}
			_, rotate2, verify2 := rec.snapshotCalls()
			assert.Equal(t, rotate1[host+".2"], rotate2[host+".2"], "背景不得對最終失敗者重新下達改密")
			assert.Equal(t, verify1[host+".2"], verify2[host+".2"], "也不再登入")
			assert.Equal(t, model.CredentialMemberTerminalFailed, memberByID(t, f, rot.ID, stuck.ID).State)
			cand := candidateOf(t, f, stuck.AccountID)
			require.NotNil(t, cand, "候選保留（可能是那台唯一的新秘密）")
			assert.True(t, cand.NextAttemptAt.After(time.Now()), "候選延後，不留在每一輪都撈到的到期狀態")
			assert.False(t, cand.Abandoned, "延後不是一次嘗試，不觸發逾期放棄")

			// 有人在場的逐台補跑照常可以重新下達
			rec.verifyErr[host+".2"] = nil
			require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, stuck.ID))
			_, rotate3, _ := rec.snapshotCalls()
			assert.Equal(t, rotate1[host+".2"]+1, rotate3[host+".2"], "補跑重新下達一次")
			assert.Equal(t, model.CredentialMemberApplied, memberByID(t, f, rot.ID, stuck.ID).State)
		})
	}
}

// 已收束的成員（授權重驗停止）：背景不重新排入。
func TestBackgroundNeverRequeuesAbandonedMember(t *testing.T) {
	f, rec, rot, stuck := unknownRotation(t, "10.9.92")
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", stuck.ID).
		Updates(map[string]any{"state": model.CredentialMemberAbandoned, "next_attempt_at": nil}).Error)
	_, rotate0, verify0 := rec.snapshotCalls()
	makeCandidateDue(t, f, stuck.AccountID)
	f.retry.RunDue()
	_, rotate1, verify1 := rec.snapshotCalls()
	assert.Equal(t, rotate0["10.9.92.2"], rotate1["10.9.92.2"])
	assert.Equal(t, verify0["10.9.92.2"], verify1["10.9.92.2"])
	assert.Equal(t, model.CredentialMemberAbandoned, memberByID(t, f, rot.ID, stuck.ID).State)
}

// 重啟時中斷轉入的成員：背景以新秘密登入驗證一次即可收斂，不下達改密。
// 這與遠端結果未知時的既有處置相同（同一組退避與期限），只是登入、不改遠端。
func TestInterruptedMemberBackgroundVerifiesOnly(t *testing.T) {
	f, rec, rot, stuck := unknownRotation(t, "10.9.93")
	interruptStuck(t, f, stuck)
	require.Nil(t, memberByID(t, f, rot.ID, stuck.ID).NextAttemptAt, "前置：成員沒有自己的退避，由候選列承擔")
	_, rotate0, verify0 := rec.snapshotCalls()

	makeCandidateDue(t, f, stuck.AccountID)
	f.retry.RunDue()

	_, rotate1, verify1 := rec.snapshotCalls()
	assert.Equal(t, rotate0["10.9.93.2"], rotate1["10.9.93.2"], "不下達新的改密")
	assert.Equal(t, verify0["10.9.93.2"]+1, verify1["10.9.93.2"], "只以新秘密登入一次")
	assert.Equal(t, model.CredentialMemberApplied, memberByID(t, f, rot.ID, stuck.ID).State)
}

// 成員自己的退避未到時，候選到期不得繞過它重新下達（拆分模式乾淨失敗後候選保留，
// 若不看成員的退避，排程每分鐘都會對那台再下一次改密）。
func TestBackgroundRespectsMemberBackoff(t *testing.T) {
	f := setupBatchFixture(t)
	host := "10.9.94"
	credID, accounts := f.sharedOn(t, "背景退避", "ops", "old", host+".1", host+".2")
	rec := newSecretRecorder()
	rec.rotateErr[host+".2"] = &remoteRejectedError{reason: model.ChangeSecretReasonRemoteRejected}
	f.rotations.executors = func(string) rotationExecutor { return rec }
	f.useExecutor(rec)
	rot, err := f.rotations.StartSplit(userCtx(7, "owner"), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
	member := f.memberOf(t, rot.ID, accounts[1])
	require.Equal(t, model.CredentialMemberRetryWait, member.State)
	require.NotNil(t, candidateOf(t, f, accounts[1]), "前置：拆分模式乾淨失敗仍保留候選")
	require.NotNil(t, member.NextAttemptAt)
	require.True(t, member.NextAttemptAt.After(time.Now()), "前置：成員的退避未到")

	_, rotate0, _ := rec.snapshotCalls()
	for round := 0; round < 3; round++ {
		makeCandidateDue(t, f, accounts[1])
		f.retry.RunDue()
	}
	_, rotate1, _ := rec.snapshotCalls()
	assert.Equal(t, rotate0[host+".2"], rotate1[host+".2"], "退避未到，零額外改密")
	assert.True(t, candidateOf(t, f, accounts[1]).NextAttemptAt.After(time.Now()), "候選延後")

	// 成員到期後由背景照常推進
	delete(rec.rotateErr, host+".2")
	f.setMemberNextAttempt(t, member.ID, time.Now().Add(-time.Minute))
	f.retry.RunDue()
	assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[1]).State)
}

// 背景推進只碰進行中、目標仍是待生效版本的那一輪：放棄後或目標被取代後一律不推、遠端零 I/O。
func TestAdvanceMemberInBackgroundOnlyRunningRound(t *testing.T) {
	t.Run("已放棄的一輪", func(t *testing.T) {
		f, rec, rot, stuck := unknownRotation(t, "10.9.98")
		require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
		_, rotate0, verify0 := rec.snapshotCalls()
		advanced, err := f.rotations.AdvanceMemberInBackground(context.Background(), rot.ID, stuck.ID)
		require.NoError(t, err)
		assert.False(t, advanced)
		_, rotate1, verify1 := rec.snapshotCalls()
		assert.Equal(t, rotate0, rotate1)
		assert.Equal(t, verify0, verify1)
		assert.Equal(t, model.CredentialMemberChangedUnverified, memberByID(t, f, rot.ID, stuck.ID).State)
	})
	t.Run("待生效版本已被取代", func(t *testing.T) {
		f, rec, rot, stuck := unknownRotation(t, "10.9.89")
		require.NoError(t, f.db.Model(&model.Credential{}).Where("id = ?", rot.CredentialID).
			Update("pending_version_id", nil).Error)
		_, _, verify0 := rec.snapshotCalls()
		advanced, err := f.rotations.AdvanceMemberInBackground(context.Background(), rot.ID, stuck.ID)
		assert.Error(t, err)
		assert.False(t, advanced)
		_, _, verify1 := rec.snapshotCalls()
		assert.Equal(t, verify0, verify1, "遠端零 I/O")
	})
}

// 背景判定逐格：只有排隊、到期的等待重試與到期的已送出未驗證會被推進。
func TestMemberDueInBackground(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	for _, state := range credentialMemberStates {
		for _, at := range []*time.Time{nil, &past, &future} {
			m := &model.CredentialRotationMember{State: state, NextAttemptAt: at}
			got := memberDueInBackground(m, now)
			want := false
			switch state {
			case model.CredentialMemberQueued:
				want = true
			case model.CredentialMemberRetryWait, model.CredentialMemberChangedUnverified:
				want = at == nil || !at.After(now)
			}
			assert.Equal(t, want, got, "state=%s next=%v", state, at)
		}
	}
}

// splitAbandonedAfterDeniedRetry 拆分模式：第二台已送出未驗證、逾期轉最終失敗，放棄本輪後
// 在發起者失權時被按一次補跑，停成已收束、候選仍在。
func splitAbandonedAfterDeniedRetry(t *testing.T, host string) (*batchFixture, *secretRecorder, *model.CredentialRotation, uint, model.CredentialRotationMember) {
	t.Helper()
	f := setupBatchFixture(t)
	credID, accounts := f.sharedOn(t, "拆分放棄-"+host, "ops", "old", host+".1", host+".2", host+".3")
	rec := newSecretRecorder()
	rec.rotateErr[host+".2"] = &remoteStateUnknownError{reason: model.ChangeSecretReasonRemoteStateUnknown}
	f.rotations.executors = func(string) rotationExecutor { return rec }
	f.useExecutor(rec)
	rot, err := f.rotations.StartSplit(userCtx(7, "owner"), credID, StartRotationRequest{})
	require.NoError(t, err)
	require.NoError(t, f.rotations.Run(userCtx(7, "owner"), rot.ID))
	rec.rotateErr[host+".2"] = nil
	rec.verifyErr[host+".2"] = errRemoteDropped
	require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
		Update("started_at", time.Now().Add(-25*time.Hour)).Error)
	m2 := *f.memberOf(t, rot.ID, accounts[1])
	require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, m2.ID))
	require.Equal(t, model.CredentialMemberTerminalFailed, memberByID(t, f, rot.ID, m2.ID).State)
	require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
	got, err := f.rotations.UnsettledRotationID(credID)
	require.NoError(t, err)
	require.Equal(t, rot.ID, got, "前置：放棄後指得出這一輪")

	f.authz.deny(CredCapRotate)
	// 失權者的逐台補跑在重新排入前即被拒，不改成員狀態
	require.ErrorIs(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, m2.ID), ErrCredentialBindForbidden)
	require.Equal(t, model.CredentialMemberTerminalFailed, memberByID(t, f, rot.ID, m2.ID).State)
	// 夾具：成員經授權重驗停止而收束（背景推進遇發起者失權時的落點），候選保留
	require.NoError(t, f.db.Model(&model.CredentialRotationMember{}).Where("id = ?", m2.ID).
		Updates(map[string]any{"state": model.CredentialMemberAbandoned, "last_error": model.ChangeSecretReasonAuthzRevoked}).Error)
	m2 = memberByID(t, f, rot.ID, m2.ID)
	require.Equal(t, model.CredentialMemberAbandoned, m2.State, "前置：失權時停成已收束")
	require.NotNil(t, candidateOf(t, f, accounts[1]), "前置：候選仍在")
	return f, rec, rot, credID, m2
}

// 拆分模式放棄後，動過遠端、後來才被停成已收束、候選仍在的成員照列並給補跑。
func TestSplitAbandonedMemberWithCandidateStaysSurfaced(t *testing.T) {
	f, rec, rot, credID, m2 := splitAbandonedAfterDeniedRetry(t, "10.9.95")

	got, err := f.rotations.UnsettledRotationID(credID)
	require.NoError(t, err)
	assert.Equal(t, rot.ID, got, "候選仍在且未收束：這一輪不得從憑證頁消失")
	detail, err := f.creds.Get(adminCtx(), credID)
	require.NoError(t, err)
	assert.Equal(t, rot.ID, detail.UnsettledRotationID)
	kept, err := f.rotations.CandidateKeptMembers(rot.ID)
	require.NoError(t, err)
	assert.True(t, kept[m2.ID], "呈現面據此給這台補跑")

	// 權限恢復後具權者補跑可收斂（拆分收斂後原共用憑證即回收，這一輪標記完成）
	f.authz.allow(CredCapRotate)
	rec.verifyErr["10.9.95.2"] = nil
	require.NoError(t, f.rotations.RunMember(userCtx(7, "owner"), rot.ID, m2.ID))
	assert.Equal(t, model.CredentialMemberApplied, memberByID(t, f, rot.ID, m2.ID).State)
	done, err := loadRotation(f.db, rot.ID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialRotationCompleted, done.Status)
}

// 已放棄、仍待逐台補跑的那一輪留下的候選到期：不走單帳號路徑、不以「授權失效」告警，
// 不累計失敗次數；只延後，等人在憑證詳情補跑。
func TestAbandonedRotationCandidateSkipsSingleAccountRetry(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (*batchFixture, *secretRecorder, uint)
	}{
		{"整組", func(t *testing.T) (*batchFixture, *secretRecorder, uint) {
			f, rec, rot, stuck := unknownRotation(t, "10.9.96")
			require.NoError(t, f.rotations.Abandon(userCtx(7, "owner"), rot.ID))
			got, err := f.rotations.UnsettledRotationID(rot.CredentialID)
			require.NoError(t, err)
			require.Equal(t, rot.ID, got)
			return f, rec, stuck.AccountID
		}},
		{"拆分", func(t *testing.T) (*batchFixture, *secretRecorder, uint) {
			f, rec, _, _, m2 := splitAbandonedAfterDeniedRetry(t, "10.9.97")
			f.authz.allow(CredCapRotate)
			return f, rec, m2.AccountID
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, rec, accountID := tc.setup(t)
			notifier := audit.NewAlertNotifier(f.db, nil)
			f.retry.notifier = notifier
			before := candidateOf(t, f, accountID)
			require.NotNil(t, before)
			_, _, verify0 := rec.snapshotCalls()

			makeCandidateDue(t, f, accountID)
			promoted, failed := f.retry.RunDue()

			assert.Zero(t, promoted)
			assert.Zero(t, failed, "不算一次失敗的重試")
			assert.EqualValues(t, 0, notifier.PendingNotifications(), "不發「授權失效停止」告警")
			_, _, verify1 := rec.snapshotCalls()
			assert.Equal(t, verify0, verify1, "遠端零觸碰")
			after := candidateOf(t, f, accountID)
			require.NotNil(t, after, "候選保留")
			assert.Equal(t, before.LastError, after.LastError, "原因碼不被改寫")
			assert.Equal(t, before.AttemptCount, after.AttemptCount, "不累計次數")
			assert.True(t, after.NextAttemptAt.After(time.Now()), "延後")
		})
	}
}

// 放棄後該掛載才建立的候選（屬於計劃或批次）不被誤認為輪替留下的。
func TestRotationOwnsCandidateDiscriminates(t *testing.T) {
	finished := time.Now()
	target := uint(42)
	member := &model.CredentialRotationMember{TargetVersionID: &target}
	group := &model.CredentialRotation{Mode: model.CredentialRotationModeGroup, FinishedAt: &finished}
	split := &model.CredentialRotation{Mode: model.CredentialRotationModeSplit, FinishedAt: &finished}

	assert.True(t, rotationOwnsCandidate(group, member, &model.ChangeSecretCandidate{TargetVersionID: 42}))
	assert.False(t, rotationOwnsCandidate(group, member, &model.ChangeSecretCandidate{TargetVersionID: 43}), "另一版的候選")
	assert.False(t, rotationOwnsCandidate(group, member, &model.ChangeSecretCandidate{}), "沒帶版本的候選")
	assert.True(t, rotationOwnsCandidate(split, member, &model.ChangeSecretCandidate{CreatedAt: finished.Add(-time.Hour)}))
	assert.False(t, rotationOwnsCandidate(split, member, &model.ChangeSecretCandidate{CreatedAt: finished.Add(time.Minute)}), "放棄後才建立")
	assert.False(t, rotationOwnsCandidate(split, member, &model.ChangeSecretCandidate{TargetVersionID: 7, CreatedAt: finished.Add(-time.Hour)}), "帶版本的不是拆分候選")
}
