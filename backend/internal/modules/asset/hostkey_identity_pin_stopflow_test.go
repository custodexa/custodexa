package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 接入正式停止分支後的端到端子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.5/ 與 3.4/）：
// 提交階段的停止審計、同一身分狀態退避多輪只留一筆、A -> B -> A 與記錄重建各留一筆、
// 審計寫入失敗時仍停止且去重鍵不前進、期限（候選放棄、成員逾期後重排仍被擋）。
// 夾具的綁定與主機金鑰記錄都經正式回呼建立；異動走採用、重置與重新記錄的資料面結果。

// verifyAfterExecutor 在 Verify 成功之後（本地提交之前）插入一段動作。
type verifyAfterExecutor struct {
	rotationExecutor
	after func()
}

func (h verifyAfterExecutor) Verify(ctx context.Context, rt rotationTarget, secret []byte) error {
	err := h.rotationExecutor.Verify(ctx, rt, secret)
	if err == nil && h.after != nil {
		h.after()
	}
	return err
}

// bumpAfterVerify 驗證成功之後主機身分被換掉：經正式不符觀察加 Adopt 採用另一把金鑰（世代加一）。
func bumpAfterVerify(t *testing.T, db *gorm.DB, assetID uint, fired *int) func() {
	return func() {
		*fired++
		adoptObservedKey(t, db, assetID, genHostKey(t))
	}
}

// adoptBackTo 靶機換回指定金鑰，並經正式觀察加 Adopt 採用（世代加一）。
func adoptBackTo(t *testing.T, srv *testSSHServer, db *gorm.DB, assetID uint, signer ssh.Signer) {
	t.Helper()
	adoptBackToSigner(t, srv, db, assetID, signer)
}

// requireStopSeq 停止審計依序為給定的 (detail, phase, verification_sent)。
func requireStopSeq(t *testing.T, stops []map[string]any, want ...[3]string) {
	t.Helper()
	require.Len(t, stops, len(want), "每個身分狀態 token 恰一筆停止審計")
	for i, w := range want {
		assert.Equal(t, w[0], stops[i]["detail"], "第 %d 筆 detail", i+1)
		assert.Equal(t, w[1], stops[i]["phase"], "第 %d 筆 phase", i+1)
		assert.Equal(t, w[2], stops[i]["verification_sent"], "第 %d 筆 verification_sent", i+1)
		assert.Equal(t, true, stops[i]["candidate_retained"])
	}
}

// runCommitStopCandidate 一般候選的三條提交路徑：驗證成功之後提交之前主機身分被換掉，
// 不提交、候選保留、原因碼為身分變更，並留下 phase=commit、verification_sent=true 的停止審計。
func runCommitStopCandidate(t *testing.T) {
	commitStop := [3]string{hostIdentityCommitGenerationChanged, hostIdentityPhaseCommit, verificationSentTrue}

	t.Run("一般密碼rotatePassword", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		wireStopAudit(f)
		fired := 0
		orig := f.runner.executors
		f.runner.executors = func(ch string) rotationExecutor {
			return verifyAfterExecutor{orig(ch), bumpAfterVerify(t, f.db, f.assetID, &fired)}
		}
		records := f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
		assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, f).LastError)
		assert.EqualValues(t, 1, f.candidateCount(t), "候選保留")
		assert.Equal(t, "oldpass123", f.storedPassword(t), "本地憑證不動")
		requireStopSeq(t, stopAuditDetails(t, f), commitStop)
	})

	t.Run("一般SSH金鑰rotateKey", func(t *testing.T) {
		f := keyRotationFixture(t)
		wireStopAudit(f)
		fired := 0
		orig := f.runner.executors
		f.runner.executors = func(ch string) rotationExecutor {
			return verifyAfterExecutor{orig(ch), bumpAfterVerify(t, f.db, f.assetID, &fired)}
		}
		records := f.runner.RunPlan(f.keyPlan(t))
		require.Len(t, records, 1)
		require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
		assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, f).LastError)
		assert.EqualValues(t, 1, f.candidateCount(t), "候選保留")
		requireStopSeq(t, stopAuditDetails(t, f), commitStop)
	})

	t.Run("retry轉正RetryOneAs", func(t *testing.T) {
		s := newRetryScenario(t)
		fired := 0
		orig := s.f.retry.executors
		s.f.retry.executors = func(ch string) rotationExecutor {
			return verifyAfterExecutor{orig(ch), bumpAfterVerify(t, s.f.db, s.f.assetID, &fired)}
		}
		assert.False(t, s.retry(t, false))
		require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
		assert.EqualValues(t, s.baseAuth+1, s.f.server.authAttempts.Load(), "驗證登入恰一次")
		assert.EqualValues(t, 1, s.f.candidateCount(t), "候選保留")
		assert.Equal(t, "oldpass123", s.f.storedPassword(t))
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, s.f).LastError)
		requireStopSeq(t, stopAuditDetails(t, s.f), commitStop)
	})
}

// runCommitStopMember 整組與拆分成員的提交交易被擋下：phase=commit 的成員停止審計。
func runCommitStopMember(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "整組commitGroupApplied"
		if split {
			name = "拆分commitSplitApplied"
		}
		t.Run(name, func(t *testing.T) {
			f := setupBatchFixture(t)
			credID, accounts := f.sharedOn(t, "提交停止", "ops", "old-shared", "10.36.1.1", "10.36.1.2")
			assetID := f.bindingOf(t, accounts[1]).AssetID
			rec := newSecretRecorder()
			fired := bumpGenerationAfterVerify(t, f, rec, "10.36.1.2", assetID)
			f.useRotationExecutor(rec)
			var rot *model.CredentialRotation
			var err error
			if split {
				rot, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
			} else {
				rot, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
			}
			require.NoError(t, err)
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			require.EqualValues(t, 1, fired.Load(), "注入器必須真的觸發（否則為假綠）")

			bad := f.memberOf(t, rot.ID, accounts[1])
			stops := memberStops(t, f.db)
			requireStopSeq(t, stops, [3]string{hostIdentityCommitGenerationChanged, hostIdentityPhaseCommit, verificationSentTrue})
			assert.Equal(t, "member", stops[0]["job_kind"])
			assert.EqualValues(t, bad.ID, stops[0]["member_id"])
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, stops[0]["reason"])
			assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[0]).State, "另一台不受影響，不留停止審計")
		})
	}
}

// runRetryStopTokens 候選重試路徑的去重與 token 轉移。
func runRetryStopTokens(t *testing.T) {
	prec := func(detail string) [3]string {
		return [3]string{detail, hostIdentityPhasePrecheck, verificationSentFalse}
	}

	t.Run("同一token退避多輪恰一筆且通知一次", func(t *testing.T) {
		s := newRetryScenario(t)
		notifier := audit.NewAlertNotifier(s.f.db, nil)
		s.f.retry.notifier = notifier
		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		attempts := candidateOfAccount(t, s.f).AttemptCount
		for i := 0; i < 4; i++ {
			assert.False(t, s.retry(t, i%2 == 1))
		}
		requireStopSeq(t, stopAuditDetails(t, s.f), prec(hostIdentityGenerationChanged))
		assert.EqualValues(t, 1, notifier.PendingNotifications(), "退避多輪只通知一次")
		assert.EqualValues(t, attempts+4, candidateOfAccount(t, s.f).AttemptCount, "每輪都仍停止、仍累計次數")
		s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	})

	t.Run("A到B再回A寫兩筆", func(t *testing.T) {
		s := newRetryScenario(t)
		notifier := audit.NewAlertNotifier(s.f.db, nil)
		s.f.retry.notifier = notifier
		orig := s.f.server.currentHostKey()
		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		assert.False(t, s.retry(t, false))
		assert.False(t, s.retry(t, false))
		adoptBackTo(t, s.f.server, s.f.db, s.f.assetID, orig)
		assert.False(t, s.retry(t, false))
		assert.False(t, s.retry(t, false))
		requireStopSeq(t, stopAuditDetails(t, s.f), prec(hostIdentityGenerationChanged), prec(hostIdentityGenerationChanged))
		assert.EqualValues(t, 2, notifier.PendingNotifications())
		s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	})

	t.Run("record_missing首次一筆與刪列重建各一筆", func(t *testing.T) {
		s := newRetryScenario(t)
		notifier := audit.NewAlertNotifier(s.f.db, nil)
		s.f.retry.notifier = notifier
		require.NoError(t, s.f.db.Where("asset_id = ?", s.f.assetID).Delete(&model.AssetHostKey{}).Error)
		assert.False(t, s.retry(t, false))
		assert.False(t, s.retry(t, false))
		requireStopSeq(t, stopAuditDetails(t, s.f), prec(hostIdentityRecordMissing))
		rerecordCurrentKey(t, s)
		assert.False(t, s.retry(t, false))
		assert.False(t, s.retry(t, false))
		requireStopSeq(t, stopAuditDetails(t, s.f), prec(hostIdentityRecordMissing), prec(hostIdentityGenerationChanged))
		assert.EqualValues(t, 2, notifier.PendingNotifications())
		s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	})

	t.Run("審計寫入失敗仍停止且去重鍵不前進", func(t *testing.T) {
		s := newRetryScenario(t)
		notifier := audit.NewAlertNotifier(s.f.db, nil)
		s.f.retry.notifier = notifier
		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		s.f.retry.auditTx = failingAuditTxSink{}
		assert.False(t, s.retry(t, false))
		s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
		assert.Empty(t, stopAuditDetails(t, s.f), "審計寫不進去：不留半筆")
		assert.Nil(t, candidateOfAccount(t, s.f).HostIdentityAlertedKey, "去重鍵不前進")
		assert.EqualValues(t, 0, notifier.PendingNotifications(), "審計失敗不通知")

		s.f.retry.auditTx = audit.NewTxSink()
		assert.False(t, s.retry(t, false))
		s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
		requireStopSeq(t, stopAuditDetails(t, s.f), prec(hostIdentityGenerationChanged))
		assert.NotNil(t, candidateOfAccount(t, s.f).HostIdentityAlertedKey)
		assert.EqualValues(t, 1, notifier.PendingNotifications())
	})
}

// runMemberStopTokens 成員補跑驗證路徑的同一組去重與 token 轉移案例。
func runMemberStopTokens(t *testing.T) {
	prec := func(detail string) [3]string {
		return [3]string{detail, hostIdentityPhasePrecheck, verificationSentFalse}
	}
	run := func(t *testing.T, f *memberBindFixture, rotID, memberID uint) {
		t.Helper()
		require.NoError(t, f.rotations.RunMember(adminCtx(), rotID, memberID))
	}
	memberKey := func(t *testing.T, f *memberBindFixture, memberID uint) *string {
		var m model.CredentialRotationMember
		require.NoError(t, f.db.First(&m, memberID).Error)
		return m.HostIdentityAlertedKey
	}

	t.Run("同一token退避多輪恰一筆且通知一次", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		cap := &stopNotifyCapture{}
		f.rotations.WithStopNotifier(cap.fn)
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		base := f.server.authAttempts.Load()
		for i := 0; i < 4; i++ {
			run(t, f, rot.ID, m.ID)
		}
		requireStopSeq(t, memberStops(t, f.db), prec(hostIdentityGenerationChanged))
		identityNotices := 0
		for _, r := range cap.rule {
			if r == hostIdentityStopRule {
				identityNotices++
			}
		}
		assert.Equal(t, 1, identityNotices, "退避多輪只通知一次")
		assert.EqualValues(t, base, f.server.authAttempts.Load(), "沒有任何認證嘗試")
		requireMemberHeld(t, f, rot.ID)
	})

	t.Run("A到B再回A寫兩筆", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		cap := &stopNotifyCapture{}
		f.rotations.WithStopNotifier(cap.fn)
		orig := f.server.currentHostKey()
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		run(t, f, rot.ID, m.ID)
		run(t, f, rot.ID, m.ID)
		adoptBackTo(t, f.server, f.db, f.assetID, orig)
		run(t, f, rot.ID, m.ID)
		run(t, f, rot.ID, m.ID)
		requireStopSeq(t, memberStops(t, f.db), prec(hostIdentityGenerationChanged), prec(hostIdentityGenerationChanged))
		n := 0
		for _, r := range cap.rule {
			if r == hostIdentityStopRule {
				n++
			}
		}
		assert.Equal(t, 2, n)
		requireMemberHeld(t, f, rot.ID)
	})

	t.Run("record_missing首次一筆與刪列重建各一筆", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		require.NoError(t, f.db.Where("asset_id = ?", f.assetID).Delete(&model.AssetHostKey{}).Error)
		base := f.server.authAttempts.Load()
		run(t, f, rot.ID, m.ID)
		run(t, f, rot.ID, m.ID)
		requireStopSeq(t, memberStops(t, f.db), prec(hostIdentityRecordMissing))
		host, port := serverAddr2(t, f.server)
		_, err := f.rotations.hostKeys.Evaluate(f.assetID, host, port, f.server.currentHostKey().PublicKey())
		require.NoError(t, err)
		run(t, f, rot.ID, m.ID)
		run(t, f, rot.ID, m.ID)
		requireStopSeq(t, memberStops(t, f.db), prec(hostIdentityRecordMissing), prec(hostIdentityGenerationChanged))
		assert.EqualValues(t, base, f.server.authAttempts.Load(), "沒有任何認證嘗試")
		requireMemberHeld(t, f, rot.ID)
	})

	t.Run("審計寫入失敗仍停止且去重鍵不前進", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		cap := &stopNotifyCapture{}
		f.rotations.WithStopNotifier(cap.fn)
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		base := f.server.authAttempts.Load()
		good := f.rotations.auditTx
		f.rotations.auditTx = failingAuditTxSink{}
		_ = f.rotations.RunMember(adminCtx(), rot.ID, m.ID)
		requireMemberHeld(t, f, rot.ID)
		assert.EqualValues(t, base, f.server.authAttempts.Load(), "沒有任何認證嘗試")
		assert.Empty(t, memberStops(t, f.db), "審計寫不進去：不留半筆")
		assert.Nil(t, memberKey(t, f, m.ID), "去重鍵不前進")
		for _, r := range cap.rule {
			assert.NotEqual(t, hostIdentityStopRule, r, "審計失敗不通知")
		}

		f.rotations.auditTx = good
		run(t, f, rot.ID, m.ID)
		requireMemberHeld(t, f, rot.ID)
		requireStopSeq(t, memberStops(t, f.db), prec(hostIdentityGenerationChanged))
		assert.NotNil(t, memberKey(t, f, m.ID))
	})
}

// runStopDeadlines 期限：候選於 24 小時後 Abandoned 且列仍在；成員逾期轉終止失敗，重排後下達仍被擋下。
func runStopDeadlines(t *testing.T) {
	t.Run("候選24小時後Abandoned且列仍在", func(t *testing.T) {
		s := newRetryScenario(t)
		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		assert.False(t, s.retry(t, false))
		assert.False(t, candidateOfAccount(t, s.f).Abandoned, "期限內不放棄")
		require.NoError(t, s.f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", s.f.accountID).
			Update("created_at", time.Now().Add(-candidateRetryDeadline-time.Hour)).Error)
		assert.False(t, s.retry(t, false))
		cand := candidateOfAccount(t, s.f)
		assert.True(t, cand.Abandoned, "逾期放棄")
		assert.EqualValues(t, 1, s.f.candidateCount(t), "列仍在")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, cand.LastError)
		assert.EqualValues(t, s.baseAuth, s.f.server.authAttempts.Load(), "全程沒有認證嘗試")
		requireStopSeq(t, stopAuditDetails(t, s.f), [3]string{hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse})
		var logged map[string]any = stopAuditDetails(t, s.f)[0]
		assert.NotEmpty(t, logged["deadline"], "審計帶原截止時間")
	})

	t.Run("成員逾期轉終止失敗且重排後仍被擋", func(t *testing.T) {
		f, rot, m := sentUnverified(t, false)
		adoptRemoteKey(t, f.server, f.db, f.assetID, true)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		requireMemberHeld(t, f, rot.ID)
		require.NoError(t, f.db.Model(&model.CredentialRotation{}).Where("id = ?", rot.ID).
			Update("started_at", time.Now().Add(-candidateRetryDeadline-time.Hour)).Error)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		after := f.member(t, rot.ID)
		require.Equal(t, model.CredentialMemberTerminalFailed, after.State, "逾期轉終止失敗")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, after.LastError)

		// 重排後下達：仍被撥號前查庫擋下，遠端零 I/O
		rotates := 0
		f.wrapExecutors(func(e rotationExecutor) rotationExecutor { return rotateCounter{e, &rotates} })
		f.server.authAttempts.Store(0)
		f.server.chpasswdCalls.Store(0)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, m.ID))
		again := f.member(t, rot.ID)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, again.LastError, "回新碼")
		assert.NotEqual(t, model.CredentialMemberApplied, again.State)
		assert.EqualValues(t, 0, f.server.authAttempts.Load(), "遠端零 I/O")
		assert.EqualValues(t, 0, f.server.chpasswdCalls.Load())
		assert.Equal(t, 0, rotates, "Rotate 呼叫 0")
		requireStopSeq(t, memberStops(t, f.db), [3]string{hostIdentityGenerationChanged, hostIdentityPhasePrecheck, verificationSentFalse})
	})
}
