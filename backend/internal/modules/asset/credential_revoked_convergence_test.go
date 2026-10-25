package asset

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// revokedCandidate 建一個「已下達、驗證未過、之後發起者失權」的候選：
// 批次第二台的驗證失敗，候選留著且 Applied；回傳候選與資產識別。
func (f *batchFixture) revokedCandidate(t *testing.T, rec *secretRecorder, host1, host2 string) (model.ChangeSecretCandidate, uint) {
	t.Helper()
	f.addHost(t, "h1", host1, "ops")
	a2, acc2 := f.addHost(t, "h2", host2, "ops")
	// 主機金鑰記錄與綁定快照都經正式回呼建立：遠端出示這把鑰，第一次握手即記錄並綁定
	rec.hostKey = genHostKey(t)
	rec.verifyErr[host2] = errRemoteDropped
	f.useExecutor(rec)
	batch, ids, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "batcher")
	require.NoError(t, err)
	f.runner.RunBatch(batch, ids)
	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("account_id = ?", acc2).First(&cand).Error)
	require.True(t, cand.Applied, "下達成功、驗證失敗：候選應標已下達")
	require.NotEmpty(t, cand.TargetFingerprint, "建立時就固定目標指紋")
	require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding, "首次派送經綁定回呼：候選應已綁定")
	rec.mu.Lock()
	delete(rec.verifyErr, host2)
	rec.mu.Unlock()
	return cand, a2
}

func TestCredentialRevokedConvergence(t *testing.T) {
	t.Run("已下達未知且失權：只 Verify 與本地提交，不 Rotate，留痕不含秘密", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.1.1", "10.20.1.2")
		f.retry.WithAuditSink(audit.NewTxSink())
		_, rotBefore, verBefore := rec.snapshotCalls()
		f.authz.deny(CredCapAccountRotate)

		assert.True(t, f.retry.RetryOne(&cand), "失權但已下達且目標未變：可驗證並提交")
		_, rotAfter, verAfter := rec.snapshotCalls()
		assert.Equal(t, rotBefore, rotAfter, "不得 Rotate")
		assert.Equal(t, verBefore["10.20.1.2"]+1, verAfter["10.20.1.2"], "只做一次 Verify")
		assert.Zero(t, f.candidateCountFor(t, cand.AccountID), "本地提交後候選已刪")

		var logs []model.AuditLog
		require.NoError(t, f.db.Where("details LIKE ?", "%recovery_verify%").Find(&logs).Error)
		require.Len(t, logs, 1)
		assert.NotContains(t, logs[0].Details, "old-")
		assert.NotContains(t, strings.ToLower(logs[0].Details), "password")
	})

	t.Run("prepared（未確認下達）不給例外", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.2.1", "10.20.2.2")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("applied", false).Error)
		cand.Applied = false
		_, _, verBefore := rec.snapshotCalls()
		f.authz.deny(CredCapAccountRotate)

		assert.False(t, f.retry.RetryOne(&cand))
		_, _, verAfter := rec.snapshotCalls()
		assert.Equal(t, verBefore, verAfter, "遠端零觸碰")
		assert.Equal(t, model.ChangeSecretReasonAuthzRevoked, f.candidateOf(t, cand.ID).LastError)
	})

	t.Run("目標漂移（改址）或缺證據一律拒絕", func(t *testing.T) {
		for name, mutate := range map[string]func(f *batchFixture, cand *model.ChangeSecretCandidate, assetID uint){
			"改址": func(f *batchFixture, _ *model.ChangeSecretCandidate, assetID uint) {
				require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", assetID).
					Update("host", "10.99.99.99").Error)
			},
			"改綁憑證": func(f *batchFixture, cand *model.ChangeSecretCandidate, _ uint) {
				require.NoError(t, f.db.Model(&model.AssetAccount{}).Where("id = ?", cand.AccountID).
					Update("credential_id", 424242).Error)
			},
			"指紋缺失": func(f *batchFixture, cand *model.ChangeSecretCandidate, _ uint) {
				require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
					Update("target_fingerprint", "").Error)
				cand.TargetFingerprint = ""
			},
			"主機金鑰記錄被重置": func(f *batchFixture, _ *model.ChangeSecretCandidate, assetID uint) {
				require.NoError(t, f.db.Where("asset_id = ?", assetID).Delete(&model.AssetHostKey{}).Error)
			},
		} {
			t.Run(name, func(t *testing.T) {
				f := setupBatchFixture(t)
				rec := newSecretRecorder()
				cand, assetID := f.revokedCandidate(t, rec, "10.20.3.1", "10.20.3.2")
				mutate(f, &cand, assetID)
				_, _, verBefore := rec.snapshotCalls()
				f.authz.deny(CredCapAccountRotate)

				assert.False(t, f.retry.RetryOne(&cand))
				_, _, verAfter := rec.snapshotCalls()
				assert.Equal(t, verBefore, verAfter, "不把候選送向新目的地")
				kept := f.candidateOf(t, cand.ID)
				if name == "主機金鑰記錄被重置" {
					// 綁定的主機身分已不是資產當下的記錄：歸主機身分變更，細節為記錄缺失
					assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, kept.LastError)
					var asset model.Asset
					require.NoError(t, f.db.First(&asset, assetID).Error)
					assert.Equal(t, hostIdentityRecordMissing,
						hostIdentityVerdict(f.db, hostIdentityJobOfCandidate(kept), &asset))
					return
				}
				assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, kept.LastError)
			})
		}
	})

	t.Run("超過 24 小時：停止、保留候選並沿原放棄告警，重試不延時", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.4.1", "10.20.4.2")
		old := time.Now().Add(-25 * time.Hour)
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("created_at", old).Error)
		cand.CreatedAt = old
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		_, _, verBefore := rec.snapshotCalls()
		f.authz.deny(CredCapAccountRotate)

		assert.False(t, f.retry.RetryOne(&cand))
		_, _, verAfter := rec.snapshotCalls()
		assert.Equal(t, verBefore, verAfter)
		kept := f.candidateOf(t, cand.ID)
		assert.Equal(t, model.ChangeSecretReasonAuthzConvergenceExpired, kept.LastError)
		assert.True(t, kept.Abandoned, "逾期放棄")
		assert.WithinDuration(t, old, kept.CreatedAt, time.Second, "重試不重設期限")
		assert.EqualValues(t, 2, notifier.PendingNotifications(), "停止告警一次、放棄告警一次")
	})

	t.Run("同一候選的授權停止告警只發一次，不隨退避週期重複", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.5.1", "10.20.5.2")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("applied", false).Error)
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		f.authz.deny(CredCapAccountRotate)
		for i := 0; i < 4; i++ {
			cur := f.candidateOf(t, cand.ID)
			assert.False(t, f.retry.RetryOne(cur))
		}
		assert.EqualValues(t, 1, notifier.PendingNotifications())
	})

	t.Run("升級前的舊候選：背景告警每個候選只發一次", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.6.1", "10.20.6.2")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("authorization_id", nil).Error)
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		for i := 0; i < 4; i++ {
			cur := f.candidateOf(t, cand.ID)
			assert.False(t, f.retry.RetryOne(cur))
		}
		assert.EqualValues(t, 1, notifier.PendingNotifications())
		// 24 小時放棄時再發一次
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Update("created_at", time.Now().Add(-25*time.Hour)).Error)
		cur := f.candidateOf(t, cand.ID)
		assert.False(t, f.retry.RetryOne(cur))
		assert.EqualValues(t, 2, notifier.PendingNotifications())
		assert.True(t, f.candidateOf(t, cand.ID).Abandoned)
	})

	t.Run("留痕寫不進去：不提交本地、候選保留（落地面缺席與失敗皆然）", func(t *testing.T) {
		for name, sink := range map[string]port.TxSink{"缺席": nil, "失敗": failingAuditTxSink{}} {
			f := setupBatchFixture(t)
			rec := newSecretRecorder()
			cand, _ := f.revokedCandidate(t, rec, "10.20.12.1", "10.20.12.2")
			f.retry.auditTx = sink
			f.authz.deny(CredCapAccountRotate)

			assert.False(t, f.retry.RetryOne(&cand), name)
			assert.EqualValues(t, 1, f.candidateCountFor(t, cand.AccountID), "%s：候選保留", name)
		}
	})

	t.Run("進入有限驗證告警每個候選只發一次；成功與失敗都有審計", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.13.1", "10.20.13.2")
		f.retry.WithAuditSink(audit.NewTxSink())
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		rec.mu.Lock()
		rec.verifyErr["10.20.13.2"] = errRemoteDropped
		rec.mu.Unlock()
		f.authz.deny(CredCapAccountRotate)

		cur := f.candidateOf(t, cand.ID)
		assert.False(t, f.retry.RetryOne(cur), "驗證失敗")
		assert.EqualValues(t, 1, notifier.PendingNotifications())
		rec.mu.Lock()
		delete(rec.verifyErr, "10.20.13.2")
		rec.mu.Unlock()
		cur = f.candidateOf(t, cand.ID)
		assert.True(t, f.retry.RetryOne(cur), "第二次驗證成功")
		assert.EqualValues(t, 1, notifier.PendingNotifications(), "不重複告警")

		var logs []model.AuditLog
		require.NoError(t, f.db.Where("details LIKE ?", "%recovery_verify%").Order("id").Find(&logs).Error)
		require.Len(t, logs, 2)
		assert.Equal(t, string(model.StatusFailure), string(logs[0].Status))
		assert.Contains(t, logs[0].Details, "verify_failed")
		assert.Equal(t, string(model.StatusSuccess), string(logs[1].Status))
		for _, l := range logs {
			assert.Contains(t, l.Details, cand.TargetFingerprint, "記錄目標指紋")
			assert.Contains(t, l.Details, "allowed_because")
			assert.Contains(t, l.Details, model.ChangeSecretReasonAuthzRevoked)
		}
	})

	t.Run("輪替成員：留痕寫不進去不提交，成員保留未驗證", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "失權留痕", "ops", "old-shared", "10.20.14.1", "10.20.14.2")
		rec := newSecretRecorder()
		rec.verifyErr["10.20.14.2"] = errRemoteDropped
		f.useRotationExecutor(rec)
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		member := f.memberOf(t, rot.ID, accounts[1])
		// 主機金鑰記錄與成員綁定由替身經正式回呼建立（不手插記錄列）
		require.Equal(t, model.HostKeyBindingBound, member.HostKeyBinding)
		rec.mu.Lock()
		delete(rec.verifyErr, "10.20.14.2")
		rec.mu.Unlock()
		f.rotations.auditTx = failingAuditTxSink{}
		f.authz.deny(CredCapRotate)

		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID))
		assert.Equal(t, model.CredentialMemberChangedUnverified, f.memberOf(t, rot.ID, accounts[1]).State)
		assert.EqualValues(t, 1, f.candidateCountFor(t, accounts[1]), "候選保留")
	})

	t.Run("舊候選經具權者重試：不能證實目標則拒絕，能證實則固定指紋", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.10.1", "10.20.10.2")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Updates(map[string]any{"authorization_id": nil, "target_fingerprint": ""}).Error)
		cand.AuthorizationID, cand.TargetFingerprint = nil, ""
		require.NoError(t, f.db.Unscoped().Delete(&model.AssetAccount{}, cand.AccountID).Error)
		_, _, verBefore := rec.snapshotCalls()

		assert.False(t, f.retry.RetryOneAs(userCtx(8, "operator"), &cand), "掛載已不存在：無從證實目標")
		_, _, verAfter := rec.snapshotCalls()
		assert.Equal(t, verBefore, verAfter)
		assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, f.candidateOf(t, cand.ID).LastError)
	})

	t.Run("舊候選經具權者重試：固定當下目標指紋", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.11.1", "10.20.11.2")
		require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", cand.ID).
			Updates(map[string]any{"authorization_id": nil, "target_fingerprint": ""}).Error)
		require.NoError(t, f.candidates.PinTargetFingerprint(cand.ID, cand.AccountID))
		pinned := f.candidateOf(t, cand.ID).TargetFingerprint
		want, err := loadTargetFingerprint(f.db, cand.AccountID)
		require.NoError(t, err)
		assert.Equal(t, want, pinned)
		require.NoError(t, f.candidates.PinTargetFingerprint(cand.ID, cand.AccountID))
		assert.Equal(t, pinned, f.candidateOf(t, cand.ID).TargetFingerprint, "已有指紋不被覆蓋")
	})

	t.Run("SSH 舊鑰未清：成功提交但標未完成並告警", func(t *testing.T) {
		f := setupBatchFixture(t)
		rec := newSecretRecorder()
		cand, _ := f.revokedCandidate(t, rec, "10.20.7.1", "10.20.7.2")
		priv, pub, err := GenerateSSHKeyPair("recovery-test")
		require.NoError(t, err)
		_, prevPub, err := GenerateSSHKeyPair("previous")
		require.NoError(t, err)
		require.NoError(t, f.db.Delete(&model.ChangeSecretCandidate{}, cand.ID).Error)
		created, err := f.candidates.Create(adminCtx(), CandidateInput{
			AssetID: cand.AssetID, AccountID: cand.AccountID, AccountUsername: "ops", PlanID: cand.PlanID,
			BatchID: cand.BatchID, AuthorizationID: *cand.AuthorizationID,
			SecretType: model.ChangeSecretTypeSSHKey, PrivateKey: priv, PublicKey: pub, PreviousPublicKey: prevPub,
		})
		require.NoError(t, err)
		require.NoError(t, f.candidates.MarkApplied(created.ID))
		created = bindCandidateViaCallback(t, f.db, f.runner.hostKeys, created.ID, rec.hostKey)
		notifier := audit.NewAlertNotifier(f.db, nil)
		f.retry.notifier = notifier
		f.retry.WithAuditSink(audit.NewTxSink())
		f.authz.deny(CredCapAccountRotate)

		require.True(t, f.retry.RetryOne(created))
		var recs []model.ChangeSecretRecord
		require.NoError(t, f.db.Where("account_id = ?", cand.AccountID).Find(&recs).Error)
		var got []string
		for _, r := range recs {
			got = append(got, r.Error)
		}
		assert.Contains(t, got, model.ChangeSecretReasonRecoveredCleanupPending)
		assert.EqualValues(t, 2, notifier.PendingNotifications(), "進入有限驗證一則、舊公鑰待清理一則")
	})

	t.Run("輪替成員 changed_unverified：失權且目標未變時只驗證，不再下達", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "失權收斂", "ops", "old-shared", "10.20.8.1", "10.20.8.2")
		rec := newSecretRecorder()
		rec.verifyErr["10.20.8.2"] = errRemoteDropped
		f.useRotationExecutor(rec)
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		member := f.memberOf(t, rot.ID, accounts[1])
		require.Equal(t, model.CredentialMemberChangedUnverified, member.State)
		require.NotEmpty(t, member.TargetFingerprint)
		// 主機金鑰記錄與成員綁定由替身經正式回呼建立（不手插記錄列）
		require.Equal(t, model.HostKeyBindingBound, member.HostKeyBinding)
		var stops []string
		f.rotations.WithStopNotifier(func(rule, msg string) { stops = append(stops, rule) })
		rec.mu.Lock()
		delete(rec.verifyErr, "10.20.8.2")
		rec.mu.Unlock()
		_, rotBefore, _ := rec.snapshotCalls()

		f.authz.deny(CredCapRotate)
		require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID))
		assert.Equal(t, model.CredentialMemberApplied, f.memberOf(t, rot.ID, accounts[1]).State)
		_, rotAfter, _ := rec.snapshotCalls()
		assert.Equal(t, rotBefore, rotAfter, "不得再下達")
		assert.Equal(t, []string{"改密工作於授權失效後進入有限驗證"}, stops, "進入有限驗證告警一次")
	})

	t.Run("輪替成員：目標已改址則停止，成員與候選保留，告警只一次", func(t *testing.T) {
		f := setupBatchFixture(t)
		credID, accounts := f.sharedOn(t, "失權漂移", "ops", "old-shared", "10.20.9.1", "10.20.9.2")
		rec := newSecretRecorder()
		rec.verifyErr["10.20.9.2"] = errRemoteDropped
		f.useRotationExecutor(rec)
		rot, err := f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		member := f.memberOf(t, rot.ID, accounts[1])
		require.Equal(t, model.CredentialMemberChangedUnverified, member.State)
		require.NoError(t, f.db.Exec("UPDATE assets SET host = ? WHERE host = ?", "10.99.9.9", "10.20.9.2").Error)
		var stops []string
		f.rotations.WithStopNotifier(func(rule, msg string) { stops = append(stops, rule) })
		_, _, verBefore := rec.snapshotCalls()

		f.authz.deny(CredCapRotate)
		for i := 0; i < 3; i++ {
			require.NoError(t, f.rotations.RunMember(adminCtx(), rot.ID, member.ID))
		}
		got := f.memberOf(t, rot.ID, accounts[1])
		assert.Equal(t, model.CredentialMemberChangedUnverified, got.State, "保留未驗證狀態")
		assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, got.LastError)
		_, _, verAfter := rec.snapshotCalls()
		assert.Equal(t, verBefore, verAfter)
		assert.Len(t, stops, 1, "同一原因每個成員只告警一次")
		assert.Equal(t, int64(1), f.candidateCountFor(t, accounts[1]), "候選保留")
	})
}

func (f *batchFixture) candidateOf(t *testing.T, id uint) *model.ChangeSecretCandidate {
	t.Helper()
	var c model.ChangeSecretCandidate
	require.NoError(t, f.db.Where("id = ?", id).First(&c).Error)
	return &c
}

func (f *batchFixture) candidateCountFor(t *testing.T, accountID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", accountID).Count(&n).Error)
	return n
}
