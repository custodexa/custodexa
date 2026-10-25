package asset

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 排程與手動重試接主機身分守衛的子案例（root：TestCredentialRecoveryHostIdentityPin，前綴 3.4/retry）。
// 夾具的主機金鑰記錄與候選綁定一律由 RunPlan 的首次派送經正式回呼建立，沒有直接寫 bound；
// 異動走採用、重置與重新記錄的正式資料面結果。

// retryScenario 一個已綁定、已下達、驗證失敗而保留的一般候選，與可控的授權判定樁。
type retryScenario struct {
	f        *csFixture
	authz    *fakeCredentialAuthorizer
	baseAuth int32
}

func newRetryScenario(t *testing.T) *retryScenario {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	authz := newAllowAllAuthorizer()
	f.retry.WithManagementAuthorizer(authz)
	f.retry.WithAuditSink(audit.NewTxSink())
	require.NoError(t, f.db.AutoMigrate(&model.AssetHostKeyMismatch{}))
	f.hostKeys.SetAuditTxSink(audit.NewTxSink())
	f.hostKeys.SetSystemAlertSink(newFakeAlertSink())

	f.server.mu.Lock()
	f.server.rejectVerifyLogin = true
	f.server.mu.Unlock()
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	require.Positive(t, f.server.verifyRejectFired.Load(), "驗證失敗注入器必須觸發")
	f.server.mu.Lock()
	f.server.rejectVerifyLogin = false
	f.server.mu.Unlock()

	cand := candidateOfAccount(t, f)
	require.True(t, cand.Applied)
	require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding, "首次派送經綁定回呼")
	require.NotEmpty(t, cand.TargetFingerprint)
	return &retryScenario{f: f, authz: authz, baseAuth: f.server.authAttempts.Load()}
}

// revokeInitiator 原發起者失權：授權脈絡記的能力被拒。並證明重驗確實回報失權（否則後續斷言是假綠）。
func revokeInitiator(t *testing.T, f *csFixture, authz *fakeCredentialAuthorizer) {
	t.Helper()
	authz.deny(CredCapRotate, CredCapAccountRotate)
	cand := candidateOfAccount(t, f)
	require.Equal(t, model.ChangeSecretReasonAuthzRevoked, f.retry.revalidateCandidate(context.Background(), &cand))
}

func restoreInitiator(authz *fakeCredentialAuthorizer) {
	authz.allow(CredCapRotate, CredCapAccountRotate)
}

// retry 以排程（無主體）或手動（具權點擊者）呼叫同一條重試路徑。
func (s *retryScenario) retry(t *testing.T, manual bool) bool {
	t.Helper()
	cand := candidateOfAccount(t, s.f)
	ctx := context.Background()
	if manual {
		ctx = adminCtx()
	}
	return s.f.retry.RetryOneAs(ctx, &cand)
}

// requireStopped 候選仍在、本地憑證不動、遠端沒有新的認證嘗試，且停止原因為新碼。
func (s *retryScenario) requireStopped(t *testing.T, reason string) {
	t.Helper()
	assert.EqualValues(t, s.baseAuth, s.f.server.authAttempts.Load(), "沒有新的認證嘗試（候選密碼不得送出）")
	assert.EqualValues(t, 1, s.f.candidateCount(t), "候選保留")
	assert.Equal(t, "oldpass123", s.f.storedPassword(t), "本地憑證不動")
	cand := candidateOfAccount(t, s.f)
	assert.Equal(t, reason, cand.LastError)
	assert.True(t, cand.Applied)
}

// requireStopAudit 恰一筆停止審計，detail 與階段符合。
func (s *retryScenario) requireStopAudit(t *testing.T, detail, phase, sent string) {
	t.Helper()
	requireOneStop(t, s.f, detail, phase, sent)
}

type identityMutation struct {
	name   string
	detail string
	apply  func(t *testing.T, s *retryScenario)
}

// adoptBackToKey 靶機換回指定金鑰，並經正式觀察加 Adopt 採用（世代加一）。
func adoptBackToKey(t *testing.T, s *retryScenario, signer ssh.Signer) {
	t.Helper()
	adoptBackToSigner(t, s.f.server, s.f.db, s.f.assetID, signer)
}

func rerecordCurrentKey(t *testing.T, s *retryScenario) {
	t.Helper()
	host, port := serverAddr(t, s.f)
	_, err := s.f.hostKeys.Evaluate(s.f.assetID, host, port, s.f.server.currentHostKey().PublicKey())
	require.NoError(t, err)
}

func retryMutations() []identityMutation {
	actor := HostKeyActor{UserID: 1, Username: "super"}
	return []identityMutation{
		{"採用B且遠端換B", hostIdentityGenerationChanged, func(t *testing.T, s *retryScenario) {
			adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		}},
		{"A經重置後記錄回A", hostIdentityGenerationChanged, func(t *testing.T, s *retryScenario) {
			existed, err := s.f.hostKeys.Reset(s.f.assetID, actor)
			require.NoError(t, err)
			require.True(t, existed)
			rerecordCurrentKey(t, s)
		}},
		{"A經B回A", hostIdentityGenerationChanged, func(t *testing.T, s *retryScenario) {
			orig := s.f.server.currentHostKey()
			adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
			adoptBackToKey(t, s, orig)
		}},
		{"刪列重建到同世代", hostIdentityGenerationChanged, func(t *testing.T, s *retryScenario) {
			var before model.AssetHostKey
			require.NoError(t, s.f.db.Where("asset_id = ?", s.f.assetID).First(&before).Error)
			require.NoError(t, s.f.db.Where("asset_id = ?", s.f.assetID).Delete(&model.AssetHostKey{}).Error)
			rerecordCurrentKey(t, s)
			var after model.AssetHostKey
			require.NoError(t, s.f.db.Where("asset_id = ?", s.f.assetID).First(&after).Error)
			require.NotEqual(t, before.ID, after.ID, "重建的是新列")
			require.Equal(t, before.TrustGeneration, after.TrustGeneration, "世代相同：只有記錄 ID 能分辨")
		}},
		{"重置待記錄", hostIdentityResetPending, func(t *testing.T, s *retryScenario) {
			existed, err := s.f.hostKeys.Reset(s.f.assetID, actor)
			require.NoError(t, err)
			require.True(t, existed)
		}},
		{"升級前候選未綁定", hostIdentityUnboundLegacy, func(t *testing.T, s *retryScenario) {
			// 升級遷移把既有候選標為 legacy：不帶歷史身分
			require.NoError(t, s.f.db.Model(&model.ChangeSecretCandidate{}).Where("account_id = ?", s.f.accountID).
				Updates(map[string]any{"host_key_binding": model.HostKeyBindingLegacy, "host_key_record_id": 0,
					"host_key_generation": 0, "host_key_algorithm": "", "host_key_fingerprint": ""}).Error)
		}},
	}
}

// runRetryAuthMatrix 排程與手動重試 × 三種授權狀態 × 六種異動。
func runRetryAuthMatrix(t *testing.T) {
	states := []struct {
		name   string
		manual []bool
		run    func(t *testing.T, s *retryScenario, manual bool, mut identityMutation)
	}{
		{"原發起者有效", []bool{false, true}, func(t *testing.T, s *retryScenario, manual bool, mut identityMutation) {
			mut.apply(t, s)
			assert.False(t, s.retry(t, manual))
			s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
		}},
		{"失權", []bool{false, true}, func(t *testing.T, s *retryScenario, manual bool, mut identityMutation) {
			mut.apply(t, s)
			revokeInitiator(t, s.f, s.authz)
			assert.False(t, s.retry(t, manual), "失權的有限驗證也被主機身分擋下")
			s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
			var recoveryAudits int64
			require.NoError(t, s.f.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%recovery_verify%").Count(&recoveryAudits).Error)
			assert.EqualValues(t, 0, recoveryAudits, "沒有進入有限驗證")
		}},
		{"失權後恢復", []bool{false, true}, func(t *testing.T, s *retryScenario, manual bool, mut identityMutation) {
			mut.apply(t, s)
			revokeInitiator(t, s.f, s.authz)
			assert.False(t, s.retry(t, manual))
			restoreInitiator(s.authz)
			assert.False(t, s.retry(t, manual), "能力恢復後仍被擋下：守衛不依賴授權狀態")
			s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
		}},
		{"還原世代不符的手動重新授權", []bool{true}, func(t *testing.T, s *retryScenario, manual bool, mut identityMutation) {
			mut.apply(t, s)
			s.authz.setRestoreGeneration("gen-after-restore")
			assert.False(t, s.retry(t, true))
			s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
		}},
	}
	for _, st := range states {
		for _, manual := range st.manual {
			path := "排程"
			if manual {
				path = "手動"
			}
			for _, mut := range retryMutations() {
				t.Run(fmt.Sprintf("%s/%s/%s", st.name, path, mut.name), func(t *testing.T) {
					s := newRetryScenario(t)
					st.run(t, s, manual, mut)
					s.requireStopAudit(t, mut.detail, hostIdentityPhasePrecheck, verificationSentFalse)
					assert.Positive(t, s.f.server.verifyRejectFired.Load())
				})
			}
		}
	}
}

// runRetryTargetFingerprintNotMixed 目標指紋不符與主機身分變更互不混淆：兩者同時成立時先報目標變更，
// 且不寫身分停止審計；只有身分變更時回新碼，不回目標變更。
func runRetryTargetFingerprintNotMixed(t *testing.T) {
	t.Run("目標與身分同時變更回目標變更", func(t *testing.T) {
		s := newRetryScenario(t)
		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		require.NoError(t, s.f.db.Model(&model.Asset{}).Where("id = ?", s.f.assetID).Update("host", "10.99.99.99").Error)
		revokeInitiator(t, s.f, s.authz)
		assert.False(t, s.retry(t, false))
		s.requireStopped(t, model.ChangeSecretReasonAuthzTargetChanged)
		assert.Empty(t, stopAuditDetails(t, s.f), "目標變更不是身分變更：不寫身分停止審計")
	})
	t.Run("只有身分變更回新碼而非目標變更", func(t *testing.T) {
		s := newRetryScenario(t)
		adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		revokeInitiator(t, s.f, s.authz)
		assert.False(t, s.retry(t, false))
		cand := candidateOfAccount(t, s.f)
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, cand.LastError)
		assert.NotEqual(t, model.ChangeSecretReasonAuthzTargetChanged, cand.LastError)
	})
	t.Run("單純失權且身分相符仍放行有限驗證", func(t *testing.T) {
		// 失權後、候選已綁定且身分未變：有限驗證放行（只驗證、只提交本地，不再下達）
		s := newRetryScenario(t)
		revokeInitiator(t, s.f, s.authz)
		assert.True(t, s.retry(t, false), "失權但已下達、24 小時內、目標未變、身分相符")
		assert.EqualValues(t, s.baseAuth+1, s.f.server.authAttempts.Load(), "只做一次驗證登入")
		assert.EqualValues(t, 0, s.f.candidateCount(t), "本地提交後候選已刪")
		assert.Equal(t, s.f.server.currentPassword(), s.f.storedPassword(t))
		var logs []model.AuditLog
		require.NoError(t, s.f.db.Where("details LIKE ?", "%recovery_verify%").Find(&logs).Error)
		require.Len(t, logs, 1)
		assert.Contains(t, logs[0].Details, "host_identity_match")
		assert.Empty(t, stopAuditDetails(t, s.f))
	})
}

// runRetryHandshake 撥號前查庫已放行、握手前身分被換掉：預期身分回呼拒絕，不送出候選秘密。
func runRetryHandshake(t *testing.T) {
	s := newRetryScenario(t)
	fired := 0
	orig := s.f.retry.executors
	s.f.retry.executors = func(ch string) rotationExecutor {
		return verifyHookExecutor{rotationExecutor: orig(ch), beforeVerify: func() {
			fired++
			adoptRemoteKey(t, s.f.server, s.f.db, s.f.assetID, true)
		}}
	}
	assert.False(t, s.retry(t, false))
	require.Equal(t, 1, fired, "注入器必須真的觸發（否則為假綠）")
	s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
	s.requireStopAudit(t, hostIdentityGenerationChanged, hostIdentityPhaseHandshake, verificationSentFalse)
}

// runRetryTransport 傳輸切換與 WinRM 照舊。
func runRetryTransport(t *testing.T) {
	// 不依賴授權狀態的兩條路徑：原發起者有效、失權後恢復（失權期間目標已變，先停在目標變更）
	for _, state := range []string{"原發起者有效", "失權後恢復"} {
		t.Run("SSH綁定改為WinRM/"+state, func(t *testing.T) {
			s := newRetryScenario(t)
			useWinRMChannel(t, s.f.db, s.f.assetID)
			require.NoError(t, s.f.db.Model(&model.Asset{}).Where("id = ?", s.f.assetID).Update("host", "10.77.0.9").Error)
			probe := &winrmProbe{inner: newRotationRecorder()}
			s.f.retry.executors = func(string) rotationExecutor { return probe }
			if state == "失權後恢復" {
				revokeInitiator(t, s.f, s.authz)
				assert.False(t, s.retry(t, false))
				assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, candidateOfAccount(t, s.f).LastError,
					"失權期間通道已改：先停在目標變更，不混成身分變更")
				restoreInitiator(s.authz)
			}
			assert.False(t, s.retry(t, false))
			_, _, verifies := probe.inner.snapshot()
			assert.Empty(t, verifies, "WinRM 執行器的 Verify 呼叫 0 次")
			s.requireStopped(t, model.ChangeSecretReasonHostIdentityChanged)
			s.requireStopAudit(t, hostIdentityTransportChanged, hostIdentityPhasePrecheck, verificationSentFalse)
		})
	}

	newWinRM := func(t *testing.T) (*csFixture, *fakeCredentialAuthorizer, *winrmProbe) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		authz := newAllowAllAuthorizer()
		f.retry.WithManagementAuthorizer(authz)
		f.retry.WithAuditSink(audit.NewTxSink())
		useWinRMChannel(t, f.db, f.assetID)
		probe := &winrmProbe{inner: newRotationRecorder()}
		f.runner.executors = func(string) rotationExecutor { return probe }
		f.retry.executors = func(string) rotationExecutor { return probe }
		var asset model.Asset
		require.NoError(t, f.db.First(&asset, f.assetID).Error)
		probe.inner.setVerifyErr(asset.Host, errors.New("verify timeout"))
		records := f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		require.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		cand := candidateOfAccount(t, f)
		require.Equal(t, model.HostKeyBindingBound, cand.HostKeyBinding)
		require.Equal(t, model.HostKeyTransportWinRM, cand.HostKeyTransport)
		require.True(t, cand.Applied)
		probe.inner.setVerifyErr(asset.Host, nil)
		return f, authz, probe
	}

	t.Run("自始WinRM授權正常分支照常驗證", func(t *testing.T) {
		f, _, probe := newWinRM(t)
		_, _, before := probe.inner.snapshot()
		cand := candidateOfAccount(t, f)
		assert.True(t, f.retry.RetryOneAs(context.Background(), &cand), "WinRM 無主機金鑰可比：照常驗證並轉正")
		_, _, after := probe.inner.snapshot()
		total := func(m map[string]int) (n int) {
			for _, v := range m {
				n += v
			}
			return
		}
		assert.Equal(t, total(before)+1, total(after), "Verify 恰多一次")
		assert.EqualValues(t, 0, f.candidateCount(t))
		assert.Empty(t, stopAuditDetails(t, f))
	})

	t.Run("自始WinRM失權分支維持既有停止結果", func(t *testing.T) {
		f, authz, probe := newWinRM(t)
		_, _, before := probe.inner.snapshot()
		revokeInitiator(t, f, authz)
		cand := candidateOfAccount(t, f)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		_, _, after := probe.inner.snapshot()
		assert.Equal(t, before, after, "沒有任何 Verify")
		assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, candidateOfAccount(t, f).LastError,
			"既有結果：無 SSH 位址的資產查無主機金鑰記錄，不放行")
		assert.Empty(t, stopAuditDetails(t, f), "不是身分變更")
	})

	for _, state := range []string{"原發起者有效", "失權後恢復"} {
		t.Run("WinRM綁定改為SSH通道/"+state, func(t *testing.T) {
			f, authz, _ := newWinRM(t)
			require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", f.assetID).
				Update("rotation_channel", "").Error)
			base := f.server.authAttempts.Load()
			if state == "失權後恢復" {
				revokeInitiator(t, f, authz)
				cand := candidateOfAccount(t, f)
				assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
				restoreInitiator(authz)
			}
			cand := candidateOfAccount(t, f)
			assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
			assert.EqualValues(t, base, f.server.authAttempts.Load(), "SSH 靶機沒有任何認證嘗試")
			assert.EqualValues(t, 1, f.candidateCount(t))
			assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, f).LastError)
			requireOneStop(t, f, hostIdentityTransportChanged, hostIdentityPhasePrecheck, verificationSentFalse)
		})
	}
}

// runMemberKeyMarkApplied 成員 SSH 金鑰下達標記點的失敗注入（下達標記四點矩陣的第四點）：
// 標記寫不進去只記 log、不中止驗證；(i) 驗證另失敗，成員仍轉已下達未驗證、派送標記照寫、候選 applied 保持 false 保留；
// (ii) 驗證與提交成功，照常就位、候選刪除。
func runMemberKeyMarkApplied(t *testing.T) {
	prep := func(t *testing.T, host string, verifyFails bool) (*rotationFixture, uint, *model.CredentialRotation, func() string) {
		f := setupRotationFixture(t)
		oldPrivate, _, err := GenerateSSHKeyPair("seed-key")
		require.NoError(t, err)
		cred, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{
			Name: "標記失敗金鑰-" + host, Username: "ops", ProtocolFamily: model.ProtocolFamilySSH,
			SecretType: model.ChangeSecretTypeSSHKey, PrivateKey: oldPrivate,
		})
		require.NoError(t, err)
		asset := newSSHAsset(t, f.assets, host, host)
		binding, err := f.creds.Bind(adminCtx(), cred.ID, &BindCredentialRequest{AssetID: asset.ID})
		require.NoError(t, err)
		if verifyFails {
			f.remote.setVerifyErr(host, assert.AnError)
		}
		require.NoError(t, f.db.Exec(failMarkTriggerSQL).Error)
		logs := captureLog(t)
		rot, err := f.rotations.Start(adminCtx(), cred.ID, StartRotationRequest{})
		require.NoError(t, err)
		require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
		return f, binding.ID, rot, logs
	}
	t.Run("驗證另失敗", func(t *testing.T) {
		f, acc, rot, logs := prep(t, "10.42.1.1", true)
		assert.Contains(t, logs(), "標記候選已下達失敗", "標記失敗記 log 並繼續驗證")
		f.remote.mu.Lock()
		delivered := f.remote.keyDelivered["10.42.1.1"]
		f.remote.mu.Unlock()
		require.NotEmpty(t, delivered, "下達確實發生")
		m := f.memberFor(t, rot.ID, acc)
		assert.Equal(t, model.CredentialMemberChangedUnverified, m.State, "成員仍轉已下達未驗證")
		assert.NotNil(t, m.SecretSentAt, "派送標記照寫")
		var cand model.ChangeSecretCandidate
		require.NoError(t, f.db.Where("account_id = ?", acc).First(&cand).Error)
		assert.False(t, cand.Applied, "applied 保持 false，候選保留")
	})
	t.Run("驗證與提交成功", func(t *testing.T) {
		f, acc, rot, logs := prep(t, "10.42.2.1", false)
		assert.Contains(t, logs(), "標記候選已下達失敗")
		m := f.memberFor(t, rot.ID, acc)
		assert.Equal(t, model.CredentialMemberApplied, m.State)
		assert.NotNil(t, m.SecretSentAt)
		assert.EqualValues(t, 0, f.candidateCountFor(t, acc), "照常就位、候選刪除")
	})
}
