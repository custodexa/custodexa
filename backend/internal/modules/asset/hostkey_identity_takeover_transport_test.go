package asset

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 傳輸類別的子案例（root：TestCredentialRecoveryHostIdentityTakeover，前綴 4.1/傳輸/）。

// winrmTakeover 一個走 WinRM 通道、已下達未驗證而保留的候選，與可計數的 WinRM 執行器替身。
type winrmTakeover struct {
	f     *csFixture
	authz *fakeCredentialAuthorizer
	probe *winrmProbe
	svc   *HostIdentityTakeoverService
	cand  model.ChangeSecretCandidate
}

func newWinRMTakeover(t *testing.T) winrmTakeover {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	authz := newAllowAllAuthorizer()
	f.retry.WithManagementAuthorizer(authz)
	f.retry.WithAuditSink(audit.NewTxSink())
	wireStopAudit(f)
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
	probe.inner.setVerifyErr(asset.Host, nil)
	cand := candidateOfAccount(t, f)
	require.Equal(t, model.HostKeyTransportWinRM, cand.HostKeyTransport)
	require.True(t, cand.Applied)
	svc := NewHostIdentityTakeoverService(f.db, authz).WithCandidateRunner(f.retry)
	svc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	return winrmTakeover{f: f, authz: authz, probe: probe, svc: svc, cand: cand}
}

func (w winrmTakeover) verifyTotal() int {
	_, _, verifies := w.probe.inner.snapshot()
	n := 0
	for _, v := range verifies {
		n += v
	}
	return n
}

// restampTargetFingerprint 把候選記下的目標指紋改成當下的值：通道切換本身會讓目標指紋不同
// （先被目標變更擋下），要驗到傳輸守衛就得讓兩者相等。
func restampTargetFingerprint(t *testing.T, w winrmTakeover, jobID uint, accountID uint) {
	t.Helper()
	tf, err := loadTargetFingerprint(w.f.db, accountID)
	require.NoError(t, err)
	require.NoError(t, w.f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", jobID).
		Update("target_fingerprint", tf).Error)
}

func runTakeoverTransport(t *testing.T) {
	const p = "4.1/傳輸/"

	t.Run(p+"legacy且WinRM_帶transport_winrm的確認成功_審計記winrm_身分欄空", func(t *testing.T) {
		w := newWinRMTakeover(t)
		// 升級前建立的候選：沒有歷史身分
		require.NoError(t, w.f.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", w.cand.ID).Updates(map[string]any{
			"host_key_binding": model.HostKeyBindingLegacy, "host_key_transport": "", "host_key_record_id": 0,
			"host_key_algorithm": "", "host_key_fingerprint": "", "host_key_generation": 0}).Error)
		beforeVerify, beforeRotate := w.verifyTotal(), w.probe.rotateCalls()
		err := w.svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, w.cand.ID,
			HostIdentityConfirmRequest{Transport: model.HostKeyTransportWinRM})
		require.NoError(t, err)
		assert.Equal(t, beforeVerify+1, w.verifyTotal(), "單次驗證")
		assert.Equal(t, beforeRotate, w.probe.rotateCalls(), "只 Verify 不 Rotate")
		assert.EqualValues(t, 0, w.f.candidateCount(t), "驗證成功後候選轉正")

		var rows []model.CredentialHostIdentityConfirmation
		require.NoError(t, w.f.db.Where("kind = ? AND job_id = ?", takeoverKindCandidate, w.cand.ID).Find(&rows).Error)
		require.Len(t, rows, 1)
		r := rows[0]
		assert.Equal(t, model.HostKeyTransportWinRM, r.ConfirmedTransport)
		assert.Zero(t, r.ConfirmedRecordID)
		assert.Empty(t, r.ConfirmedAlgorithm)
		assert.Empty(t, r.ConfirmedFingerprint)
		assert.Zero(t, r.ConfirmedGeneration)
		assert.Equal(t, model.HostKeyBindingLegacy, r.OriginalBinding)
		assert.Equal(t, "verified", r.Outcome)

		d := lastConfirmAudit(t, w.f.db)
		assert.Equal(t, model.HostKeyTransportWinRM, d["transport"])
		confirmed, ok := d["confirmed"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, model.HostKeyTransportWinRM, confirmed["transport"])
		assert.EqualValues(t, 0, confirmed["record_id"])
		assert.Equal(t, "", confirmed["fingerprint"])
		assert.Equal(t, "", confirmed["algorithm"])
	})

	// 傳輸已變更：任何確認都 409，無紀錄、無審計、Verify 0
	type switchCase struct {
		name string
		make func(t *testing.T) (winrmTakeover, HostIdentityConfirmRequest)
	}
	cases := []switchCase{
		{"SSH綁定而資產當下為WinRM/帶ssh身分", func(t *testing.T) (winrmTakeover, HostIdentityConfirmRequest) {
			w := newSSHBoundThenWinRM(t)
			return w, validConfirmRequest(t, w.f.db, w.f.assetID)
		}},
		{"SSH綁定而資產當下為WinRM/帶winrm", func(t *testing.T) (winrmTakeover, HostIdentityConfirmRequest) {
			w := newSSHBoundThenWinRM(t)
			return w, HostIdentityConfirmRequest{Transport: model.HostKeyTransportWinRM}
		}},
		{"WinRM綁定而資產當下為SSH/帶ssh身分", func(t *testing.T) (winrmTakeover, HostIdentityConfirmRequest) {
			w := newWinRMTakeover(t)
			require.NoError(t, w.f.db.Model(&model.Asset{}).Where("id = ?", w.f.assetID).
				Update("rotation_channel", "").Error)
			trustServerKey(t, w)
			restampTargetFingerprint(t, w, w.cand.ID, w.cand.AccountID)
			return w, validConfirmRequest(t, w.f.db, w.f.assetID)
		}},
		{"WinRM綁定而資產當下為SSH/帶winrm", func(t *testing.T) (winrmTakeover, HostIdentityConfirmRequest) {
			w := newWinRMTakeover(t)
			require.NoError(t, w.f.db.Model(&model.Asset{}).Where("id = ?", w.f.assetID).
				Update("rotation_channel", "").Error)
			restampTargetFingerprint(t, w, w.cand.ID, w.cand.AccountID)
			return w, HostIdentityConfirmRequest{Transport: model.HostKeyTransportWinRM}
		}},
	}
	for _, c := range cases {
		t.Run(p+"transport_changed任何確認都409/"+c.name, func(t *testing.T) {
			w, req := c.make(t)
			req.AcceptDifferentKey = true
			beforeVerify, beforeAudits := w.verifyTotal(), confirmAuditCount(t, w.f.db)
			beforeAttempts := w.f.server.authAttempts.Load()
			err := w.svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, w.cand.ID, req)
			require.ErrorIs(t, err, ErrHostIdentityMoved)
			var rows []model.CredentialHostIdentityConfirmation
			require.NoError(t, w.f.db.Find(&rows).Error)
			assert.Empty(t, rows, "無承接紀錄")
			assert.Equal(t, beforeAudits, confirmAuditCount(t, w.f.db))
			assert.Equal(t, beforeVerify, w.verifyTotal(), "沒有任何 Verify")
			assert.Equal(t, beforeAttempts, w.f.server.authAttempts.Load())
			assert.EqualValues(t, 1, w.f.candidateCount(t), "候選保留")
		})
	}

	t.Run(p+"SSH降級為WinRM_帶確認的人工重試_Verify0次_transport_changed_不可確認", func(t *testing.T) {
		s := newRetryScenario(t)
		useWinRMChannel(t, s.f.db, s.f.assetID)
		require.NoError(t, s.f.db.Model(&model.Asset{}).Where("id = ?", s.f.assetID).Update("host", "10.77.0.9").Error)
		probe := &winrmProbe{inner: newRotationRecorder()}
		s.f.retry.executors = func(string) rotationExecutor { return probe }
		cand := candidateOfAccount(t, s.f)
		svc := NewHostIdentityTakeoverService(s.f.db, s.authz).WithCandidateRunner(s.f.retry)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.NoError(t, s.f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))

		// 帶確認：通道已改，目標指紋不同，先被目標變更擋下；也不會出現任何承接紀錄
		for _, req := range []HostIdentityConfirmRequest{
			{Transport: model.HostKeyTransportWinRM},
			acceptDifferent(validConfirmRequest(t, s.f.db, s.f.assetID)),
		} {
			err := svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, cand.ID, req)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrHostIdentityConfirmIncomplete)
		}
		var n int64
		require.NoError(t, s.f.db.Model(&model.CredentialHostIdentityConfirmation{}).Count(&n).Error)
		assert.Zero(t, n)

		// 人工重試：回報 transport_changed，不可確認
		res := s.f.retry.RetryOneAsResult(adminCtx(), &cand)
		assert.False(t, res.Promoted)
		require.NotNil(t, res.HostIdentity)
		assert.Equal(t, hostIdentityTransportChanged, res.HostIdentity.Status)
		assert.Equal(t, hostIdentityTransportChanged, res.HostIdentity.Detail)
		assert.False(t, res.HostIdentity.Confirmable)
		_, _, verifies := probe.inner.snapshot()
		assert.Empty(t, verifies, "WinRM 執行器的 Verify 呼叫 0 次")
		assert.EqualValues(t, s.baseAuth, s.f.server.authAttempts.Load(), "authAttempts 0")
	})
}

// newSSHBoundThenWinRM SSH 通道下綁定的候選，之後資產改走 WinRM；候選記下的目標指紋同步成當下的值。
func newSSHBoundThenWinRM(t *testing.T) winrmTakeover {
	t.Helper()
	s := newRetryScenario(t)
	probe := &winrmProbe{inner: newRotationRecorder()}
	s.f.retry.executors = func(string) rotationExecutor { return probe }
	cand := candidateOfAccount(t, s.f)
	require.Equal(t, model.HostKeyTransportSSH, cand.HostKeyTransport)
	useWinRMChannel(t, s.f.db, s.f.assetID)
	svc := NewHostIdentityTakeoverService(s.f.db, s.authz).WithCandidateRunner(s.f.retry)
	svc.SetAuditTxSink(audit.NewTxSink())
	require.NoError(t, s.f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
	w := winrmTakeover{f: s.f, authz: s.authz, probe: probe, svc: svc, cand: cand}
	restampTargetFingerprint(t, w, cand.ID, cand.AccountID)
	return w
}

// trustServerKey 資產當下走 SSH 通道且靶機的金鑰已是自身記錄（WinRM 綁定期間沒有記錄，此處補上）。
func trustServerKey(t *testing.T, w winrmTakeover) {
	t.Helper()
	var asset model.Asset
	require.NoError(t, w.f.db.First(&asset, w.f.assetID).Error)
	pub := w.f.server.currentHostKey().PublicKey()
	require.NoError(t, w.f.db.Create(&model.AssetHostKey{
		AssetID: asset.ID, Algorithm: pub.Type(), Fingerprint: ssh.FingerprintSHA256(pub),
		PublicKey: base64.StdEncoding.EncodeToString(pub.Marshal()),
		Host:      model.NormalizeHostKeyHost(asset.Host), Port: asset.Port, TrustGeneration: 1,
	}).Error)
}
