package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 資料庫自改通道走過每一條改密路徑：工作列在派送前綁定為「自始為 db」的無金鑰傳輸，
// 沒有任何一條因查無主機金鑰記錄或傳輸變更而停下。

// useDBNativeChannel 把資產改成設定 db_native 的 mysql 資產（直接寫列：驗的是派送路徑，不是表單）。
func useDBNativeChannel(t *testing.T, db *gorm.DB, assetIDs ...uint) {
	t.Helper()
	require.NoError(t, db.Model(&model.Asset{}).Where("id IN ?", assetIDs).Updates(map[string]any{
		"protocol": model.ProtocolMySQL, "port": 3306, "rotation_channel": model.RotationChannelDBNative,
	}).Error)
}

// requireDBBound 工作列的主機身分快照為「已綁定、傳輸 db、身分欄全空」。
func requireDBBound(t *testing.T, binding, transport, algorithm, fingerprint string) {
	t.Helper()
	assert.Equal(t, model.HostKeyBindingBound, binding)
	assert.Equal(t, model.HostKeyTransportDB, transport)
	assert.Empty(t, algorithm)
	assert.Empty(t, fingerprint)
}

// newDBNativeUnverified 一般候選：第一次執行驗證失敗，候選以 db 傳輸綁定後保留。
func newDBNativeUnverified(t *testing.T) (*csFixture, *fakeCredentialAuthorizer, *winrmProbe) {
	t.Helper()
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	authz := newAllowAllAuthorizer()
	f.retry.WithManagementAuthorizer(authz)
	f.retry.WithAuditSink(audit.NewTxSink())
	wireStopAudit(f)
	useDBNativeChannel(t, f.db, f.assetID)
	probe := &winrmProbe{inner: newRotationRecorder()}
	f.runner.executors = func(string) rotationExecutor { return probe }
	f.retry.executors = func(string) rotationExecutor { return probe }
	var asset model.Asset
	require.NoError(t, f.db.First(&asset, f.assetID).Error)
	probe.inner.setVerifyErr(asset.Host, errors.New("verify timeout"))
	records := f.runner.RunPlan(f.plan(t, nil))
	require.Len(t, records, 1)
	require.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
	cand := candidateOfAccount(t, f)
	requireDBBound(t, cand.HostKeyBinding, cand.HostKeyTransport, cand.HostKeyAlgorithm, cand.HostKeyFingerprint)
	require.True(t, cand.Applied)
	probe.inner.setVerifyErr(asset.Host, nil)
	return f, authz, probe
}

func TestDBNativeRotationPaths(t *testing.T) {
	t.Run("計畫執行", func(t *testing.T) {
		f := setupChangeSecretFixture(t, "root", "oldpass123")
		wireStopAudit(f)
		useDBNativeChannel(t, f.db, f.assetID)
		var seen model.ChangeSecretCandidate
		probe := &winrmProbe{inner: newRotationRecorder()}
		probe.onRot = func() {
			require.NoError(t, f.db.Where("account_id = ?", f.accountID).First(&seen).Error)
		}
		f.runner.executors = func(string) rotationExecutor { return probe }
		records := f.runner.RunPlan(f.plan(t, nil))
		require.Len(t, records, 1)
		require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		require.Equal(t, 1, probe.rotateCalls())
		requireDBBound(t, seen.HostKeyBinding, seen.HostKeyTransport, seen.HostKeyAlgorithm, seen.HostKeyFingerprint)
		assert.Empty(t, stopAuditDetails(t, f))
	})

	t.Run("批次", func(t *testing.T) {
		f := setupBatchFixture(t)
		assetID, accountID := f.addHost(t, "db-batch", "10.32.0.1", "ops")
		useDBNativeChannel(t, f.db, assetID)
		var seen model.ChangeSecretCandidate
		probe := &winrmProbe{inner: newRotationRecorder()}
		probe.onRot = func() {
			require.NoError(t, f.db.Where("account_id = ?", accountID).First(&seen).Error)
		}
		f.runner.executors = func(string) rotationExecutor { return probe }
		batch, assetIDs, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, true), 7, "admin")
		require.NoError(t, err)
		records := f.runner.RunBatch(batch, assetIDs)
		require.Len(t, records, 1)
		require.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		require.Equal(t, 1, probe.rotateCalls())
		requireDBBound(t, seen.HostKeyBinding, seen.HostKeyTransport, seen.HostKeyAlgorithm, seen.HostKeyFingerprint)
	})

	for _, split := range []bool{false, true} {
		name := "共用憑證整組輪替成員"
		if split {
			name = "拆分輪替成員"
		}
		t.Run(name, func(t *testing.T) {
			f := setupRotationFixture(t)
			credID, accounts := f.sharedOn(t, "db甲", "ops", "old", "10.32.1.1")
			useDBNativeChannel(t, f.db, f.binding(t, accounts[0]).AssetID)
			var seen model.CredentialRotationMember
			probe := &winrmProbe{inner: f.remote}
			probe.onRot = func() {
				require.NoError(t, f.db.Where("account_id = ?", accounts[0]).First(&seen).Error)
			}
			f.rotations.executors = func(string) rotationExecutor { return probe }
			var rot *model.CredentialRotation
			var err error
			if split {
				rot, err = f.rotations.StartSplit(adminCtx(), credID, StartRotationRequest{})
			} else {
				rot, err = f.rotations.Start(adminCtx(), credID, StartRotationRequest{})
			}
			require.NoError(t, err)
			require.NoError(t, f.rotations.Run(adminCtx(), rot.ID))
			require.Equal(t, 1, probe.rotateCalls())
			requireDBBound(t, seen.HostKeyBinding, seen.HostKeyTransport, seen.HostKeyAlgorithm, seen.HostKeyFingerprint)
			m := f.memberFor(t, rot.ID, accounts[0])
			assert.Equal(t, model.CredentialMemberApplied, m.State, "錯誤: %s", m.LastError)
			assert.Empty(t, memberStops(t, f.db))
		})
	}

	t.Run("系統重試", func(t *testing.T) {
		f, _, probe := newDBNativeUnverified(t)
		_, _, before := probe.inner.snapshot()
		cand := candidateOfAccount(t, f)
		require.True(t, f.retry.RetryOne(&cand))
		_, _, after := probe.inner.snapshot()
		assert.Greater(t, sumCalls(after), sumCalls(before), "確實撥號驗證")
		assert.EqualValues(t, 0, f.candidateCount(t), "驗證成功後候選轉正")
		assert.Empty(t, stopAuditDetails(t, f))
	})

	// 失權後的有限收斂要求資產有主機金鑰記錄（credential_recovery.go 的 recoveryVerdict）；
	// 無主機金鑰的傳輸沒有這筆記錄，現況與 WinRM 相同：以目標變更停下、不撥號，不是因身分記錄缺失或傳輸變更
	t.Run("失權後的有限收斂", func(t *testing.T) {
		f, authz, probe := newDBNativeUnverified(t)
		revokeInitiator(t, f, authz)
		_, _, before := probe.inner.snapshot()
		cand := candidateOfAccount(t, f)
		assert.False(t, f.retry.RetryOneAs(context.Background(), &cand))
		_, _, after := probe.inner.snapshot()
		assert.Equal(t, before, after, "沒有任何 Verify")
		assert.Equal(t, model.ChangeSecretReasonAuthzTargetChanged, candidateOfAccount(t, f).LastError)
		assert.Empty(t, stopAuditDetails(t, f), "不是身分記錄缺失或傳輸變更的停止")
	})

	t.Run("通道改為posix_ssh後重試_停止原因為傳輸變更", func(t *testing.T) {
		f, _, probe := newDBNativeUnverified(t)
		require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", f.assetID).Updates(map[string]any{
			"protocol": model.ProtocolSSH, "rotation_channel": model.RotationChannelPosixSSH,
		}).Error)
		_, _, before := probe.inner.snapshot()
		cand := candidateOfAccount(t, f)
		assert.False(t, f.retry.RetryOne(&cand))
		_, _, after := probe.inner.snapshot()
		assert.Equal(t, before, after, "沒有任何 Verify")
		assert.Equal(t, model.ChangeSecretReasonHostIdentityChanged, candidateOfAccount(t, f).LastError)
		requireOneStop(t, f, hostIdentityTransportChanged, hostIdentityPhasePrecheck, verificationSentFalse)
	})

	t.Run("承接只有拒絕面", func(t *testing.T) {
		f, authz, probe := newDBNativeUnverified(t)
		svc := NewHostIdentityTakeoverService(f.db, authz).WithCandidateRunner(f.retry)
		svc.SetAuditTxSink(audit.NewTxSink())
		require.NoError(t, f.db.AutoMigrate(&model.CredentialHostIdentityConfirmation{}))
		cand := candidateOfAccount(t, f)
		_, _, before := probe.inner.snapshot()

		err := svc.ConfirmHostIdentityAndVerify(adminCtx(), takeoverKindCandidate, cand.ID,
			HostIdentityConfirmRequest{Transport: model.HostKeyTransportWinRM})
		require.Error(t, err, "db 工作不可用 winrm 確認")
		t.Logf("transport=winrm 的確認: %v", err)

		_, derr := DecodeHostIdentityConfirmRequest([]byte(`{"transport":"db","fingerprint":"SHA256:AAAA"}`))
		require.ErrorIs(t, derr, ErrHostIdentityConfirmInvalid, "db 確認帶指紋在形狀驗證即拒絕")
		t.Logf("transport=db 帶指紋的確認: %v", derr)

		var n int64
		require.NoError(t, f.db.Model(&model.CredentialHostIdentityConfirmation{}).Count(&n).Error)
		assert.Zero(t, n, "不留承接紀錄")
		_, _, after := probe.inner.snapshot()
		assert.Equal(t, before, after, "沒有任何 Verify")
		assert.EqualValues(t, 1, f.candidateCount(t), "候選保留")
	})
}

func sumCalls(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
