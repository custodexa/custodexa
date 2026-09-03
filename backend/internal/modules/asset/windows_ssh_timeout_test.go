package asset

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// SSH 通道的指令逾時與結果標記的契約邊界。
//
// 指令送出後目標端腳本掛住（Add-Type、Set-LocalUser 或 ReadLine 卡住）時，SSH 通道與 WinRM 一樣
// 在同一個上限到期即放手：記狀態不可知、候選保留、連線關閉不再等目標。沒有這道上限，改密計劃的
// 該帳號會永遠不回報。契約表外的結果標記值同一條底線：分不清就保留候選。

// TestWindowsSSHCommandTimeoutSharedWithWinRM 兩通道的指令逾時同一個值，且正式組態確實帶著它。
func TestWindowsSSHCommandTimeoutSharedWithWinRM(t *testing.T) {
	assert.Equal(t, 90*time.Second, windowsCommandTimeout)
	assert.Equal(t, windowsCommandTimeout, newWindowsSSHExecutor().commandTimeout, "SSH 正式組態的指令逾時")
	assert.Equal(t, windowsCommandTimeout, newWindowsWinRMExecutor().commandTimeout, "WinRM 正式組態的指令逾時")
}

// TestWindowsSSHExecutorCommandTimeoutIsUnverified 指令送出後目標端停住：逾時即回狀態不可知
// （不是確定失敗、不是本地前置失敗），不等目標跑完，且連線已關閉（靶機觀察到客戶端放棄）。
func TestWindowsSSHExecutorCommandTimeoutIsUnverified(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"
	srv := newTestSSHServer(t, "Administrator", "old")
	srv.mu.Lock()
	srv.windowsExecStall = 3 * time.Second
	srv.mu.Unlock()
	e := testWindowsSSHExecutor(nil)
	e.commandTimeout = 300 * time.Millisecond

	start := time.Now()
	err := e.Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
	elapsed := time.Since(start)
	require.Error(t, err)
	require.Positive(t, srv.windowsStallFired.Load(), "停住注入器未觸發")
	assert.Less(t, elapsed, 2*time.Second, "逾時後不得等目標跑完")

	var unknown *remoteStateUnknownError
	require.True(t, errors.As(err, &unknown), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, unknown.reason)
	assert.Contains(t, err.Error(), "timed out")
	assert.NotContains(t, err.Error(), newPassword)
	var rejected *remoteRejectedError
	var local *localPreconditionError
	assert.False(t, errors.As(err, &rejected), "指令送出後的逾時不得判為確定失敗")
	assert.False(t, errors.As(err, &local))

	stdin, _ := srv.lastChpasswdStdin.Load().(string)
	assert.Equal(t, newPassword+"\nold\nAdministrator\n", stdin, "指令確實已送出（密碼已投遞）")
	assert.Eventually(t, func() bool { return srv.windowsStallReleasedByPeer.Load() > 0 },
		2*time.Second, 20*time.Millisecond, "逾時後連線須關閉，靶機的停住應因客戶端放棄而解除")
}

// TestWindowsSSHVerifyCommandTimeout 驗證指令同受逾時保護：驗證階段的掛住回錯（呼叫端記 unverified），
// 不得無限等待。
func TestWindowsSSHVerifyCommandTimeout(t *testing.T) {
	srv := newTestSSHServer(t, "Administrator", "old")
	srv.mu.Lock()
	srv.windowsExecStall = 3 * time.Second
	srv.mu.Unlock()
	e := testWindowsSSHExecutor(nil)
	e.commandTimeout = 300 * time.Millisecond

	start := time.Now()
	err := e.Verify(context.Background(), sshTarget(srv, "Administrator"), "old")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second, "三次驗證各自逾時後即返回")
	assert.Contains(t, err.Error(), "timed out")
	assert.EqualValues(t, 3, srv.windowsStallFired.Load(), "驗證序列三次各送出一次指令")
}

// TestWindowsSSHCommandTimeoutThroughRunner 經狀態機落地：逾時記 unverified、原因為遠端狀態不可知、
// 候選保留、本地憑證不動、記錄不帶逾時原文。
func TestWindowsSSHCommandTimeoutThroughRunner(t *testing.T) {
	fx := setupChangeSecretFixture(t, "root", "oldpass123")
	srv := newTestSSHServer(t, "Administrator", "winoldpass")
	srv.mu.Lock()
	srv.windowsExecStall = 3 * time.Second
	srv.mu.Unlock()
	host, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	id := fx.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-ssh-timeout", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsSSH, RotationSSHPort: port,
	})
	fx.runner.executors = func(string) rotationExecutor {
		e := testWindowsSSHExecutor(nil)
		e.commandTimeout = 300 * time.Millisecond
		return e
	}

	start := time.Now()
	records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
	require.Len(t, records, 1)
	require.Positive(t, srv.windowsStallFired.Load(), "停住注入器未觸發")
	assert.Less(t, time.Since(start), 2*time.Second)
	rec := records[0]
	assert.Equal(t, model.ChangeSecretUnverified, rec.Status)
	assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, rec.Error)
	assert.EqualValues(t, 1, fx.candidateCount(t), "指令已送出而未回報 ⇒ 候選保留")

	var acct model.AssetAccount
	require.NoError(t, fx.db.Where("asset_id = ?", id).First(&acct).Error)
	creds, err := fx.assets.GetWithCredentialsForAccount(id, acct.ID)
	require.NoError(t, err)
	assert.Equal(t, "winoldpass", creds.Password, "本地憑證不動")
}

// TestClassifyWindowsOutcomeMarkerOutsideContract 契約表外的結果標記值（契約腳本印不出來）：
// 記狀態不可知、候選保留，不得判為確定失敗；契約內的值分流不變。
func TestClassifyWindowsOutcomeMarkerOutsideContract(t *testing.T) {
	const subject = "asset=7 user=svc"
	for _, code := range []int{2, 7, 99, 255, 100000} {
		for _, exit := range []int{0, 1, code} {
			err := classifyWindowsOutcome(subject, exit, marker(code), "stray output")
			var unknown *remoteStateUnknownError
			require.True(t, errors.As(err, &unknown), "標記 %d 退出碼 %d: err=%v", code, exit, err)
			assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, unknown.reason, "標記 %d", code)
			assert.Contains(t, err.Error(), "outside the script contract")
			var rejected *remoteRejectedError
			assert.False(t, errors.As(err, &rejected), "標記 %d 不得判為確定失敗", code)
		}
	}
	// 雙向：契約內的值維持各自的分流
	var rejected *remoteRejectedError
	require.True(t, errors.As(classifyWindowsOutcome(subject, 1, marker(1), ""), &rejected))
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rejected.reason)
	require.True(t, errors.As(classifyWindowsOutcome(subject, 1, marker(3), ""), &rejected))
	assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, rejected.reason)
	require.True(t, errors.As(classifyWindowsOutcome(subject, 1, marker(4), ""), &rejected))
	assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rejected.reason)
	assert.NoError(t, classifyWindowsOutcome(subject, 1, marker(0), ""))
	assert.NoError(t, classifyWindowsOutcome(subject, 1, marker(6), ""))
}

// TestWindowsSSHMarkerOutsideContractThroughRunner 契約表外的標記經 SSH 通道與狀態機落地：
// unverified、候選保留、本地憑證不動。
func TestWindowsSSHMarkerOutsideContractThroughRunner(t *testing.T) {
	fx := setupChangeSecretFixture(t, "root", "oldpass123")
	srv := newTestSSHServer(t, "Administrator", "winoldpass")
	srv.mu.Lock()
	srv.chpasswdExitCode = 1
	srv.windowsResultMarkerCode = 7
	srv.windowsExitCodeFirstExecOnly = true
	srv.mu.Unlock()
	host, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	id := fx.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-ssh-marker7", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsSSH, RotationSSHPort: port,
	})
	fx.runner.executors = func(string) rotationExecutor { return testWindowsSSHExecutor(nil) }

	records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
	require.Len(t, records, 1)
	require.Positive(t, srv.chpasswdExitFired.Load(), "退出碼注入器未觸發")
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, records[0].Error)
	assert.EqualValues(t, 1, fx.candidateCount(t), "契約表外的標記 ⇒ 分不清 ⇒ 候選保留")

	var acct model.AssetAccount
	require.NoError(t, fx.db.Where("asset_id = ?", id).First(&acct).Error)
	creds, err := fx.assets.GetWithCredentialsForAccount(id, acct.ID)
	require.NoError(t, err)
	assert.Equal(t, "winoldpass", creds.Password, "本地憑證不動")
}
