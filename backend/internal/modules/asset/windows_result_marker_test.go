package asset

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 結局訊號的契約：腳本印在標準輸出的結果標記為主、退出碼為輔。目標的預設 shell 可能把退出碼
// 改寫（真機：Windows OpenSSH 預設 shell 為 PowerShell 時，顯式 exit 4 到我方成 exit 1），
// 分流不得因此退化；標記缺失而退出碼非零，結局分不清，一律記狀態不可知並保留候選。

// TestWindowsResultMarkerParse 標記解析：容忍 CRLF、BOM、前後噪音；格式不對即視為缺失；多行取最後。
func TestWindowsResultMarkerParse(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		code   int
		found  bool
	}{
		{"CRLF", "ROTATION_RESULT=4\r\n", 4, true},
		{"LF", "ROTATION_RESULT=6\n", 6, true},
		{"無換行", "ROTATION_RESULT=0", 0, true},
		{"BOM", "\uFEFFROTATION_RESULT=3\r\n", 3, true},
		{"前後噪音", "warning: something\r\nROTATION_RESULT=5\r\ntrailing\r\n", 5, true},
		{"多行取最後", "ROTATION_RESULT=0\r\nROTATION_RESULT=4\r\n", 4, true},
		{"空", "", 0, false},
		{"只有 CLIXML 形狀", "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"></Objs>\r\n", 0, false},
		{"非數字", "ROTATION_RESULT=abc\r\n", 0, false},
		{"負數", "ROTATION_RESULT=-1\r\n", 0, false},
		{"行中出現不算", "x ROTATION_RESULT=4\r\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, found := parseWindowsResultMarker(c.stdout)
			assert.Equal(t, c.found, found)
			assert.Equal(t, c.code, code)
		})
	}
}

func marker(code int) string { return windowsResultMarkerPrefix + strconv.Itoa(code) + "\r\n" }

// TestClassifyWindowsOutcomeMarkerBeatsExitCode 標記存在時以標記為結局碼，退出碼被改寫成 1 也不影響分流。
func TestClassifyWindowsOutcomeMarkerBeatsExitCode(t *testing.T) {
	const subject = "asset=7 user=svc"
	var rejected *remoteRejectedError
	var unknown *remoteStateUnknownError

	assert.NoError(t, classifyWindowsOutcome(subject, 1, marker(windowsExitSelfVerifyUnavailable), "#< CLIXML"), "標記 6、退出碼 1：新密碼已設定，交重連驗證")
	assert.NoError(t, classifyWindowsOutcome(subject, 1, marker(0), ""), "標記 0、退出碼 1")
	assert.NoError(t, classifyWindowsOutcome(subject, 0, marker(0), ""))

	err := classifyWindowsOutcome(subject, 1, marker(windowsExitSelfVerifyRolledBack), "#< CLIXML")
	require.True(t, errors.As(err, &rejected), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rejected.reason)

	err = classifyWindowsOutcome(subject, 1, marker(windowsExitStdinNotDelivered), "")
	require.True(t, errors.As(err, &rejected), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, rejected.reason)

	err = classifyWindowsOutcome(subject, 1, marker(windowsExitSelfVerifyRollbackFailed), "")
	require.True(t, errors.As(err, &unknown), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, unknown.reason)

	err = classifyWindowsOutcome(subject, 1, marker(1), "Access is denied.\nmore")
	require.True(t, errors.As(err, &rejected), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rejected.reason)
	assert.Contains(t, err.Error(), "Access is denied", "設定失敗的 stderr 首行進 cause")
}

// TestClassifyWindowsOutcomeMissingMarker 標記缺失：退出碼非零＝狀態不可知（不是確定失敗，候選不清）；
// 退出碼 0 交重連驗證。
func TestClassifyWindowsOutcomeMissingMarker(t *testing.T) {
	const subject = "asset=7 user=svc"
	for _, exit := range []int{1, 3, 4, 5, 6, 255} {
		err := classifyWindowsOutcome(subject, exit, "#< CLIXML\r\n", "#< CLIXML")
		var unknown *remoteStateUnknownError
		require.True(t, errors.As(err, &unknown), "exit %d: err=%v", exit, err)
		assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, unknown.reason, "exit %d", exit)
		var rejected *remoteRejectedError
		var local *localPreconditionError
		assert.False(t, errors.As(err, &rejected), "exit %d 無標記不得判為確定失敗", exit)
		assert.False(t, errors.As(err, &local))
		assert.Contains(t, err.Error(), "without result marker")
	}
	assert.NoError(t, classifyWindowsOutcome(subject, 0, "", ""), "退出碼 0 無標記：交重連驗證")
}

// TestWindowsSSHExecutorResultMarker SSH 通道：退出碼被目標 shell 改寫成 1 時仍依標記分流；
// 無標記的退出碼 1 為狀態不可知。
func TestWindowsSSHExecutorResultMarker(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"
	rotate := func(t *testing.T, srv *testSSHServer) error {
		t.Helper()
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
		require.Positive(t, srv.chpasswdExitFired.Load(), "退出碼注入器未觸發")
		return err
	}
	degraded := func(t *testing.T, markerCode int) *testSSHServer {
		t.Helper()
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = 1
		srv.windowsResultMarkerCode = markerCode
		srv.windowsApplyStdinPassword = true
		srv.windowsExitCodeFirstExecOnly = true
		srv.mu.Unlock()
		return srv
	}

	t.Run("標記 6 退出碼 1 交重連驗證後通過", func(t *testing.T) {
		srv := degraded(t, windowsExitSelfVerifyUnavailable)
		require.NoError(t, rotate(t, srv))
		require.NoError(t, testWindowsSSHExecutor(nil).Verify(context.Background(), sshTarget(srv, "Administrator"), newPassword), "靶機已是新密碼")
	})

	t.Run("標記 4 退出碼 1 自驗失敗已回滾", func(t *testing.T) {
		srv := degraded(t, windowsExitSelfVerifyRolledBack)
		err := rotate(t, srv)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rejected.reason)
		require.NoError(t, testWindowsSSHExecutor(nil).Verify(context.Background(), sshTarget(srv, "Administrator"), "old"), "靶機仍是舊密碼")
	})

	t.Run("標記 3 退出碼 1 密碼未投遞", func(t *testing.T) {
		srv := degraded(t, windowsExitStdinNotDelivered)
		err := rotate(t, srv)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, rejected.reason)
	})

	t.Run("標記 5 退出碼 1 回滾失敗", func(t *testing.T) {
		srv := degraded(t, windowsExitSelfVerifyRollbackFailed)
		err := rotate(t, srv)
		var unknown *remoteStateUnknownError
		require.True(t, errors.As(err, &unknown), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, unknown.reason)
	})

	t.Run("退出碼 1 無標記 狀態不可知", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = 1
		srv.windowsOmitResultMarker = true
		srv.mu.Unlock()
		err := rotate(t, srv)
		var unknown *remoteStateUnknownError
		require.True(t, errors.As(err, &unknown), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, unknown.reason)
		var rejected *remoteRejectedError
		assert.False(t, errors.As(err, &rejected), "無標記的退出碼 1 不得判為確定失敗")
		assert.NotContains(t, err.Error(), newPassword)
	})

	t.Run("退出碼 0 無標記 交重連驗證", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.windowsOmitResultMarker = true
		srv.mu.Unlock()
		require.NoError(t, testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword))
	})
}

// TestWindowsSSHResultMarkerThroughRunner SSH 通道經狀態機落地：退出碼一律被改寫成 1 的目標上，
// 標記 6 → success 提交新密碼；標記 4 → failed 清候選；無標記 → unverified 保留候選。三案本地憑證只在 success 提交。
func TestWindowsSSHResultMarkerThroughRunner(t *testing.T) {
	run := func(t *testing.T, mut func(*testSSHServer)) (*csFixture, *testSSHServer, uint, model.ChangeSecretRecord) {
		t.Helper()
		fx := setupChangeSecretFixture(t, "root", "oldpass123")
		srv := newTestSSHServer(t, "Administrator", "winoldpass")
		srv.mu.Lock()
		// 退出碼改寫只套在改密指令上；其後的驗證指令照常退出 0
		srv.chpasswdExitCode = 1
		srv.windowsExitCodeFirstExecOnly = true
		mut(srv)
		srv.mu.Unlock()
		host, portStr, err := net.SplitHostPort(srv.addr())
		require.NoError(t, err)
		port, err := strconv.Atoi(portStr)
		require.NoError(t, err)
		id := fx.addRotationAsset(t, &CreateAssetRequest{
			Name: "win-ssh-marker", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
			Username: "Administrator", Password: "winoldpass",
			RotationChannel: model.RotationChannelWindowsSSH, RotationSSHPort: port,
		})
		fx.runner.executors = func(string) rotationExecutor { return testWindowsSSHExecutor(nil) }
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
		require.Len(t, records, 1)
		require.Positive(t, srv.chpasswdExitFired.Load(), "退出碼注入器未觸發")
		return fx, srv, id, records[0]
	}
	storedPassword := func(t *testing.T, fx *csFixture, assetID uint) string {
		t.Helper()
		var acct model.AssetAccount
		require.NoError(t, fx.db.Where("asset_id = ?", assetID).First(&acct).Error)
		creds, err := fx.assets.GetWithCredentialsForAccount(assetID, acct.ID)
		require.NoError(t, err)
		return creds.Password
	}

	t.Run("標記 6 退出碼 1 success", func(t *testing.T) {
		fx, srv, id, rec := run(t, func(s *testSSHServer) {
			s.windowsResultMarkerCode = windowsExitSelfVerifyUnavailable
			s.windowsApplyStdinPassword = true
		})
		assert.Equal(t, model.ChangeSecretSuccess, rec.Status, "錯誤: %s", rec.Error)
		assert.EqualValues(t, 0, fx.candidateCount(t))
		newPassword := storedPassword(t, fx, id)
		assert.NotEqual(t, "winoldpass", newPassword, "本地憑證已提交為新密碼")
		srv.mu.Lock()
		remote := srv.password
		srv.mu.Unlock()
		assert.Equal(t, newPassword, remote, "靶機與本地提交的一致")
	})

	t.Run("標記 4 退出碼 1 failed 清候選", func(t *testing.T) {
		fx, _, id, rec := run(t, func(s *testSSHServer) { s.windowsResultMarkerCode = windowsExitSelfVerifyRolledBack })
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rec.Error)
		assert.EqualValues(t, 0, fx.candidateCount(t), "目標已回滾 ⇒ 候選清除")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id), "本地憑證不動")
	})

	t.Run("無標記 退出碼 1 unverified 保留候選", func(t *testing.T) {
		fx, _, id, rec := run(t, func(s *testSSHServer) { s.windowsOmitResultMarker = true })
		assert.Equal(t, model.ChangeSecretUnverified, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, rec.Error)
		assert.EqualValues(t, 1, fx.candidateCount(t), "結局分不清 ⇒ 候選保留")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id), "本地憑證不動")
		assert.False(t, strings.Contains(rec.Error, "exit"), "記錄只放原因碼")
	})
}

// TestWinRMMissingMarkerThroughRunner WinRM 通道同一條底線：無標記的非零退出記 unverified、候選保留。
func TestWinRMMissingMarkerThroughRunner(t *testing.T) {
	f := newFakeWinRMServer(t, "winoldpass")
	f.set(func(f *fakeWinRMServer) { f.exitCode = 1; f.omitResultMarker = true; f.stderr = "#< CLIXML" })
	host, port := f.hostPort()
	fx := setupChangeSecretFixture(t, "root", "oldpass123")
	id := fx.addRotationAsset(t, &CreateAssetRequest{
		Name: "win-marker", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
		Username: "Administrator", Password: "winoldpass",
		RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: port,
	})
	fx.runner.executors = func(string) rotationExecutor { return testWinRMExecutor(f, nil) }
	records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
	require.Len(t, records, 1)
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, records[0].Error)
	assert.EqualValues(t, 1, fx.candidateCount(t), "結局分不清 ⇒ 候選保留")
	assert.Len(t, f.snapshot().commands, 1, "指令確實已送出")
}
