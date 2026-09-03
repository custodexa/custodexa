package asset

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// windowsSSHExecutor 對行程內 SSH 靶機：命令列形狀（顯式 powershell.exe、不含密碼、
// 密碼只在標準輸入）與 *ssh.ExitError 分流。靶機沿 change_secret_testserver_test.go
// 的 fixture（它記錄 exec 命令列與收到的標準輸入，退出碼與斷線可注入），未改動。

func sshTarget(srv *testSSHServer, username string) rotationTarget {
	return rotationTarget{
		asset:     &model.Asset{Name: "win-ssh", Protocol: model.ProtocolRDP, Host: "127.0.0.1", Port: 3389, RotationChannel: model.RotationChannelWindowsSSH},
		channel:   model.RotationChannelWindowsSSH,
		username:  username,
		addr:      srv.addr(),
		hostKeyCB: srv.hostKeyCallback(),
	}
}

func testWindowsSSHExecutor(slept *[]time.Duration) windowsSSHExecutor {
	e := newWindowsSSHExecutor()
	e.sleep = func(_ context.Context, d time.Duration) error {
		if slept != nil {
			*slept = append(*slept, d)
		}
		return nil
	}
	return e
}

// TestWindowsSSHExecutorCommandShape exec 字串以 powershell.exe 開頭、不含密碼；標準輸入含密碼。
func TestWindowsSSHExecutorCommandShape(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"
	srv := newTestSSHServer(t, "Administrator", "old")
	e := testWindowsSSHExecutor(nil)

	require.NoError(t, e.Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword))

	cmd, _ := srv.lastExecCommand.Load().(string)
	require.True(t, strings.HasPrefix(cmd, "powershell.exe -NoProfile -NonInteractive -EncodedCommand "), "exec 字串須顯式呼叫 powershell.exe: %q", cmd)
	assert.NotContains(t, cmd, newPassword)
	assert.NotContains(t, cmd, "chpasswd")
	assert.NotContains(t, cmd, "sudo")
	script := decodeWindowsCommand(t, cmd)
	assert.Contains(t, script, "Set-LocalUser -Name $u -Password")
	assert.NotContains(t, script, "Administrator", "帳號名不進腳本文字")
	assert.NotContains(t, script, newPassword)

	stdin, _ := srv.lastChpasswdStdin.Load().(string)
	assert.Equal(t, newPassword+"\nold\nAdministrator\n", stdin, "密碼與帳號名只經標準輸入投遞（第一行新、第二行舊、第三行帳號名）")

	// 驗證：以新密碼另建連線跑無副作用指令（靶機未更新密碼，故此處仍以 old 驗）
	require.NoError(t, e.Verify(context.Background(), sshTarget(srv, "Administrator"), "old"))
	verifyCmd, _ := srv.lastExecCommand.Load().(string)
	assert.Equal(t, windowsVerifyScript, decodeWindowsCommand(t, verifyCmd))
	verifyStdin, _ := srv.lastChpasswdStdin.Load().(string)
	assert.Empty(t, verifyStdin, "驗證不投遞任何秘密")
}

// TestWindowsSSHExecutorExitCodeSemantics exit 3 → 密碼未投遞；其餘非零 → 遠端拒絕；
// 斷線 → 狀態不可知；舊密碼錯 → 登入失敗；帳號名不合 → 本地攔下（不撥號）。
func TestWindowsSSHExecutorExitCodeSemantics(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"

	t.Run("exit 3", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = 3
		srv.mu.Unlock()
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
		require.Positive(t, srv.chpasswdExitFired.Load(), "退出碼注入器未觸發")
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, rejected.reason)
	})

	t.Run("exit 1", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = 1
		srv.mu.Unlock()
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rejected.reason)
	})

	t.Run("斷線", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdDropConn = true
		srv.mu.Unlock()
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
		require.Error(t, err)
		require.Positive(t, srv.chpasswdDropFired.Load(), "斷線注入器未觸發")
		var rejected *remoteRejectedError
		var local *localPreconditionError
		assert.False(t, errors.As(err, &rejected), "斷線不得判為確定失敗")
		assert.False(t, errors.As(err, &local))
	})

	t.Run("舊密碼錯", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "wrong", newPassword)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonOldCredentialLoginFailed, rejected.reason)
		assert.Zero(t, srv.chpasswdCalls.Load(), "登入失敗即不送指令")
	})

	t.Run("帳號名不合", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, `DOMAIN\Administrator`), "old", newPassword)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonAccountNameInvalid, local.reason)
		assert.Zero(t, srv.passwordAuthCalls.Load(), "遠端完全未被觸碰（連撥號都沒有）")
	})

	t.Run("驗證重試序列", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		var slept []time.Duration
		err := testWindowsSSHExecutor(&slept).Verify(context.Background(), sshTarget(srv, "Administrator"), "wrong")
		require.Error(t, err)
		assert.Equal(t, []time.Duration{2 * time.Second, 5 * time.Second}, slept, "與 WinRM 同一組序列")
		assert.EqualValues(t, 3, srv.passwordAuthCalls.Load(), "三次嘗試各撥號一次")
	})
}
