package asset

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 目標端自驗與回滾的契約：三行標準輸入、腳本的校準／自驗／回滾三句、退出碼 4／5／6 的分流，
// 以及經狀態機落地的候選處置。正式碼不得含回歸專用的強制失敗開關。

// TestWindowsRotationScriptContract 腳本文字含校準、設定、自驗、回滾與四個退出碼，
// 不含任何密碼與帳號名；標準輸入為新密碼、舊密碼、帳號名各一行。
func TestWindowsRotationScriptContract(t *testing.T) {
	const account = "svc backup"
	const newPassword = "N3w-P@ssw0rd!xyz"
	const oldPassword = "0ld-P@ssw0rd!abc"

	script := decodeWindowsCommand(t, buildWindowsCommand(windowsRotationScript))
	assert.NotContains(t, script, newPassword)
	assert.NotContains(t, script, oldPassword)
	assert.NotContains(t, script, account)
	assert.Equal(t, 3, strings.Count(script, "$in.ReadLine()"), "新密碼、舊密碼、帳號名各讀一行")
	assert.NotContains(t, script, "[Console]::In", "標準輸入須經指定 UTF-8 的讀取器，不經主控台預設編碼")
	assert.Contains(t, script, "if ([string]::IsNullOrEmpty($p) -or [string]::IsNullOrEmpty($o) -or [string]::IsNullOrEmpty($u)) { Write-Result 3; exit 3 }", "缺任一行即結局碼 3，且在觸碰帳號之前")
	assert.Less(t, strings.Index(script, "exit 3"), strings.Index(script, "Set-LocalUser"), "結局碼 3 的判斷須在 Set-LocalUser 之前")

	// 校準：先以舊密碼試驗證器；驗不過或拋例外都把 $v 清空
	assert.Contains(t, script, "if (-not $v.ValidateCredentials($u, $o)) { $v = $null }", "先以舊密碼校準驗證器")
	assert.Contains(t, script, "} catch { $v = $null }", "校準拋例外＝驗證器不可用")
	assert.Contains(t, script, "try { Set-LocalUser -Name $u -Password (ConvertTo-SecureString $p -AsPlainText -Force) } catch { [Console]::Error.WriteLine($_.Exception.Message); Write-Result 1; exit 1 }", "設定失敗＝結局碼 1（帳號未變更），錯誤原文只進 stderr")
	assert.Contains(t, script, "if ($null -eq $v) { Write-Result 6; exit 6 }", "驗證器不可用：新密碼保留、結局碼 6")
	assert.Contains(t, script, "try { $ok = $v.ValidateCredentials($u, $p) } catch { Write-Result 6; exit 6 }", "自驗拋例外＝結局碼 6，不回滾")
	assert.Contains(t, script, "if ($ok) { Write-Result 0; exit 0 }")
	assert.Contains(t, script, "try { Set-LocalUser -Name $u -Password (ConvertTo-SecureString $o -AsPlainText -Force) } catch { Write-Result 5; exit 5 }", "回滾失敗＝結局碼 5")
	assert.True(t, strings.HasSuffix(script, "Write-Result 4; exit 4"), "回滾成功以結局碼 4 結束")
	assert.Less(t, strings.Index(script, "$p -AsPlainText"), strings.Index(script, "$o -AsPlainText"), "先設新密碼，回滾才用舊密碼")

	// 結果標記：定義在腳本開頭、印到標準輸出、只含結局碼；每一個 exit 都緊跟同碼的標記
	assert.Contains(t, script, "function Write-Result([int]$c) { [Console]::Out.WriteLine('ROTATION_RESULT=' + $c); [Console]::Out.Flush() }")
	assert.Less(t, strings.Index(script, "function Write-Result"), strings.Index(script, "ReadLine"), "標記函式須在讀密碼之前定義")
	pairs := regexp.MustCompile(`Write-Result (\d+); exit (\d+)`).FindAllStringSubmatch(script, -1)
	assert.Equal(t, strings.Count(script, "exit "), len(pairs), "每個 exit 都須緊跟同碼的結果標記")
	for _, p := range pairs {
		assert.Equal(t, p[1], p[2], "標記碼與退出碼須相同: %s", p[0])
	}

	stdin := windowsRotationStdin(newPassword, oldPassword, account)
	assert.Equal(t, newPassword+"\n"+oldPassword+"\n"+account+"\n", stdin, "第一行新密碼、第二行舊密碼、第三行帳號名")
}

// TestClassifyWindowsExitSelfVerify 4 → 確定失敗帶自驗失敗碼；5 → 狀態不可知帶回滾失敗碼；6 → 視同成功。
func TestClassifyWindowsExitSelfVerify(t *testing.T) {
	var rejected *remoteRejectedError
	err := classifyWindowsExit(windowsExitSelfVerifyRolledBack, "")
	require.True(t, errors.As(err, &rejected), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rejected.reason)

	var unknown *remoteStateUnknownError
	err = classifyWindowsExit(windowsExitSelfVerifyRollbackFailed, "ignored")
	require.True(t, errors.As(err, &unknown), "err=%v", err)
	assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, unknown.reason)
	assert.False(t, errors.As(err, &rejected), "退出碼 5 不得判為確定失敗")
	assert.NotContains(t, err.Error(), "ignored", "退出碼 5 的 stderr 不進錯誤")

	assert.NoError(t, classifyWindowsExit(windowsExitSelfVerifyUnavailable, ""), "退出碼 6：新密碼已設定，交重連驗證")

	assert.True(t, model.IsChangeSecretReason(model.ChangeSecretReasonRemoteSelfVerifyFailed))
	assert.True(t, model.IsChangeSecretReason(model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed))
	assert.True(t, model.IsChangeSecretReason(model.ChangeSecretReasonInvalidOldSecret))
}

// TestWindowsOldSecretLineSafety 舊密碼與新密碼同一條行協定；違者是本地前置錯誤。
func TestWindowsOldSecretLineSafety(t *testing.T) {
	for _, bad := range []string{"", "a\nb", "a\rb", "a\x00b"} {
		err := validateWindowsOldSecret(bad)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "%q 應為本地前置錯誤", bad)
		assert.Equal(t, model.ChangeSecretReasonInvalidOldSecret, local.reason)
	}
	assert.NoError(t, validateWindowsOldSecret("ok'\"$`;pass"))
}

// TestWinRMExecutorSelfVerifyExitCodes WinRM 通道：三行標準輸入；exit 4／5／6 的分流；舊密碼含換行本地攔下。
func TestWinRMExecutorSelfVerifyExitCodes(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"

	t.Run("標準輸入三行", func(t *testing.T) {
		f := newFakeWinRMServer(t, "0ld-P@ss!")
		require.NoError(t, testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "0ld-P@ss!", newPassword))
		assert.Equal(t, newPassword+"\n0ld-P@ss!\nAdministrator\n", f.stdinText(), "第一行新密碼、第二行舊密碼、第三行帳號名")
		assert.NotContains(t, decodeWindowsCommand(t, f.snapshot().commands[0]), "0ld-P@ss!", "舊密碼不進腳本")
	})

	t.Run("exit 4 自驗失敗已回滾", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.exitCode = windowsExitSelfVerifyRolledBack })
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rejected.reason)
		assert.Equal(t, "old", f.snapshot().password, "端點仍是舊密碼")
	})

	t.Run("exit 5 回滾失敗 狀態不可知", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.exitCode = windowsExitSelfVerifyRollbackFailed })
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword)
		var unknown *remoteStateUnknownError
		require.True(t, errors.As(err, &unknown), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, unknown.reason)
		var rejected *remoteRejectedError
		var local *localPreconditionError
		assert.False(t, errors.As(err, &rejected))
		assert.False(t, errors.As(err, &local))
	})

	t.Run("exit 6 驗證器不可用 交重連驗證", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.exitCode = windowsExitSelfVerifyUnavailable; f.exitCodeFirstCommandOnly = true })
		e := testWinRMExecutor(f, nil)
		require.NoError(t, e.Rotate(context.Background(), winrmTarget(f), "old", newPassword))
		assert.Equal(t, newPassword, f.snapshot().password, "端點已是新密碼")
		require.NoError(t, e.Verify(context.Background(), winrmTarget(f), newPassword), "重連驗證以新密碼通過")
	})

	t.Run("舊密碼含換行 本地攔下", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old\nx", newPassword)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonInvalidOldSecret, local.reason)
		assert.Equal(t, 0, f.snapshot().handshakes, "遠端完全未被觸碰")
	})
}

// TestWindowsSSHExecutorSelfVerifyExitCodes SSH 通道同一套契約。
func TestWindowsSSHExecutorSelfVerifyExitCodes(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"

	t.Run("標準輸入三行", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "0ld-P@ss!")
		require.NoError(t, testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "0ld-P@ss!", newPassword))
		stdin, _ := srv.lastChpasswdStdin.Load().(string)
		assert.Equal(t, newPassword+"\n0ld-P@ss!\nAdministrator\n", stdin)
		cmd, _ := srv.lastExecCommand.Load().(string)
		assert.NotContains(t, decodeWindowsCommand(t, cmd), "0ld-P@ss!", "舊密碼不進腳本")
	})

	t.Run("exit 4", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = windowsExitSelfVerifyRolledBack
		srv.mu.Unlock()
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
		require.Positive(t, srv.chpasswdExitFired.Load(), "退出碼注入器未觸發")
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rejected.reason)
	})

	t.Run("exit 5", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = windowsExitSelfVerifyRollbackFailed
		srv.mu.Unlock()
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword)
		var unknown *remoteStateUnknownError
		require.True(t, errors.As(err, &unknown), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, unknown.reason)
	})

	t.Run("exit 6", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		srv.mu.Lock()
		srv.chpasswdExitCode = windowsExitSelfVerifyUnavailable
		srv.mu.Unlock()
		require.NoError(t, testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old", newPassword))
		require.Positive(t, srv.chpasswdExitFired.Load(), "退出碼注入器未觸發")
	})

	t.Run("舊密碼含換行 本地攔下", func(t *testing.T) {
		srv := newTestSSHServer(t, "Administrator", "old")
		err := testWindowsSSHExecutor(nil).Rotate(context.Background(), sshTarget(srv, "Administrator"), "old\nx", newPassword)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonInvalidOldSecret, local.reason)
		assert.Zero(t, srv.passwordAuthCalls.Load(), "連撥號都沒有")
	})
}

// TestWinRMSelfVerifyThroughRunner 退出碼 4／5／6 經狀態機落地：4 記 failed 帶自驗失敗碼、候選清除；
// 5 記 unverified 帶回滾失敗碼、候選保留；6 走重連驗證後 success。三案本地憑證只在 6 提交為新密碼。
func TestWinRMSelfVerifyThroughRunner(t *testing.T) {
	run := func(t *testing.T, exit int) (*csFixture, *fakeWinRMServer, uint, model.ChangeSecretRecord) {
		t.Helper()
		f := newFakeWinRMServer(t, "winoldpass")
		// 退出碼只套在改密指令上；其後的驗證指令照常退出 0
		f.set(func(f *fakeWinRMServer) { f.exitCode = exit; f.exitCodeFirstCommandOnly = true })
		host, port := f.hostPort()
		fx := setupChangeSecretFixture(t, "root", "oldpass123")
		id := fx.addRotationAsset(t, &CreateAssetRequest{
			Name: "win-selfverify", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
			Username: "Administrator", Password: "winoldpass",
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: port,
		})
		fx.runner.executors = func(string) rotationExecutor { return testWinRMExecutor(f, nil) }
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
		require.Len(t, records, 1)
		return fx, f, id, records[0]
	}
	storedPassword := func(t *testing.T, fx *csFixture, assetID uint) string {
		t.Helper()
		var acct model.AssetAccount
		require.NoError(t, fx.db.Where("asset_id = ?", assetID).First(&acct).Error)
		creds, err := fx.assets.GetWithCredentialsForAccount(assetID, acct.ID)
		require.NoError(t, err)
		return creds.Password
	}

	t.Run("exit 4 自驗失敗已回滾 failed", func(t *testing.T) {
		fx, f, id, rec := run(t, windowsExitSelfVerifyRolledBack)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyFailed, rec.Error)
		assert.EqualValues(t, 0, fx.candidateCount(t), "目標已回滾 ⇒ 候選清除")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id), "本地憑證不動")
		assert.Equal(t, "winoldpass", f.snapshot().password, "端點仍是舊密碼")
	})

	t.Run("exit 5 回滾失敗 unverified", func(t *testing.T) {
		fx, _, id, rec := run(t, windowsExitSelfVerifyRollbackFailed)
		assert.Equal(t, model.ChangeSecretUnverified, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, rec.Error)
		assert.EqualValues(t, 1, fx.candidateCount(t), "狀態不可知 ⇒ 候選保留")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id), "本地憑證不動")
	})

	t.Run("exit 6 驗證器不可用 重連驗證後 success", func(t *testing.T) {
		fx, f, id, rec := run(t, windowsExitSelfVerifyUnavailable)
		assert.Equal(t, model.ChangeSecretSuccess, rec.Status, "錯誤: %s", rec.Error)
		assert.EqualValues(t, 0, fx.candidateCount(t))
		newPassword := storedPassword(t, fx, id)
		assert.NotEqual(t, "winoldpass", newPassword, "本地憑證已提交為新密碼")
		assert.Equal(t, newPassword, f.snapshot().password)
	})
}

// TestWindowsRotationProductionHasNoLoopbackSwitch 正式碼（非測試檔、非回歸專用建置檔）
// 不得含強制自驗失敗的開關與回歸建置的符號。掃到的檔數與略過的回歸檔數都有下限，
// 掃到空集合即轉紅。
func TestWindowsRotationProductionHasNoLoopbackSwitch(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(self)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	forbidden := []string{"loopback", "Loopback", "$ok = $false", "SelfVerifyFailure", "RotateValidatorUnavailable"}
	scanned, skipped := 0, 0
	sawScript := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		content := string(raw)
		if strings.HasPrefix(content, "//go:build loopback") {
			skipped++
			continue
		}
		scanned++
		if name == "windows_script.go" {
			sawScript = true
		}
		for _, token := range forbidden {
			if idx := strings.Index(content, token); idx >= 0 {
				line := 1 + strings.Count(content[:idx], "\n")
				t.Errorf("%s:%d 含回歸專用記號 %q，正式碼不得有強制自驗失敗的開關", name, line, token)
			}
		}
	}
	assert.GreaterOrEqual(t, scanned, 20, "掃描檔數異常少，守衛可能沒掃到正式碼")
	assert.True(t, sawScript, "windows_script.go 必須在掃描範圍內")
	assert.GreaterOrEqual(t, skipped, 1, "回歸專用建置檔應存在且被略過（它才是開關的合法所在）")
}
