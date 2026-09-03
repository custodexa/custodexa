package asset

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// windowsWinRMExecutor 對假 WS-Man 端點的三態分流、驗證重試序列、逾時語義，
// 以及經 ChangeSecretRunner 的端到端狀態機。

func winrmTarget(f *fakeWinRMServer) rotationTarget {
	return rotationTarget{asset: f.asset(), channel: model.RotationChannelWindowsWinRM, username: "Administrator"}
}

// TestWinRMExecutorExitCodeSemantics exit 0 成功（密碼只在標準輸入）、exit 3 密碼未投遞、
// exit 1 遠端拒絕、連線中斷狀態不可知、憑證錯登入失敗、帳號名不合本地攔下。
func TestWinRMExecutorExitCodeSemantics(t *testing.T) {
	const newPassword = "N3w-P@ssw0rd!"

	t.Run("exit 0", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		e := testWinRMExecutor(f, nil)
		require.NoError(t, e.Rotate(context.Background(), winrmTarget(f), "old", newPassword))

		snap := f.snapshot()
		require.Len(t, snap.commands, 1)
		script := decodeWindowsCommand(t, snap.commands[0])
		assert.Contains(t, script, "Set-LocalUser -Name $u -Password")
		assert.NotContains(t, script, "Administrator", "帳號名不進腳本文字")
		assert.NotContains(t, snap.commands[0], newPassword, "命令列不得含新密碼")
		assert.NotContains(t, script, newPassword, "腳本不得含新密碼")
		assert.Equal(t, newPassword+"\nold\nAdministrator\n", f.stdinText(), "密碼與帳號名只經標準輸入投遞（第一行新、第二行舊、第三行帳號名）")
		assert.True(t, snap.stdinEOF, "標準輸入須送 EOF")
		assert.Equal(t, 0, snap.plaintextBodies, "全部載荷皆加密")
		assert.Equal(t, newPassword, snap.password, "端點以新密碼接受後續交握")
	})

	t.Run("exit 3 密碼未投遞", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.exitCode = 3 })
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, rejected.reason)
	})

	t.Run("exit 1 遠端拒絕", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.exitCode = 1; f.stderr = "Access is denied." })
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rejected.reason)
		assert.Contains(t, err.Error(), "Access is denied", "stderr 進 cause 供 log 診斷")
	})

	t.Run("連線中斷 狀態不可知", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.dropOnReceive = true })
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword)
		require.Error(t, err)
		var rejected *remoteRejectedError
		var local *localPreconditionError
		assert.False(t, errors.As(err, &rejected), "指令送出後斷線不得判為確定失敗")
		assert.False(t, errors.As(err, &local))
	})

	t.Run("OperationTimeout fault 後繼續等", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.timeoutFaultOnce = true })
		require.NoError(t, testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword))
		assert.GreaterOrEqual(t, f.snapshot().receives, 2)
	})

	t.Run("非逾時 fault 狀態不可知", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.faultOnReceive = true })
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "old", newPassword)
		require.Error(t, err)
		var rejected *remoteRejectedError
		assert.False(t, errors.As(err, &rejected))
	})

	t.Run("舊密碼錯 登入失敗", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), winrmTarget(f), "wrong", newPassword)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonOldCredentialLoginFailed, rejected.reason)
		assert.Empty(t, f.snapshot().commands, "登入失敗即不送指令")
	})

	t.Run("帳號名不合 本地攔下", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		target := winrmTarget(f)
		target.username = `DOMAIN\Administrator`
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), target, "old", newPassword)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "err=%v", err)
		assert.Equal(t, model.ChangeSecretReasonAccountNameInvalid, local.reason)
		assert.Equal(t, 0, f.snapshot().handshakes, "遠端完全未被觸碰")
	})
}

// TestWinRMExecutorVerifyRetrySequence 驗證以新密碼另建工作階段，固定序列 0s／2s／5s 三次；
// 前兩次被拒、第三次成功仍算成功；三次皆失敗回錯。
func TestWinRMExecutorVerifyRetrySequence(t *testing.T) {
	t.Run("第三次成功", func(t *testing.T) {
		f := newFakeWinRMServer(t, "new")
		f.set(func(f *fakeWinRMServer) { f.failHandshakes = 2 })
		var slept []time.Duration
		e := testWinRMExecutor(f, &slept)
		require.NoError(t, e.Verify(context.Background(), winrmTarget(f), "new"))
		assert.Equal(t, []time.Duration{2 * time.Second, 5 * time.Second}, slept, "序列 0s／2s／5s：首次不等，其後等 2s、5s")
		snap := f.snapshot()
		// 每則 WS-Man 訊息各自交握：前兩次嘗試各在第一則就被拒，第三次才走完整序列
		assert.Greater(t, snap.handshakes, 2, "前兩次交握被拒各佔一次，第三次成功後才開始送指令")
		require.Len(t, snap.commands, 1)
		assert.Equal(t, windowsVerifyScript, decodeWindowsCommand(t, snap.commands[0]))
		assert.Empty(t, f.stdinText(), "驗證不投遞任何秘密")
	})

	t.Run("序列用盡回錯", func(t *testing.T) {
		f := newFakeWinRMServer(t, "new")
		var slept []time.Duration
		e := testWinRMExecutor(f, &slept)
		err := e.Verify(context.Background(), winrmTarget(f), "wrong")
		require.ErrorIs(t, err, errWinRMAuthFailed)
		assert.Equal(t, []time.Duration{2 * time.Second, 5 * time.Second}, slept)
		assert.Equal(t, 3, f.snapshot().handshakes, "三次嘗試各一次交握")
	})

	t.Run("驗證指令非零退出視為失敗", func(t *testing.T) {
		f := newFakeWinRMServer(t, "new")
		f.set(func(f *fakeWinRMServer) { f.exitCode = 5 })
		err := testWinRMExecutor(f, nil).Verify(context.Background(), winrmTarget(f), "new")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit 5")
	})
}

// TestWinRMExecutorTimeoutIsUnverified 指令送出後逾時：回非分類錯誤（狀態不可知），
// 且逾時後立即返回（不等目標）。建立 shell 階段的逾時是指令送出前的失敗，
// 分流見 TestWinRMExecutorSessionFailuresAreDefinite。
func TestWinRMExecutorTimeoutIsUnverified(t *testing.T) {
	f := newFakeWinRMServer(t, "old")
	f.set(func(f *fakeWinRMServer) { f.stallReceive = 3 * time.Second })
	e := testWinRMExecutor(f, nil)
	e.commandTimeout = 300 * time.Millisecond
	start := time.Now()
	err := e.Rotate(context.Background(), winrmTarget(f), "old", "NewP@ss1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	var rejected *remoteRejectedError
	var local *localPreconditionError
	assert.False(t, errors.As(err, &rejected), "指令送出後的逾時不得判為確定失敗")
	assert.False(t, errors.As(err, &local))
	assert.Less(t, time.Since(start), 2*time.Second, "逾時後不得等目標跑完")
	assert.Len(t, f.snapshot().commands, 1, "指令確實已送出")
}

// closedTCPPort 一個此刻沒有人監聽的本機埠（連線會被拒）。
func closedTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// TestWinRMExecutorSessionFailuresAreDefinite 指令送出前的失敗一律是確定失敗（遠端未變更）：
// 撥號逾時、連線被拒、TLS 憑證不受信任、目標對交握回 403，都歸「無法建立工作階段」並保留
// 建立 shell 階段的成因型別供 log 判讀；舊密碼錯與加密不可用維持各自的原因碼（見
// TestWinRMExecutorExitCodeSemantics 與 TestWinRMClientRefusesUnencryptedTarget）。
func TestWinRMExecutorSessionFailuresAreDefinite(t *testing.T) {
	assertUnreachable := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		var rejected *remoteRejectedError
		require.True(t, errors.As(err, &rejected), "指令送出前的失敗須為確定失敗: %v", err)
		assert.Equal(t, model.ChangeSecretReasonRemoteUnreachable, rejected.reason)
		var dialErr *winrmDialError
		assert.True(t, errors.As(err, &dialErr), "成因須保留建立 shell 階段的型別: %v", err)
	}

	t.Run("撥號逾時", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.stallCreate = 3 * time.Second })
		e := testWinRMExecutor(f, nil)
		e.dialTimeout = 300 * time.Millisecond
		start := time.Now()
		err := e.Rotate(context.Background(), winrmTarget(f), "old", "NewP@ss1")
		assertUnreachable(t, err)
		assert.Contains(t, err.Error(), "timed out")
		assert.Less(t, time.Since(start), 2*time.Second, "逾時後不得等目標")
		assert.Empty(t, f.snapshot().commands, "shell 未建立即不送指令")
	})

	t.Run("連線被拒", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		target := winrmTarget(f)
		target.asset.WinrmPort = closedTCPPort(t)
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), target, "old", "NewP@ss1")
		assertUnreachable(t, err)
		assert.Equal(t, 0, f.snapshot().handshakes, "沒有請求抵達任何端點")
	})

	t.Run("TLS 憑證不受信任", func(t *testing.T) {
		f := newFakeWinRMTLSServer(t, "old")
		target := winrmTarget(f)
		target.asset.WinrmTLSMode = model.WinrmTLSModeSystem
		err := testWinRMExecutor(f, nil).Rotate(context.Background(), target, "old", "NewP@ss1")
		assertUnreachable(t, err)
		assert.Contains(t, err.Error(), "x509")
		assert.Equal(t, 0, f.snapshot().handshakes, "憑證不受信任時不得有請求抵達端點（不降級）")
	})

	t.Run("交握回 403 正式 NTLM 路徑", func(t *testing.T) {
		f := newFakeWinRMServer(t, "old")
		f.set(func(f *fakeWinRMServer) { f.mode = fakeWinRMModeForbidden })
		e := newWindowsWinRMExecutor() // 正式組態：真 NTLM 交握
		e.dialTimeout, e.commandTimeout = 5*time.Second, 5*time.Second
		err := e.Rotate(context.Background(), winrmTarget(f), "old", "NewP@ss1")
		assertUnreachable(t, err)
		assert.Contains(t, err.Error(), "403")
		snap := f.snapshot()
		assert.Equal(t, 0, snap.bodyRequests, "交握未完成即不得送出任何載荷")
		assert.Empty(t, snap.commands)
	})
}

// TestWinRMSessionFailuresThroughRunner 分流在狀態機的落地：工作階段建立前的 403 與撥號逾時
// 記 failed 帶「無法建立工作階段」且候選清除；指令送出後斷線記 unverified 且候選保留。
// 三案的本地憑證都不得變動。
func TestWinRMSessionFailuresThroughRunner(t *testing.T) {
	run := func(t *testing.T, f *fakeWinRMServer, exec rotationExecutor) (*csFixture, uint, model.ChangeSecretRecord) {
		t.Helper()
		host, port := f.hostPort()
		fx := setupChangeSecretFixture(t, "root", "oldpass123")
		id := fx.addRotationAsset(t, &CreateAssetRequest{
			Name: "win-session", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
			Username: "Administrator", Password: "winoldpass",
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: port,
		})
		fx.runner.executors = func(string) rotationExecutor { return exec }
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
		require.Len(t, records, 1)
		return fx, id, records[0]
	}
	storedPassword := func(t *testing.T, fx *csFixture, assetID uint) string {
		t.Helper()
		var acct model.AssetAccount
		require.NoError(t, fx.db.Where("asset_id = ?", assetID).First(&acct).Error)
		creds, err := fx.assets.GetWithCredentialsForAccount(assetID, acct.ID)
		require.NoError(t, err)
		return creds.Password
	}

	t.Run("工作階段建立前 403", func(t *testing.T) {
		f := newFakeWinRMServer(t, "winoldpass")
		f.set(func(f *fakeWinRMServer) { f.mode = fakeWinRMModeForbidden })
		e := newWindowsWinRMExecutor()
		e.dialTimeout, e.commandTimeout = 5*time.Second, 5*time.Second
		fx, id, rec := run(t, f, e)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteUnreachable, rec.Error)
		assert.EqualValues(t, 0, fx.candidateCount(t), "指令未送出 ⇒ 候選清除")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id), "本地憑證不動")
	})

	t.Run("撥號逾時", func(t *testing.T) {
		f := newFakeWinRMServer(t, "winoldpass")
		f.set(func(f *fakeWinRMServer) { f.stallCreate = 3 * time.Second })
		e := testWinRMExecutor(f, nil)
		e.dialTimeout = 300 * time.Millisecond
		fx, id, rec := run(t, f, e)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteUnreachable, rec.Error)
		assert.EqualValues(t, 0, fx.candidateCount(t), "指令未送出 ⇒ 候選清除")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id))
		assert.Empty(t, f.snapshot().commands)
	})

	t.Run("指令送出後斷線", func(t *testing.T) {
		f := newFakeWinRMServer(t, "winoldpass")
		f.set(func(f *fakeWinRMServer) { f.dropOnReceive = true })
		fx, id, rec := run(t, f, testWinRMExecutor(f, nil))
		assert.Equal(t, model.ChangeSecretUnverified, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, rec.Error)
		assert.EqualValues(t, 1, fx.candidateCount(t), "狀態不可知 ⇒ 候選保留")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id))
		assert.Len(t, f.snapshot().commands, 1, "指令確實已送出")
	})
}

// TestWinRMExecutorThroughRunner 真執行器接上狀態機：成功提交新密碼、exit 3 乾淨失敗清候選、
// 斷線保留候選記 unverified。
func TestWinRMExecutorThroughRunner(t *testing.T) {
	setup := func(t *testing.T) (*csFixture, *fakeWinRMServer, uint) {
		t.Helper()
		f := newFakeWinRMServer(t, "winoldpass")
		host, port := f.hostPort()
		fx := setupChangeSecretFixture(t, "root", "oldpass123")
		id := fx.addRotationAsset(t, &CreateAssetRequest{
			Name: "win-real", Protocol: model.ProtocolRDP, Host: host, Port: 3389,
			Username: "Administrator", Password: "winoldpass",
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: model.WinrmSchemeHTTP, WinrmPort: port,
		})
		fx.runner.executors = func(string) rotationExecutor { return testWinRMExecutor(f, nil) }
		return fx, f, id
	}
	storedPassword := func(t *testing.T, fx *csFixture, assetID uint) string {
		t.Helper()
		var acct model.AssetAccount
		require.NoError(t, fx.db.Where("asset_id = ?", assetID).First(&acct).Error)
		creds, err := fx.assets.GetWithCredentialsForAccount(assetID, acct.ID)
		require.NoError(t, err)
		return creds.Password
	}

	t.Run("成功", func(t *testing.T) {
		fx, f, id := setup(t)
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretSuccess, records[0].Status, "錯誤: %s", records[0].Error)
		assert.EqualValues(t, 0, fx.candidateCount(t))
		newPassword := storedPassword(t, fx, id)
		assert.NotEqual(t, "winoldpass", newPassword, "本地憑證應已提交為新密碼")
		assert.Equal(t, newPassword, f.snapshot().password, "端點的密碼與本地提交的一致")
		assert.NotContains(t, records[0].Error, newPassword)
	})

	t.Run("exit 3 乾淨失敗", func(t *testing.T) {
		fx, f, id := setup(t)
		f.set(func(f *fakeWinRMServer) { f.exitCode = 3 })
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretFailed, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, records[0].Error)
		assert.EqualValues(t, 0, fx.candidateCount(t), "遠端確定未變更 ⇒ 候選清除")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id), "本地憑證不動")
	})

	t.Run("斷線 unverified", func(t *testing.T) {
		fx, f, id := setup(t)
		f.set(func(f *fakeWinRMServer) { f.dropOnReceive = true })
		records := fx.runner.RunPlan(fx.planForAssets(t, []uint{id}, nil))
		require.Len(t, records, 1)
		assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
		assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, records[0].Error)
		assert.EqualValues(t, 1, fx.candidateCount(t), "狀態不可知 ⇒ 候選保留")
		assert.Equal(t, "winoldpass", storedPassword(t, fx, id))
	})
}
