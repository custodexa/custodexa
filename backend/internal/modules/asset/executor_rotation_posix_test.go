package asset

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/custodexa/backend/internal/model"
)

// 以堡壘機專用帳號代改 POSIX 帳號密碼：登入者與被改者分開、三種提權、失敗不退回自改。
// 全部以行程內多帳號 SSH 靶機實跑真連線（executor_fake_ssh_test.go）。

const (
	delegTargetUser     = "app"
	delegStoredOldPW    = "stored-old-pw"
	delegServerOldPW    = "server-side-old-pw" // 與憑證庫不同：代改不需要舊密碼正確
	delegExecutorUser   = "cx-exec"
	delegExecutorSecret = "Exec-Secret-9"
)

type delegEnv struct {
	*csFixture
	srv *execSSHServer
	svc *AssetExecutorService
}

// newDelegEnv 一台 ssh 資產（登入帳號 app，憑證庫密碼 delegStoredOldPW）指向多帳號靶機；
// 靶機上 app 的真實密碼是 delegServerOldPW。
func newDelegEnv(t *testing.T) *delegEnv {
	t.Helper()
	f := setupChangeSecretFixture(t, delegTargetUser, delegStoredOldPW)
	srv := newExecSSHServer(t)
	srv.addAccount(delegTargetUser, delegServerOldPW, fakeSudoNone)
	host, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	require.NoError(t, f.db.Model(&model.Asset{}).Where("id = ?", f.assetID).
		Updates(map[string]any{"host": host, "port": port, "rotation_channel": model.RotationChannelPosixSSH}).Error)
	ef := newExecutorFixture(t, f.db)
	return &delegEnv{csFixture: f, srv: srv, svc: ef.exec}
}

func (e *delegEnv) setExecutor(t *testing.T, username, password, privateKey string) {
	t.Helper()
	_, err := e.svc.Set(WithSystemCaller(context.Background()), e.assetID, &SetExecutorRequest{
		Source: ExecutorSourceInline, Username: username, Password: password, PrivateKey: privateKey,
		ExpectedAccountID: uptr(0),
	})
	require.NoError(t, err)
}

func (e *delegEnv) runOne(t *testing.T) model.ChangeSecretRecord {
	t.Helper()
	records := e.runner.RunPlan(e.plan(t, nil))
	require.Len(t, records, 1)
	return records[0]
}

// assertSelfNeverTried 以目標帳號＋憑證庫舊密碼的認證嘗試為零（代改不退回自改）。
func (e *delegEnv) assertSelfNeverTried(t *testing.T) {
	t.Helper()
	assert.Zero(t, e.srv.attemptsAs(delegTargetUser, delegStoredOldPW), "不得以目標帳號的憑證庫舊密碼登入")
	assert.Zero(t, e.srv.attemptsAs(delegTargetUser, delegServerOldPW), "不得以目標帳號的舊密碼登入")
}

func TestDelegatedRotationThreeModes(t *testing.T) {
	cases := []struct {
		name       string
		username   string
		sudo       string
		wantMethod string
		wantCmd    string
	}{
		{"root", "root", fakeSudoNone, model.ChangeSecretExecutionExecutorRoot, elevatedCmdRoot},
		{"sudo_nopasswd", delegExecutorUser, fakeSudoNopasswd, model.ChangeSecretExecutionExecutorSudoNopasswd, elevatedCmdSudoNoPass},
		{"sudo_password", delegExecutorUser, fakeSudoPassword, model.ChangeSecretExecutionExecutorSudoPassword, elevatedCmdSudoPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDelegEnv(t)
			e.srv.addAccount(c.username, delegExecutorSecret, c.sudo)
			e.setExecutor(t, c.username, delegExecutorSecret, "")

			rec := e.runOne(t)
			require.Equal(t, model.ChangeSecretSuccess, rec.Status, "error=%s", rec.Error)
			assert.Equal(t, c.wantMethod, rec.ExecutionMethod)
			assert.Equal(t, c.username, rec.ExecutorUsername)
			assert.NotZero(t, rec.ExecutorAccountID)
			assert.NotZero(t, rec.ExecutorCredentialID)
			e.assertSelfNeverTried(t)
			assert.Equal(t, 1, e.srv.attemptsAs(delegTargetUser, ""), "目標帳號只有成功後的驗證登入一次")

			newPW := e.srv.passwordOf(delegTargetUser)
			assert.NotEqual(t, delegServerOldPW, newPW, "靶機上目標帳號密碼已換")
			assert.Equal(t, newPW, e.storedPassword(t), "提交後憑證庫就位新密碼")
			assert.EqualValues(t, 0, e.candidateCount(t))

			// 指令與 stdin 形狀：命令列不含任何秘密；最後一個改密 session 的指令為預期值
			var last fakeSession
			for _, s := range e.srv.execSessions() {
				assert.NotContains(t, s.cmd, newPW)
				assert.NotContains(t, s.cmd, delegExecutorSecret)
				assert.Equal(t, c.username, s.user, "登入者是專用帳號")
				last = s
			}
			assert.Equal(t, c.wantCmd, last.cmd)
			if c.wantMethod != model.ChangeSecretExecutionExecutorSudoPassword {
				assert.NotContains(t, last.stdin, delegExecutorSecret, "非密碼段的 stdin 不含專用帳號密碼")
				assert.Equal(t, delegTargetUser+":"+newPW+"\n", last.stdin)
			} else {
				assert.Equal(t, delegExecutorSecret+"\n"+delegTargetUser+":"+newPW+"\n", last.stdin)
				first := e.srv.execSessions()[0]
				assert.Equal(t, elevatedCmdSudoNoPass, first.cmd, "先探測免密碼")
				assert.NotContains(t, first.stdin, delegExecutorSecret)
			}
			raw, err := json.Marshal(rec)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), newPW)
			assert.NotContains(t, string(raw), delegExecutorSecret)
		})
	}
}

func TestDelegatedRotationKeyExecutor(t *testing.T) {
	e := newDelegEnv(t)
	private, line := testKeyPair(t, "exec")
	acct := e.srv.addAccount(delegExecutorUser, "", fakeSudoNopasswd)
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	acct.key = pub
	e.setExecutor(t, delegExecutorUser, "", private)

	rec := e.runOne(t)
	require.Equal(t, model.ChangeSecretSuccess, rec.Status, "error=%s", rec.Error)
	assert.Equal(t, model.ChangeSecretExecutionExecutorSudoNopasswd, rec.ExecutionMethod)
	e.assertSelfNeverTried(t)
}

func TestDelegatedRotationKeyExecutorNeverSendsSecondStage(t *testing.T) {
	e := newDelegEnv(t)
	private, line := testKeyPair(t, "exec")
	acct := e.srv.addAccount(delegExecutorUser, "", fakeSudoPassword) // sudo 要密碼，金鑰型沒有密碼可送
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	acct.key = pub
	e.setExecutor(t, delegExecutorUser, "", private)

	rec := e.runOne(t)
	assert.Equal(t, model.ChangeSecretFailed, rec.Status)
	assert.Equal(t, model.ChangeSecretReasonExecutorCommandRejected, rec.Error)
	assert.Len(t, e.srv.execSessions(), 1, "金鑰型只有第一段")
	assert.EqualValues(t, 0, e.candidateCount(t))
}

// 代改失敗不退回自改：五種專用帳號一側的失敗，目標帳號舊密碼的認證嘗試恆為零。
func TestDelegatedRotationNeverFallsBackToSelf(t *testing.T) {
	t.Run("login_failed", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, "changed-on-host", fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorLoginFailed, rec.Error)
		e.assertSelfNeverTried(t)
		assert.EqualValues(t, 0, e.candidateCount(t))
		assert.Equal(t, delegExecutorUser, rec.ExecutorUsername, "失敗也記下是哪個專用帳號")
		assert.Equal(t, delegServerOldPW, e.srv.passwordOf(delegTargetUser))
	})
	t.Run("command_rejected_no_sudo", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNone)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorCommandRejected, rec.Error)
		sessions := e.srv.execSessions()
		require.Len(t, sessions, 2, "需要密碼：第一段探測、第二段送密碼")
		assert.Equal(t, elevatedCmdSudoPass, sessions[1].cmd)
		e.assertSelfNeverTried(t)
		assert.EqualValues(t, 0, e.candidateCount(t))
		assert.Zero(t, e.srv.attemptsAs(delegTargetUser, ""), "也沒有以新密碼的確認登入")
		assert.Equal(t, model.ChangeSecretExecutionExecutorSudoPassword, rec.ExecutionMethod)
	})
	t.Run("first_stage_fails_without_password_marker", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoBroken)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorCommandRejected, rec.Error)
		assert.Len(t, e.srv.execSessions(), 1, "stderr 不含需要密碼就不送第二段")
		e.assertSelfNeverTried(t)
	})
	t.Run("unavailable_no_secret", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		require.NoError(t, e.db.Model(&model.AssetAccount{}).
			Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).
			Update("effective_version_id", nil).Error)
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorUnavailable, rec.Error)
		assert.Empty(t, e.srv.authAttempts(), "遠端零接觸")
		assert.EqualValues(t, 0, e.candidateCount(t))
	})
	t.Run("unavailable_newline_password", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, "bad\npw", fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, "bad\npw", "")
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretFailed, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorUnavailable, rec.Error)
		assert.Empty(t, e.srv.authAttempts())
		assert.EqualValues(t, 0, e.candidateCount(t))
	})
	t.Run("rotation_pending_unverified_candidate", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		var mount model.AssetAccount
		require.NoError(t, e.db.Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeExecutor).First(&mount).Error)
		require.NoError(t, e.db.Create(&model.ChangeSecretCandidate{
			AccountID: mount.ID, AssetID: e.assetID, SecretType: model.ChangeSecretTypePassword,
		}).Error)
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
		assert.Equal(t, model.ChangeSecretReasonExecutorRotationPending, rec.Error)
		assert.Empty(t, e.srv.authAttempts())
	})
}

func TestDelegatedRotationPasswordExecutorWithNopasswdRule(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	rec := e.runOne(t)
	require.Equal(t, model.ChangeSecretSuccess, rec.Status)
	assert.Equal(t, model.ChangeSecretExecutionExecutorSudoNopasswd, rec.ExecutionMethod, "記實際採用的方式")
	for _, s := range e.srv.execSessions() {
		assert.NotContains(t, s.stdin, delegExecutorSecret)
	}
}

func TestDelegatedRotationSkipsTargetWithoutPasswordOrCredential(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	require.NoError(t, e.db.Model(&model.AssetAccount{}).
		Where("asset_id = ? AND purpose = ?", e.assetID, model.AccountPurposeLogin).
		Update("effective_version_id", nil).Error)
	rec := e.runOne(t)
	assert.Equal(t, model.ChangeSecretSkipped, rec.Status)
	assert.Equal(t, model.ChangeSecretReasonNoCredential, rec.Error)
	assert.Empty(t, e.srv.authAttempts(), "零連線")
	assert.Equal(t, delegExecutorUser, rec.ExecutorUsername, "記錄的專用帳號欄仍填入")
}

// 選路：金鑰輪替、沒有專用帳號的資產維持自改。
func TestDelegatedRotationRouting(t *testing.T) {
	t.Run("no_executor_is_self", func(t *testing.T) {
		e := newDelegEnv(t)
		rec := e.runOne(t)
		assert.Equal(t, model.ChangeSecretExecutionSelf, rec.ExecutionMethod)
		assert.Zero(t, rec.ExecutorAccountID)
		assert.Empty(t, rec.ExecutorUsername)
	})
	t.Run("key_rotation_is_self", func(t *testing.T) {
		e := newDelegEnv(t)
		e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoNopasswd)
		e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
		var targets []changeSecretTarget
		job := rotationJob{planID: 1, scope: model.AccountScope{model.AccountScopeAll}, secretType: model.ChangeSecretTypeSSHKey}
		targets, skip := e.runner.resolveTargets(job, e.assetID)
		require.Nil(t, skip)
		require.Len(t, targets, 1)
		assert.Nil(t, targets[0].executorPin, "金鑰輪替維持自改")
		job.secretType = model.ChangeSecretTypePassword
		targets, skip = e.runner.resolveTargets(job, e.assetID)
		require.Nil(t, skip)
		require.Len(t, targets, 1)
		require.NotNil(t, targets[0].executorPin, "密碼型改為代改")
		assert.Equal(t, delegExecutorUser, targets[0].executorPin.Username)
		assert.Equal(t, model.RotationChannelPosixSSH, targets[0].channel)
		for _, tg := range targets {
			assert.Equal(t, model.AccountPurposeLogin, e.purposeOf(t, tg.accountID), "專用帳號不出現在目標")
		}
	})
}

func (e *delegEnv) purposeOf(t *testing.T, accountID uint) string {
	t.Helper()
	var acc model.AssetAccount
	require.NoError(t, e.db.First(&acc, accountID).Error)
	return acc.Purpose
}

// 秘密不進記錄、候選、告警：靶機把 stdin 回吐 stderr 時，記錄列 JSON 仍不含任何秘密。
func TestDelegatedRotationEchoedStdinStaysOutOfRecords(t *testing.T) {
	e := newDelegEnv(t)
	e.srv.addAccount(delegExecutorUser, delegExecutorSecret, fakeSudoPassword)
	e.srv.echoStdin = true
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	rec := e.runOne(t)
	require.Equal(t, model.ChangeSecretSuccess, rec.Status)
	newPW := e.srv.passwordOf(delegTargetUser)
	var rows []model.ChangeSecretRecord
	require.NoError(t, e.db.Find(&rows).Error)
	raw, err := json.Marshal(rows)
	require.NoError(t, err)
	for _, secret := range []string{newPW, delegExecutorSecret} {
		assert.False(t, strings.Contains(string(raw), secret), "記錄列不得含秘密")
	}
}

// 取密途徑：釘住值比對、輪替中與未驗證候選、控制字元；且不放寬人員連線出口。
func TestResolveExecutorCredentials(t *testing.T) {
	e := newDelegEnv(t)
	e.setExecutor(t, delegExecutorUser, delegExecutorSecret, "")
	pin, err := readExecutorPin(e.db, e.assetID)
	require.NoError(t, err)
	require.NotNil(t, pin)
	assert.Equal(t, delegExecutorUser, pin.Username)
	assert.Equal(t, model.ChangeSecretTypePassword, pin.SecretType)

	t.Run("success", func(t *testing.T) {
		got, err := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, *pin)
		require.NoError(t, err)
		defer got.Destroy()
		assert.Equal(t, delegExecutorUser, got.Username)
		assert.Equal(t, delegExecutorSecret, secretText(t, got.Password))
	})
	t.Run("version_advanced_is_changed", func(t *testing.T) {
		stale := *pin
		stale.EffectiveVersionID = pin.EffectiveVersionID + 100
		_, err := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, stale)
		assert.ErrorIs(t, err, ErrExecutorChanged)
	})
	t.Run("other_mount_is_changed", func(t *testing.T) {
		stale := *pin
		stale.AccountID += 100
		_, err := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, stale)
		assert.ErrorIs(t, err, ErrExecutorChanged)
	})
	t.Run("connection_exits_do_not_release_executor", func(t *testing.T) {
		_, err := e.assets.GetWithCredentialsForAccount(e.assetID, pin.AccountID)
		assert.ErrorIs(t, err, ErrAssetAccountNotFound, "人員連線出口對專用帳號與不存在同形")
	})
	t.Run("active_rotation_is_busy", func(t *testing.T) {
		rid := uint(7)
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", pin.CredentialID).Update("active_rotation_id", rid).Error)
		_, err := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, *pin)
		assert.ErrorIs(t, err, ErrExecutorBusy)
		require.NoError(t, e.db.Model(&model.Credential{}).Where("id = ?", pin.CredentialID).Update("active_rotation_id", nil).Error)
	})
	t.Run("errors_never_carry_secret", func(t *testing.T) {
		stale := *pin
		stale.EffectiveVersionID = 0
		_, err := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, stale)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), delegExecutorSecret)
	})
	t.Run("username_with_colon_is_unavailable", func(t *testing.T) {
		require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("id = ?", pin.AccountID).Update("username", "a:b").Error)
		bad := *pin
		bad.Username = "a:b"
		_, err := e.assets.ResolveExecutorCredentials(context.Background(), e.assetID, bad)
		assert.ErrorIs(t, err, ErrExecutorUnavailable)
	})
}

// 執行身分自己的密碼型輪替：不經殼層的兩段式提權（登入者與被改者同一人）。
func TestExecutorOwnRotationUsesDirectCommand(t *testing.T) {
	srv := newExecSSHServer(t)
	srv.addAccount(delegExecutorUser, "own-old-pw", fakeSudoPassword)
	rt := directRotationTarget(t, srv, delegExecutorUser, true)
	require.NoError(t, posixSSHExecutor{}.Rotate(context.Background(), rt, []byte("own-old-pw"), []byte("own-new-pw")))
	sessions := srv.execSessions()
	require.Len(t, sessions, 2)
	assert.Equal(t, elevatedCmdSudoNoPass, sessions[0].cmd)
	assert.Equal(t, elevatedCmdSudoPass, sessions[1].cmd)
	assert.Equal(t, "own-old-pw\n"+delegExecutorUser+":own-new-pw\n", sessions[1].stdin)
	assert.Equal(t, "own-new-pw", srv.passwordOf(delegExecutorUser))
	for _, s := range sessions {
		assert.NotContains(t, s.cmd, "sh -c", "不要求殼層的 sudo 權")
	}

	// 登入帳號的自改指令不變
	srv2 := newExecSSHServer(t)
	srv2.addAccount("app", "app-old", fakeSudoNone)
	rt2 := directRotationTarget(t, srv2, "app", false)
	require.NoError(t, posixSSHExecutor{}.Rotate(context.Background(), rt2, []byte("app-old"), []byte("app-new")))
	require.Len(t, srv2.execSessions(), 1)
	assert.Equal(t, "sudo -S -p '' sh -c 'chpasswd'", srv2.execSessions()[0].cmd)
}

// directRotationTarget 直接對靶機的 posix 執行器用的目標（略過主機金鑰檢查）。
func directRotationTarget(t *testing.T, srv *execSSHServer, user string, direct bool) rotationTarget {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.addr())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return rotationTarget{
		asset: &model.Asset{Host: host, Port: port}, channel: model.RotationChannelPosixSSH,
		username: user, secretType: model.ChangeSecretTypePassword, addr: srv.addr(),
		hostKeyCB:     ssh.FixedHostKey(srv.hostKey.PublicKey()),
		directCommand: direct,
	}
}

// 代改的本地縱深檢查：專用帳號密碼含換行時不撥號。
func TestRotateDelegatedRejectsInjectionBeforeDialing(t *testing.T) {
	srv := newExecSSHServer(t)
	srv.addAccount(delegExecutorUser, "x", fakeSudoNopasswd)
	rt := directRotationTarget(t, srv, delegTargetUser, false)
	_, err := posixSSHExecutor{}.RotateDelegated(context.Background(), rt,
		rotationLogin{username: delegExecutorUser, password: []byte("bad\npw")}, []byte("new-pw"))
	var local *localPreconditionError
	require.ErrorAs(t, err, &local)
	assert.Equal(t, model.ChangeSecretReasonExecutorUnavailable, local.reason)
	assert.Empty(t, srv.authAttempts())

	_, err = posixSSHExecutor{}.RotateDelegated(context.Background(), rt,
		rotationLogin{username: delegExecutorUser, password: []byte("x")}, []byte("new\npw"))
	require.ErrorAs(t, err, &local)
	assert.Equal(t, model.ChangeSecretReasonInvalidNewSecret, local.reason)
	assert.Empty(t, srv.execSessions(), "新密碼含換行：不送任何指令")
}

// 不支援代改的執行器收到代改要求時乾淨失敗，不撥號。
func TestNonPosixExecutorsDoNotImplementDelegation(t *testing.T) {
	for _, ch := range []string{model.RotationChannelWindowsWinRM, model.RotationChannelWindowsSSH, model.RotationChannelDBNative} {
		_, ok := rotationExecutorFor(ch).(delegatedRotationExecutor)
		assert.False(t, ok, "通道 %s", ch)
	}
	_, ok := rotationExecutorFor(model.RotationChannelPosixSSH).(delegatedRotationExecutor)
	assert.True(t, ok)
}
