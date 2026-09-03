package asset

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
)

// windowsSSHExecutor 經 SSH 到 Windows OpenSSH、以 PowerShell 對本機帳號改密。
//
// 撥號、host key 驗證（TOFU）與標準輸入投遞沿 POSIX 執行器的同一組函式；分家的
// 只有指令：顯式 `powershell.exe … -EncodedCommand`，不倚賴目標的預設 shell，
// 也沒有 chpasswd／sudo 之類的 POSIX 假設。rdp 資產的目標埠由 rotationAddr 取
// rotation_ssh_port（呼叫端已算進 t.addr）。
type windowsSSHExecutor struct {
	verifyDelays   []time.Duration
	sleep          func(context.Context, time.Duration) error
	commandTimeout time.Duration
}

// newWindowsSSHExecutor 正式組態：與 WinRM 同一組驗證重試序列、同一個指令逾時。
func newWindowsSSHExecutor() windowsSSHExecutor {
	return windowsSSHExecutor{verifyDelays: windowsVerifyDelays(), sleep: sleepContext, commandTimeout: windowsCommandTimeout}
}

// Rotate 本地驗證 → 舊密碼登入 → 腳本＋標準輸入 → 依結果標記與退出碼分流。
func (e windowsSSHExecutor) Rotate(_ context.Context, t rotationTarget, oldSecret, newSecret string) error {
	if err := validateWindowsAccountName(t.username); err != nil {
		return err
	}
	if err := validateWindowsNewSecret(newSecret); err != nil {
		return err
	}
	if err := validateWindowsOldSecret(oldSecret); err != nil {
		return err
	}
	client, err := dialSSHPassword(t.addr, t.username, oldSecret, t.hostKeyCB)
	if err != nil {
		return &remoteRejectedError{reason: model.ChangeSecretReasonOldCredentialLoginFailed, cause: err}
	}
	defer client.Close()

	// 指令跑完走結局分流（標準輸出的結果標記為主、退出碼為輔）；其餘（連線中斷、指令逾時）狀態不可知
	stdout, stderr, err := runWindowsSSHCommand(client, buildWindowsCommand(windowsRotationScript), windowsRotationStdin(newSecret, oldSecret, t.username), e.commandTimeout)
	return classifyWindowsSSHRun(windowsLogSubject(t), stdout, stderr, err)
}

// Verify 以新密碼另建連線跑驗證指令，依固定序列重試。
func (e windowsSSHExecutor) Verify(ctx context.Context, t rotationTarget, newSecret string) error {
	var last error
	for _, delay := range e.verifyDelays {
		if delay > 0 {
			if err := e.sleep(ctx, delay); err != nil {
				return err
			}
		}
		last = e.verifyOnce(t, newSecret)
		if last == nil {
			return nil
		}
	}
	return last
}

func (e windowsSSHExecutor) verifyOnce(t rotationTarget, newSecret string) error {
	client, err := dialSSHPassword(t.addr, t.username, newSecret, t.hostKeyCB)
	if err != nil {
		return err
	}
	defer client.Close()
	_, _, err = runWindowsSSHCommand(client, buildWindowsCommand(windowsVerifyScript), "", e.commandTimeout)
	return err
}

// windowsSSHRunResult 一次 exec 會話跑完的結果，由跑指令的 goroutine 整包送回。
type windowsSSHRunResult struct {
	stdout string
	stderr string
	err    error
}

// runWindowsSSHCommand 開一個 exec 會話跑命令列；stdin 非空時經會話標準輸入投遞。
// 回傳 stdout（結果標記在此）、stderr（只供 cause 診斷）與 sess.Run 的原錯誤
// （保留 *ssh.ExitError 供分流）。兩個輸出都只保留前段，避免目標端灌爆記憶體。
//
// timeout 自指令送出起算：到期即關閉會話與整條連線（不再等目標，跑指令的 goroutine 隨之結束），
// 回帶遠端狀態不可知的錯誤——指令已送出，目標可能已改密。撥號逾時另在 dialSSHPassword。
func runWindowsSSHCommand(client *ssh.Client, command, stdin string, timeout time.Duration) (string, string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	sess.Stdout = limitedWriter{&stdout, winrmStdoutLimit}
	sess.Stderr = limitedWriter{&stderr, winrmStderrLimit}

	done := make(chan windowsSSHRunResult, 1)
	go func() {
		err := sess.Run(command)
		// Run 回來時輸出的複製 goroutine 已收尾，此處讀緩衝區不與它們競爭
		done <- windowsSSHRunResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.stdout, r.stderr, r.err
	case <-timer.C:
		// 關會話與連線讓 Run 立即返回；緩衝區此後仍可能被寫入，不讀
		_ = sess.Close()
		_ = client.Close()
		return "", "", &remoteStateUnknownError{
			reason: model.ChangeSecretReasonRemoteStateUnknown,
			cause:  fmt.Errorf("windows ssh: command timed out after %s", timeout),
		}
	}
}
