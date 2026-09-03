package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// windowsWinRMExecutor 經 WinRM（NTLM、訊息層加密）對 Windows 本機帳號改密。
//
// Rotate 以舊密碼建工作階段執行改密腳本（密碼走標準輸入）；Verify 以新密碼另建
// 工作階段跑無副作用指令。兩者的傳輸不變式（加密、逾時、序列化）都在
// winrm_transport.go／winrm_session.go，本型別只負責把結果翻成狀態機認得的三態。
type windowsWinRMExecutor struct {
	newSecurity    winrmSecurityFactory
	verifyDelays   []time.Duration
	sleep          func(context.Context, time.Duration) error
	dialTimeout    time.Duration
	commandTimeout time.Duration
}

// newWindowsWinRMExecutor 正式組態：NTLM、固定重試序列、真實逾時。
func newWindowsWinRMExecutor() windowsWinRMExecutor {
	return windowsWinRMExecutor{
		newSecurity:    newWinRMNTLMSecurity,
		verifyDelays:   windowsVerifyDelays(),
		sleep:          sleepContext,
		dialTimeout:    winrmDialTimeout,
		commandTimeout: winrmCommandTimeout,
	}
}

// windowsVerifyDelays 驗證重試的固定序列：立即、2 秒後、再 5 秒後，共三次。
//
// 真機實測改密後第一次重連即成功，序列是為了吸收帳號剛變更時的認證抖動；
// 序列用盡仍失敗交回呼叫端記為 unverified（候選保留，重試執行器接手）。
// 用函式而非包級變數：常數表沒有初始化順序語義，不該進 lifecycle 登記。
func windowsVerifyDelays() []time.Duration {
	return []time.Duration{0, 2 * time.Second, 5 * time.Second}
}

// sleepContext 可被 context 取消的等待。
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Rotate 改密。本地驗證 → 舊密碼建工作階段 → 腳本＋標準輸入 → 依結果標記與退出碼分流。
func (e windowsWinRMExecutor) Rotate(ctx context.Context, t rotationTarget, oldSecret, newSecret string) error {
	if err := validateWindowsAccountName(t.username); err != nil {
		return err
	}
	if err := validateWindowsNewSecret(newSecret); err != nil {
		return err
	}
	if err := validateWindowsOldSecret(oldSecret); err != nil {
		return err
	}
	session, err := newWinRMSession(ctx, t.asset, t.username, oldSecret, e.newSecurity, e.dialTimeout)
	if err != nil {
		// 通道設定在儲存時已驗過，這裡失敗代表設定與現況不符；未接觸遠端
		return &localPreconditionError{reason: model.ChangeSecretReasonChannelNotConfigured, cause: err}
	}
	out := session.run(buildWindowsCommand(windowsRotationScript), windowsRotationStdin(newSecret, oldSecret, t.username), e.dialTimeout, e.commandTimeout)
	if out.err != nil {
		return classifyWinRMRotateError(out.err)
	}
	return classifyWindowsOutcome(windowsLogSubject(t), out.exitCode, out.stdout, out.stderr)
}

// classifyWinRMRotateError 傳輸錯誤的分流。
//
// 唯一的分流依據是「指令是否已送出」。建立 shell 階段的失敗（winrmDialError）
// 一律是指令送出前：遠端確定未變更，記為確定失敗並清候選。其中加密不可用與憑證被拒
// 各有原因碼；其餘（連線被拒或未回應、撥號逾時、TLS 憑證驗證失敗、目標未提供可用的
// 交握）歸為「無法建立工作階段」。指令送出後的任何錯誤（中斷、指令逾時）一律狀態不可知。
// 與 POSIX 執行器同框架：舊憑證登入階段的任何失敗都是確定失敗。
func classifyWinRMRotateError(err error) error {
	var dialErr *winrmDialError
	if !errors.As(err, &dialErr) {
		return err
	}
	switch {
	case errors.Is(err, errWinRMEncryptionUnavailable):
		return &remoteRejectedError{reason: model.ChangeSecretReasonWinRMEncryptionUnavailable, cause: err}
	case errors.Is(err, errWinRMAuthFailed):
		return &remoteRejectedError{reason: model.ChangeSecretReasonOldCredentialLoginFailed, cause: err}
	}
	return &remoteRejectedError{reason: model.ChangeSecretReasonRemoteUnreachable, cause: err}
}

// Verify 以新密碼另建工作階段跑驗證指令，依固定序列重試。
func (e windowsWinRMExecutor) Verify(ctx context.Context, t rotationTarget, newSecret string) error {
	var last error
	for _, delay := range e.verifyDelays {
		if delay > 0 {
			if err := e.sleep(ctx, delay); err != nil {
				return err
			}
		}
		session, err := newWinRMSession(ctx, t.asset, t.username, newSecret, e.newSecurity, e.dialTimeout)
		if err != nil {
			return err
		}
		out := session.run(buildWindowsCommand(windowsVerifyScript), "", e.dialTimeout, e.commandTimeout)
		switch {
		case out.err != nil:
			last = out.err
		case out.exitCode != 0:
			last = fmt.Errorf("winrm: verify exit %d", out.exitCode)
		default:
			return nil
		}
	}
	return last
}
