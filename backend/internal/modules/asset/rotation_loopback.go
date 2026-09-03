//go:build loopback

package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
)

// 真機回歸入口（build tag loopback）。
//
// 正式建置不帶此 tag，本檔的符號在出貨二進位中不存在。它只做一件事：把 cmd/rotation-loopback
// 的目標描述翻成 rotationTarget，交給**正式的**執行器工廠，再把錯誤翻成狀態機的三態——
// 與 change_secret_runner 對 Rotate／Verify 回傳值的分流逐字同義。回傳結構上沒有秘密欄位。

// LoopbackTarget 一次真機回歸的目標：對應資產的改密通道欄位，host 由呼叫端給。
type LoopbackTarget struct {
	Host     string
	Channel  string
	Username string
	// WinRM 通道
	Scheme  string
	Port    int
	TLSMode string
	CACert  string
	// SSH 通道
	SSHPort int
}

// LoopbackOutcome 一次操作的結果。Class 為 success／failed／unverified，
// Reason 為 model 的改密原因碼（success 時為空）。
type LoopbackOutcome struct {
	Class     string `json:"class"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

const (
	LoopbackSuccess    = "success"
	LoopbackFailed     = "failed"
	LoopbackUnverified = "unverified"
)

// LoopbackRotate 以正式執行器對目標改密，分流同狀態機。
func LoopbackRotate(ctx context.Context, t LoopbackTarget, oldSecret, newSecret string) LoopbackOutcome {
	start := time.Now()
	err := rotationExecutorFor(t.Channel).Rotate(ctx, t.rotationTarget(), oldSecret, newSecret)
	return loopbackRotateOutcome(err, start)
}

// LoopbackVerify 以正式執行器對目標驗證憑證。驗證失敗在狀態機裡恆為 unverified。
func LoopbackVerify(ctx context.Context, t LoopbackTarget, secret string) LoopbackOutcome {
	start := time.Now()
	err := rotationExecutorFor(t.Channel).Verify(ctx, t.rotationTarget(), secret)
	if err != nil {
		return LoopbackOutcome{Class: LoopbackUnverified, Reason: model.ChangeSecretReasonVerifyFailed,
			Error: err.Error(), ElapsedMS: time.Since(start).Milliseconds()}
	}
	return LoopbackOutcome{Class: LoopbackSuccess, ElapsedMS: time.Since(start).Milliseconds()}
}

// LoopbackRotateWithoutStdin 正式改密腳本、正式工作階段（或連線），但標準輸入刻意為空；兩通道皆可。
//
// 執行器 API 表達不了這種故障（Rotate 一定投遞兩行密碼），只能在工作階段層注入。
// 期望結果是腳本契約的結局碼 3 → STDIN_NOT_DELIVERED，而不是靜默成功。
// commandTimeout 為 0 時用正式值（兩通道皆適用）。
func LoopbackRotateWithoutStdin(ctx context.Context, t LoopbackTarget, secret string,
	commandTimeout time.Duration) LoopbackOutcome {
	return loopbackRunScript(ctx, t, secret, windowsRotationScript, "", commandTimeout, loopbackRotationClassifier(t))
}

// LoopbackWinRMScript 在正式的 WinRM 工作階段上跑呼叫端給的腳本（無標準輸入）並依退出碼分流。
//
// 供「指令執行中連線被切斷」這類故障：命令列組裝、傳輸、逾時與退出碼分流都是正式碼，
// 只有腳本內容由呼叫端給。commandTimeout 為 0 時用正式值。
func LoopbackWinRMScript(ctx context.Context, t LoopbackTarget, secret, script string,
	commandTimeout time.Duration) LoopbackOutcome {
	return loopbackRunScript(ctx, t, secret, script, "", commandTimeout, loopbackExitOnlyClassifier)
}

// LoopbackVerifyOnce 以指定密碼**單次**登入（不走驗證重試序列，避免累積失敗登入次數）。
//
// 登入被拒回 failed／OLD_CREDENTIAL_LOGIN_FAILED（與兩執行器對舊憑證登入階段的分流同義），
// 其餘錯誤照 Rotate 的分流；成功回 success。供回歸斷言「某個密碼此刻能不能登入」。
func LoopbackVerifyOnce(ctx context.Context, t LoopbackTarget, secret string) LoopbackOutcome {
	return loopbackRunScript(ctx, t, secret, windowsVerifyScript, "", 0, loopbackExitOnlyClassifier)
}

// loopbackExitOnlyClassifier 非改密腳本（驗證指令、呼叫端自帶的腳本）沒有結果標記，只看退出碼。
func loopbackExitOnlyClassifier(exitCode int, _ string, stderr string) error {
	return classifyWindowsExit(exitCode, stderr)
}

// LoopbackRotateSelfVerifyFailure 正式改密腳本、正式工作階段與兩行標準輸入，
// 只把腳本的目標端自驗那一句換成「不通過」，逼出回滾路徑。
//
// 正式碼沒有這個開關：取代發生在本檔（回歸專用建置），找不到那一句即回失敗而非跑別的腳本。
// 期望結局是結局碼 4 → failed／REMOTE_SELF_VERIFY_FAILED，且目標仍是舊密碼。
func LoopbackRotateSelfVerifyFailure(ctx context.Context, t LoopbackTarget, oldSecret, newSecret string) LoopbackOutcome {
	script, err := loopbackReplaceStatement(windowsSelfVerifyStatement, "$ok = $false")
	if err != nil {
		return LoopbackOutcome{Class: LoopbackFailed, Error: err.Error()}
	}
	return loopbackRotateInjected(ctx, t, oldSecret, newSecret, script, 0)
}

// LoopbackRotateValidatorUnavailable 正式改密腳本、正式工作階段與兩行標準輸入，
// 只把校準驗證器那一句換成「驗證器不可用」，逼出不自驗、不回滾的結局碼 6 路徑。
//
// 期望結局是我方的重連驗證通過 → success，且目標已是新密碼、舊密碼登入被拒。
// 這條路徑的分流若退化成確定失敗，候選會被清掉而目標已是新密碼——正是回歸要盯住的形態。
func LoopbackRotateValidatorUnavailable(ctx context.Context, t LoopbackTarget, oldSecret, newSecret string) LoopbackOutcome {
	script, err := loopbackReplaceStatement(windowsCalibrateStatement, "$v = $null")
	if err != nil {
		return LoopbackOutcome{Class: LoopbackFailed, Error: err.Error()}
	}
	return loopbackRotateInjected(ctx, t, oldSecret, newSecret, script, 0)
}

// LoopbackRotateCommandHang 正式改密腳本、正式工作階段（或連線）與兩行標準輸入，只把校準驗證器
// 那一句換成長時間停住，逼出「指令已送出、逾時前未回報完成」的路徑。
//
// 期望結局是 unverified／REMOTE_STATE_UNKNOWN（候選保留），且目標仍是舊密碼、新密碼登入被拒。
// 停住的那一句之後腳本以結局碼 3 結束而不觸碰帳號：子行程是否隨會話關閉而終止沒有可靠保證，
// 靶機的密碼不得取決於它。commandTimeout 為 0 時用正式值（90 秒）；回歸通常縮短它以省時間。
func LoopbackRotateCommandHang(ctx context.Context, t LoopbackTarget, oldSecret, newSecret string,
	commandTimeout time.Duration) LoopbackOutcome {
	script, err := loopbackReplaceStatement(windowsCalibrateStatement, "Start-Sleep -Seconds 900; Write-Result 3; exit 3")
	if err != nil {
		return LoopbackOutcome{Class: LoopbackFailed, Error: err.Error()}
	}
	return loopbackRotateInjected(ctx, t, oldSecret, newSecret, script, commandTimeout)
}

// loopbackRotateInjected 以注入後的腳本走正式的本地驗證、工作階段、兩行標準輸入與結局分流。
// commandTimeout 為 0 時用正式值。
func loopbackRotateInjected(ctx context.Context, t LoopbackTarget, oldSecret, newSecret, script string,
	commandTimeout time.Duration) LoopbackOutcome {
	start := time.Now()
	if err := validateWindowsAccountName(t.Username); err != nil {
		return loopbackRotateOutcome(err, start)
	}
	if err := validateWindowsOldSecret(oldSecret); err != nil {
		return loopbackRotateOutcome(err, start)
	}
	return loopbackRunScript(ctx, t, oldSecret, script, windowsRotationStdin(newSecret, oldSecret, t.Username), commandTimeout, loopbackRotationClassifier(t))
}

// loopbackReplaceStatement 正式腳本，把指定的那一句換成 replacement；
// 找不到或找到不只一次即回錯，不會靜默跑到別的腳本。
func loopbackReplaceStatement(statement, replacement string) (string, error) {
	if strings.Count(windowsRotationScript, statement) != 1 {
		return "", fmt.Errorf("loopback: statement not found exactly once in the rotation script; the script contract changed")
	}
	return strings.Replace(windowsRotationScript, statement, replacement, 1), nil
}

// loopbackRotationClassifier 正式的改密結局分流（結果標記為主、退出碼為輔），綁定目標的 log 識別。
func loopbackRotationClassifier(t LoopbackTarget) func(int, string, string) error {
	subject := windowsLogSubject(t.rotationTarget())
	return func(exitCode int, stdout, stderr string) error {
		return classifyWindowsOutcome(subject, exitCode, stdout, stderr)
	}
}

// loopbackRunScript 以 secret 建正式的 WinRM 工作階段或 SSH 連線，跑 script（stdin 可空），
// 指令跑完交 classify 分流、傳輸失敗照正式分流；回三態。commandTimeout 為 0 時用正式值（兩通道同值）。
func loopbackRunScript(ctx context.Context, t LoopbackTarget, secret, script, stdin string,
	commandTimeout time.Duration, classify func(int, string, string) error) LoopbackOutcome {
	start := time.Now()
	if commandTimeout <= 0 {
		commandTimeout = windowsCommandTimeout
	}
	rt := t.rotationTarget()
	if t.Channel == model.RotationChannelWindowsWinRM {
		session, err := newWinRMSession(ctx, rt.asset, rt.username, secret, newWinRMNTLMSecurity, winrmDialTimeout)
		if err != nil {
			return loopbackRotateOutcome(&localPreconditionError{reason: model.ChangeSecretReasonChannelNotConfigured, cause: err}, start)
		}
		out := session.run(buildWindowsCommand(script), stdin, winrmDialTimeout, commandTimeout)
		if out.err != nil {
			return loopbackRotateOutcome(classifyWinRMRotateError(out.err), start)
		}
		return loopbackRotateOutcome(classify(out.exitCode, out.stdout, out.stderr), start)
	}
	client, err := dialSSHPassword(rt.addr, rt.username, secret, rt.hostKeyCB)
	if err != nil {
		return loopbackRotateOutcome(&remoteRejectedError{reason: model.ChangeSecretReasonOldCredentialLoginFailed, cause: err}, start)
	}
	defer client.Close()
	stdout, stderr, err := runWindowsSSHCommand(client, buildWindowsCommand(script), stdin, commandTimeout)
	exitCode, finished := windowsSSHExitCode(err)
	if !finished {
		return loopbackRotateOutcome(err, start)
	}
	return loopbackRotateOutcome(classify(exitCode, stdout, stderr), start)
}

// loopbackRotateOutcome Rotate 錯誤 → 三態，與 change_secret_runner 的分流同義。
func loopbackRotateOutcome(err error, start time.Time) LoopbackOutcome {
	elapsed := time.Since(start).Milliseconds()
	if err == nil {
		return LoopbackOutcome{Class: LoopbackSuccess, ElapsedMS: elapsed}
	}
	var localErr *localPreconditionError
	if errors.As(err, &localErr) {
		return LoopbackOutcome{Class: LoopbackFailed, Reason: localErr.reason, Error: err.Error(), ElapsedMS: elapsed}
	}
	var rejected *remoteRejectedError
	if errors.As(err, &rejected) {
		return LoopbackOutcome{Class: LoopbackFailed, Reason: rejected.reason, Error: err.Error(), ElapsedMS: elapsed}
	}
	var unknown *remoteStateUnknownError
	if errors.As(err, &unknown) {
		return LoopbackOutcome{Class: LoopbackUnverified, Reason: unknown.reason, Error: err.Error(), ElapsedMS: elapsed}
	}
	return LoopbackOutcome{Class: LoopbackUnverified, Reason: model.ChangeSecretReasonRemoteStateUnknown,
		Error: err.Error(), ElapsedMS: elapsed}
}

func (t LoopbackTarget) asset() *model.Asset {
	return &model.Asset{
		Host:            t.Host,
		Protocol:        model.ProtocolRDP,
		RotationChannel: t.Channel,
		WinrmScheme:     t.Scheme,
		WinrmPort:       t.Port,
		WinrmTLSMode:    t.TLSMode,
		WinrmCACert:     t.CACert,
		RotationSSHPort: t.SSHPort,
	}
}

func (t LoopbackTarget) rotationTarget() rotationTarget {
	a := t.asset()
	rt := rotationTarget{asset: a, channel: t.Channel, username: t.Username, secretType: model.ChangeSecretTypePassword}
	if t.Channel == model.RotationChannelWindowsSSH {
		rt.addr = rotationAddr(a, t.Channel)
		// 回歸靶機是同一台機器上臨時啟用的 sshd，host key 每次執行都不同；
		// 正式路徑的 TOFU 回呼由呼叫端（資產的 host key 記錄）提供，本入口不碰那條路。
		rt.hostKeyCB = ssh.InsecureIgnoreHostKey() //nolint:gosec // 只在 loopback 建置存在
	}
	return rt
}
