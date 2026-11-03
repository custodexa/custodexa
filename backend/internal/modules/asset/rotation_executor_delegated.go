package asset

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshmaterial"
	"golang.org/x/crypto/ssh"
)

// rotationLogin 一次代改以誰登入目標機。
//
// 登入者與被改者分開：自改時兩者是同一個帳號，走 Rotate；以堡壘機專用帳號代改走
// delegatedRotationExecutor.RotateDelegated，被改者在 rotationTarget.username。
type rotationLogin struct {
	username string
	// password／privateKey 二擇一；呼叫端擁有並負責抹除
	password   []byte
	privateKey []byte
}

// delegatedRotationExecutor 支援以另一個帳號登入、替目標帳號改密的執行器。
//
// 以可選介面表達而非加寬 rotationExecutor：只有 posix_ssh 通道有這條路；其餘通道的執行器
// 不實作它，呼叫端以型別斷言判定，缺席時乾淨失敗而不退回自改。
type delegatedRotationExecutor interface {
	// RotateDelegated 以 login 登入，替 t.username 把秘密換成 newSecret。
	// 回傳實際採用的執行方式（model.ChangeSecretExecution*）；撥號或送指令之前就失敗時
	// 回依登入者設定預期的方式。
	RotateDelegated(ctx context.Context, t rotationTarget, login rotationLogin, newSecret []byte) (string, error)
}

// 代改的提權指令。不經 sh -c：目標機只需允許專用帳號以 root 執行改密程式一條規則。
const (
	elevatedCmdRoot       = "chpasswd"
	elevatedCmdSudoNoPass = "env LC_ALL=C sudo -n chpasswd"
	elevatedCmdSudoPass   = "sudo -k -S -p '' chpasswd"
	// sudoPasswordRequiredMarker sudo -n 在需要密碼時的訊息片段（LC_ALL=C 下）；比對只用於選路，
	// stderr 全文不進記錄
	sudoPasswordRequiredMarker = "password is required"
)

// expectedExecutionMethod 依登入者設定預期的執行方式（尚未送出指令時記錄用）。
func expectedExecutionMethod(login rotationLogin) string {
	switch {
	case login.username == "root":
		return model.ChangeSecretExecutionExecutorRoot
	case len(login.privateKey) > 0:
		return model.ChangeSecretExecutionExecutorSudoNopasswd
	default:
		return model.ChangeSecretExecutionExecutorSudoPassword
	}
}

// RotateDelegated 以專用帳號登入並替目標帳號改密（見 delegatedRotationExecutor）。
//
// 每一段改密指令的 stdin 至多一列「帳號:新密碼」，所以任何非零退出都代表目標沒變，
// 一律歸「遠端確定未變更」；連線中斷或逾時才是不可知。
func (posixSSHExecutor) RotateDelegated(ctx context.Context, t rotationTarget, login rotationLogin, newSecret []byte) (string, error) {
	method := expectedExecutionMethod(login)
	// 專用帳號一側的縱深檢查（正常流程在取密時已擋下）
	if strings.ContainsAny(login.username, "\n\r\x00:") || bytes.ContainsAny(login.password, "\n\r\x00") {
		return method, &localPreconditionError{reason: model.ChangeSecretReasonExecutorUnavailable}
	}
	var (
		client *ssh.Client
		err    error
	)
	if len(login.privateKey) > 0 {
		client, err = dialSSHPrivateKey(ctx, t.addr, login.username, login.privateKey, t.hostKeyCB)
	} else {
		client, err = dialSSHPassword(ctx, t.addr, login.username, sshmaterial.CopyPassword(login.password), t.hostKeyCB)
	}
	if err != nil {
		reason := oldCredentialLoginReason(err)
		if reason == model.ChangeSecretReasonOldCredentialLoginFailed {
			reason = model.ChangeSecretReasonExecutorLoginFailed
		}
		return method, &remoteRejectedError{reason: reason, cause: err}
	}
	defer client.Close()
	method, err = runElevatedChpasswd(client, login, t.username, newSecret, true)
	if err != nil {
		return method, classifyElevatedError(err, model.ChangeSecretReasonExecutorCommandRejected)
	}
	return method, nil
}

// classifyElevatedError 本地前置失敗原樣上拋；指令非零退出＝遠端確定未變更；其餘（中斷、逾時）不可知。
func classifyElevatedError(err error, rejectedReason string) error {
	var localErr *localPreconditionError
	if errors.As(err, &localErr) {
		return err
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return &remoteRejectedError{reason: rejectedReason, cause: err}
	}
	return err
}

// runElevatedChpasswd 在已認證的連線上以不經殼層的指令改 targetUser 的密碼。
//
// 提權由登入者決定：root 直接 chpasswd；非 root 先 `sudo -n`（stdin 只有一列），
// 回報需要密碼且允許密碼段時才在同一條連線上開第二個 session 以 `sudo -k -S` 送登入者密碼。
// 秘密一律走 stdin，命令列不含任何秘密。回傳實際採用的方式。
func runElevatedChpasswd(client *ssh.Client, login rotationLogin, targetUser string, newPassword []byte, allowPasswordStage bool) (string, error) {
	if strings.ContainsAny(targetUser, "\n\r\x00:") {
		return "", &localPreconditionError{reason: model.ChangeSecretReasonInvalidAccountName}
	}
	if bytes.ContainsAny(newPassword, "\n\r\x00") {
		return "", &localPreconditionError{reason: model.ChangeSecretReasonInvalidNewSecret}
	}
	entry := func() []byte { return elevatedEntry(targetUser, newPassword) }

	// 每一段的 stderr 都同時遮新密碼與登入者密碼：以密碼認證時目標機已收到登入者密碼，可回吐到任何一段
	if login.username == "root" {
		_, err := runElevatedSession(client, elevatedCmdRoot, entry(), newPassword, login.password)
		return model.ChangeSecretExecutionExecutorRoot, err
	}
	stderr, err := runElevatedSession(client, elevatedCmdSudoNoPass, entry(), newPassword, login.password)
	if err == nil {
		return model.ChangeSecretExecutionExecutorSudoNopasswd, nil
	}
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) || !allowPasswordStage || len(login.password) == 0 ||
		!strings.Contains(stderr, sudoPasswordRequiredMarker) {
		return model.ChangeSecretExecutionExecutorSudoNopasswd, err
	}
	// 第二段：登入者密碼一列，再接目標一列
	stdin := make([]byte, 0, len(login.password)+1+len(targetUser)+1+len(newPassword)+1)
	stdin = append(stdin, login.password...)
	stdin = append(stdin, '\n')
	stdin = append(stdin, entry()...)
	_, err = runElevatedSession(client, elevatedCmdSudoPass, stdin, newPassword, login.password)
	return model.ChangeSecretExecutionExecutorSudoPassword, err
}

// elevatedEntry 「帳號:新密碼\n」一列。
func elevatedEntry(user string, password []byte) []byte {
	out := make([]byte, 0, len(user)+1+len(password)+1)
	out = append(out, user...)
	out = append(out, ':')
	out = append(out, password...)
	return append(out, '\n')
}

// runElevatedSession 開一個 session 執行 cmd，stdin 用完即抹除。回傳 stderr（只供選路與 log，不落庫）。
//
// 目標機可能把收到的 stdin 回吐到 stderr；stderr 在離開本函式前先把 secrets 的每個出現處換成固定字樣，
// 新密碼與專用帳號密碼因此不會經錯誤訊息進入伺服器日誌。
func runElevatedSession(client *ssh.Client, cmd string, stdin []byte, secrets ...[]byte) (string, error) {
	defer material.Wipe(stdin)
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	input := newSecretInput(stdin)
	defer input.Close()
	sess.Stdin = input
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(cmd); err != nil {
		msg := strings.TrimSpace(redactSecrets(stderr.String(), secrets...))
		stderr.Reset()
		if msg != "" {
			return msg, &elevatedExitError{msg: sanitizeRemoteMessage(msg), err: err}
		}
		return "", err
	}
	return "", nil
}

// redactedMarker 遠端回吐內容中秘密的替代字樣。
const redactedMarker = "[redacted]"

// redactSecrets 把 msg 中每個非空 secret 的出現處換成 redactedMarker。
func redactSecrets(msg string, secrets ...[]byte) string {
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		msg = strings.ReplaceAll(msg, string(s), redactedMarker)
	}
	return msg
}

// elevatedExitError 保留 *ssh.ExitError 型別供分流，附上已截短的遠端訊息（只進後端 log）。
type elevatedExitError struct {
	msg string
	err error
}

func (e *elevatedExitError) Error() string { return e.msg + ": " + e.err.Error() }
func (e *elevatedExitError) Unwrap() error { return e.err }
