package asset

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshmaterial"
	"golang.org/x/crypto/ssh"
)

// 主機帳號盤點的遠端讀取。
//
// 每一項以同一條 SSH 連線上的獨立 session 執行一個常數指令：區段邊界與退出碼由
// SSH 協定回報，遠端內容無法偽造分段。指令字串是程式常數，不拼接任何請求、
// 資產、帳號或政策的文字；只讀不寫，不呼叫 sudo。
//
// 指令經目標帳號的登入殼層解譯後才進到 sh -c，因此每個指令單行、不含 `!`、
// 內層不用單引號（csh／tcsh 的歷史展開與引號規則）。

// inventorySessionID 讀取項代號（只用於結構化日誌，不含遠端內容）。
type inventorySessionID string

const (
	inventorySessionUID      inventorySessionID = "uid"
	inventorySessionAccounts inventorySessionID = "accounts"
	inventorySessionGroup    inventorySessionID = "group"
	inventorySessionSudo     inventorySessionID = "sudo"
)

// inventorySudoScript sudo 段：sudo 是否存在、主規則檔與規則目錄的讀取。
// 遠端可控的檔名與內容一律以 od -An -tx1 十六進位編碼，每列只含 [0-9a-z_ ]。
const inventorySudoScript = `p=0; command -v sudo >/dev/null 2>&1 && p=1; test -e /usr/local/etc/sudoers && p=1; echo "P $p"; ` +
	`if test -e /etc/sudoers; then if test -r /etc/sudoers; then printf "M ok "; od -An -tx1 /etc/sudoers | tr -d " \n"; echo; else echo "M unreadable"; fi; else echo "M absent"; fi; ` +
	`if test -d /etc/sudoers.d; then if test -r /etc/sudoers.d && test -x /etc/sudoers.d; then echo "D ok"; ` +
	`for x in /etc/sudoers.d/*; do test -f "$x" || continue; printf "F "; printf %s "${x#/etc/sudoers.d/}" | od -An -tx1 | tr -d " \n"; ` +
	`if test -r "$x"; then printf " ok "; od -An -tx1 "$x" | tr -d " \n"; echo; else echo " unreadable"; fi; done; ` +
	`else echo "D unreadable"; fi; else echo "D absent"; fi`

// inventoryCommands 四個常數指令（依執行順序）。
var inventoryCommands = []struct {
	ID  inventorySessionID
	Cmd string
}{
	{inventorySessionUID, `sh -c 'id -u'`},
	{inventorySessionAccounts, `sh -c 'getent passwd'`},
	{inventorySessionGroup, `sh -c 'getent group'`},
	{inventorySessionSudo, `sh -c '` + inventorySudoScript + `'`},
}

// 輸出上限（常數）。超過任一項即整筆以 INVENTORY_OUTPUT_LIMIT 結束，不寫部分結果。
const (
	inventoryMaxTotalBytes    = 16 << 20
	inventoryMaxAccountRows   = 100000
	inventoryMaxGroupRows     = 100000
	inventoryMaxLineBytes     = 1 << 20
	inventoryMaxSudoFiles     = 256
	inventoryMaxSudoBytes     = 2 << 20
	inventoryMaxAliasDepth    = 8
	inventoryMaxAccountNameSz = 256
)

// inventoryError 盤點失敗的分類：Reason 為結束原因碼；Detail 只含結構化診斷
// （讀取項、退出碼、列號），不含任何遠端原文。
type inventoryError struct {
	Reason  string
	Session inventorySessionID
	Detail  string
}

func (e *inventoryError) Error() string {
	return fmt.Sprintf("inventory %s session=%s %s", e.Reason, e.Session, e.Detail)
}

func invErr(reason string, sess inventorySessionID, detail string) *inventoryError {
	return &inventoryError{Reason: reason, Session: sess, Detail: detail}
}

// inventoryRawOutput 四項讀取的原始輸出（只存在於記憶體，處理完即丟棄）。
type inventoryRawOutput struct {
	UID             []byte
	AccountList     []byte
	Group           []byte
	Sudo            []byte
	AccountListExit int
	GroupExit       int

	// 專用帳號身分才有：Executor 為真代表這次以專用帳號登入；Escalation 非空代表跑過提權讀取。
	Executor   bool
	Escalation *invEscalation
}

// runInventoryCommands 在已建立的連線上依序執行四個常數指令。
func runInventoryCommands(ctx context.Context, client *ssh.Client) (*inventoryRawOutput, error) {
	out := &inventoryRawOutput{}
	budget := int64(inventoryMaxTotalBytes)
	for _, c := range inventoryCommands {
		if err := ctx.Err(); err != nil {
			return nil, invErr(inventoryReasonTimeout, c.ID, "deadline")
		}
		data, exit, err := runInventorySession(ctx, client, c.Cmd, &budget)
		if err != nil {
			var ie *inventoryError
			if errors.As(err, &ie) {
				ie.Session = c.ID
				return nil, ie
			}
			if ctx.Err() != nil {
				return nil, invErr(inventoryReasonTimeout, c.ID, "deadline")
			}
			return nil, invErr(inventoryReasonCommandFailed, c.ID, "session_error")
		}
		switch c.ID {
		case inventorySessionUID:
			if exit != 0 {
				return nil, invErr(inventoryReasonCommandFailed, c.ID, fmt.Sprintf("exit=%d", exit))
			}
			out.UID = data
		case inventorySessionAccounts:
			out.AccountList, out.AccountListExit = data, exit
		case inventorySessionGroup:
			out.Group, out.GroupExit = data, exit
		case inventorySessionSudo:
			if exit != 0 {
				return nil, invErr(inventoryReasonCommandFailed, c.ID, fmt.Sprintf("exit=%d", exit))
			}
			out.Sudo = data
		}
	}
	return out, nil
}

// runInventorySession 執行一個 session：stdin 為空，stdout 邊讀邊計，超過預算即關閉；stderr 丟棄。
func runInventorySession(ctx context.Context, client *ssh.Client, cmd string, budget *int64) ([]byte, int, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, 0, err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, 0, err
	}
	sess.Stderr = io.Discard
	if err := sess.Start(cmd); err != nil {
		return nil, 0, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()
	buf, err := readCapped(stdout, budget)
	if err != nil {
		_ = sess.Close()
		return nil, 0, err
	}
	exit := 0
	if werr := sess.Wait(); werr != nil {
		var ee *ssh.ExitError
		if !errors.As(werr, &ee) {
			return nil, 0, werr
		}
		exit = ee.ExitStatus()
	}
	return buf, exit, nil
}

// readCapped 讀到 EOF；累計位元組超過剩餘預算即回上限錯誤（不再讀）。
func readCapped(r io.Reader, budget *int64) ([]byte, error) {
	var out []byte
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if int64(n) > *budget {
				return nil, invErr(inventoryReasonOutputLimit, "", "total_bytes")
			}
			*budget -= int64(n)
			out = append(out, chunk[:n]...)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// classifyInventoryDialError 撥號錯誤分流為結束原因碼。
func classifyInventoryDialError(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, ErrHostKeyChanged):
		return inventoryReasonHostKeyMismatch
	case errors.Is(err, ErrHostKeyCheckFailed):
		return inventoryReasonHostKeyCheckFailed
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded):
		return inventoryReasonTimeout
	case strings.Contains(err.Error(), "unable to authenticate"):
		return inventoryReasonLoginFailed
	default:
		return inventoryReasonConnectionFailed
	}
}

// collectInventory 撥號（主機金鑰回呼由呼叫端給，背景路徑不符即拒絕、不送憑證）、執行四個常數指令並判定。
// 失敗時回 *inventoryError，並只記結構化診斷。password 與 privateKey 由本函式負責銷毀。
func collectInventory(ctx context.Context, scanID uint, addr, user string, password *sshmaterial.Password, privateKey *material.Secret, hostKey ssh.HostKeyCallback, privGroups string) (*invScanResult, *inventoryError) {
	return collectInventoryWith(ctx, scanID, addr, user, password, privateKey, hostKey, privGroups, nil)
}

// collectInventoryWith 同 collectInventory；escPassword 非 nil 代表專用帳號身分（可能提權讀取），
// 其內容為密碼型專用帳號的密碼副本（金鑰型為空切片），本函式用完即清零。
func collectInventoryWith(ctx context.Context, scanID uint, addr, user string, password *sshmaterial.Password, privateKey *material.Secret, hostKey ssh.HostKeyCallback, privGroups string, escPassword []byte) (*invScanResult, *inventoryError) {
	defer func() {
		for i := range escPassword {
			escPassword[i] = 0
		}
	}()
	client, err := dialSSHCredentials(ctx, addr, user, password, privateKey, hostKey)
	if err != nil {
		e := invErr(classifyInventoryDialError(ctx, err), "dial", "dial")
		logInventoryFailure(scanID, e)
		return nil, e
	}
	defer client.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-done:
		}
	}()
	raw, err := runInventoryCommands(ctx, client)
	if err == nil && escPassword != nil {
		raw.Executor = true
		raw.Escalation, err = maybeEscalate(ctx, client, raw, escPassword)
	}
	if err == nil {
		var res *invScanResult
		res, err = evaluateInventory(raw, privGroups)
		if err == nil {
			if res.Status == model.HostAccountScanFailed {
				e := invErr(res.Failure, inventorySessionAccounts, fmt.Sprintf("accounts_exit=%d group_exit=%d", raw.AccountListExit, raw.GroupExit))
				logInventoryFailure(scanID, e)
				return nil, e
			}
			return res, nil
		}
	}
	var ie *inventoryError
	if !errors.As(err, &ie) {
		ie = invErr(inventoryReasonCommandFailed, "", "unclassified")
	}
	if ctx.Err() != nil {
		ie.Reason = inventoryReasonTimeout
	}
	logInventoryFailure(scanID, ie)
	return nil, ie
}

// logInventoryFailure 只記結構化診斷：盤點識別、讀取項、原因與診斷碼，不含遠端原文或錯誤文字。
func logInventoryFailure(scanID uint, e *inventoryError) {
	log.Printf("[HostAccountInventory] scan=%d reason=%s session=%s detail=%s", scanID, e.Reason, e.Session, e.Detail)
}

// maybeEscalate 只在 uid 不是 0 且未提權讀取有讀不到的項目時跑提權讀取；其餘回 nil（不需要）。
func maybeEscalate(ctx context.Context, client *ssh.Client, raw *inventoryRawOutput, password []byte) (*invEscalation, error) {
	uid, err := parseInventoryUID(raw.UID)
	if err != nil || uid == 0 {
		return nil, nil
	}
	frames, err := parseInventorySudoFrames(raw.Sudo)
	if err != nil || !sudoFramesHaveUnreadable(frames) {
		return nil, nil
	}
	return runEscalatedRead(ctx, client, password)
}
