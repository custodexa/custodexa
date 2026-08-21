// Package localpty 本地子程序掛 PTY 的終端連線（database-protocol / k8s-exec 共用）：
// 實作 sshproxy 的 TerminalConn 介面（structural typing，無 import 依賴），
// bridge 的指令審計/錄製/監看/阻斷自動沿用。
package localpty

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// CLIUser 資料庫 CLI 子程序的專用降權身分（image 內建，見 docker/backend/Dockerfile）。
// 該身分非 root、無 capability、無可寫路徑、HOME 為唯讀空目錄。
const CLIUser = "dbcli"

// Options 子程序執行環境選項
type Options struct {
	// User 非空時以該系統使用者的身分執行子程序（降權）：
	// 設定 uid/gid、清空附屬群組，並把 HOME／TMPDIR 指向該身分的家目錄。
	// 查不到該使用者或其為 root 時 Start 回錯（fail-close：寧可開不了會話，
	// 不可悄悄以 root 起 CLI）。
	User string

	// Auth 非 nil 且密碼非空時，改以 PTY 提示注入提供密碼：
	// 憑證不進子程序環境也不進 argv，只在 client 開口索取時寫入終端，
	// 提示與回顯一併從輸出流濾除（不進錄影／監看／審計）。詳見 PasswordAuth。
	Auth *PasswordAuth
}

// LookupUser 查系統使用者的 uid/gid 與家目錄（供呼叫端把子程序要讀的檔案
// chown 給該身分，例如 verify-ca 的 CA 暫存檔）。
func LookupUser(name string) (uid, gid int, home string, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, "", fmt.Errorf("查無降權執行身分 %q（image 需含該帳號，請重建 backend image）: %w", name, err)
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, "", fmt.Errorf("降權執行身分 %q 的 uid 非數值: %w", name, err)
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, "", fmt.Errorf("降權執行身分 %q 的 gid 非數值: %w", name, err)
	}
	if uid == 0 || gid == 0 {
		return 0, 0, "", fmt.Errorf("降權執行身分 %q 不得為 root（uid=%d gid=%d）", name, uid, gid)
	}
	return uid, gid, u.HomeDir, nil
}

// Conn 一條已啟動的本地 CLI PTY 連線
type Conn struct {
	cmd     *exec.Cmd
	ptmx    *os.File
	onClose func() // 連線結束時的清理（如刪除 TLS CA 暫存檔），冪等由呼叫端保證

	// writeMu 序列化寫入 ptmx：提示注入由 Read 的 goroutine 觸發，
	// 與前端輸入的 pump goroutine 並行
	writeMu sync.Mutex
	// auth 非 nil 時輸出流經提示注入器過濾（見 promptauth.go）
	auth *promptAuth
}

// SetOnClose 註冊連線關閉時的清理回呼（Close 時呼叫一次）
func (c *Conn) SetOnClose(fn func()) {
	c.onClose = fn
}

// Start 啟動程式掛 PTY（以後端程序自身的身分）。
// 連線層失敗（認證錯/不可達）由 CLI 自行印在 PTY 輸出後退出，
// 使用者在終端直接看到原因；此處僅在程式缺失或 PTY 失敗時回錯。
//
// 子程序環境最小化：不繼承後端程序環境（內含 JWT/加密金鑰等機密），
// 僅給 PATH/TERM/HOME/LANG 與呼叫端明確注入的變數。
func Start(prog string, args, env []string, cols, rows int) (*Conn, error) {
	return StartWithOptions(prog, args, env, cols, rows, Options{})
}

// StartWithOptions 同 Start，另接受執行環境選項（如降權身分）。
//
// 降權（opt.User 非空）的保證面：uid/gid 換成專用非 root 身分、附屬群組清空、
// 不帶 AmbientCaps（非 root exec 且 image 內無 setuid 檔＝子程序 capability 全空）、
// HOME/TMPDIR 指向該身分唯讀的空目錄。PTY 從屬端由本程序（root）開啟後以
// fd 傳給子程序，權限在 open 時已檢查完畢，換身分不影響終端讀寫。
func StartWithOptions(prog string, args, env []string, cols, rows int, opt Options) (*Conn, error) {
	cmd := exec.Command(prog, args...)
	home := os.Getenv("HOME")
	base := []string{
		"PATH=" + os.Getenv("PATH"),
		"TERM=xterm-256color",
		"LANG=C.UTF-8",
	}
	if opt.User != "" {
		uid, gid, userHome, err := LookupUser(opt.User)
		if err != nil {
			return nil, err
		}
		home = userHome
		// Groups 為空且 NoSetGroups=false：子程序 exec 前會 setgroups(0, NULL)，
		// 清掉後端程序（root）的全部附屬群組
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
		// TMPDIR 指向唯讀空 HOME：降權身分在容器內不應有任何可寫路徑，
		// 需要暫存檔的 client 行為會顯性失敗而不是悄悄落檔
		base = append(base, "TMPDIR="+home)
	}
	cmd.Env = append(append(base, "HOME="+home), env...)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(rows), Cols: uint16(cols),
	})
	if err != nil {
		return nil, fmt.Errorf("啟動本地終端程式失敗: %w", err)
	}
	c := &Conn{cmd: cmd, ptmx: ptmx}
	if opt.Auth != nil && opt.Auth.Password != "" && opt.Auth.Prompt != "" {
		c.auth = newPromptAuth(*opt.Auth, ptmx, c.Write)
	}
	return c, nil
}

// HasPasswordPrompt 本連線是否掛上了密碼提示注入器。
// 供不變式測試斷言「dbproxy.Start 確實接上了注入器」——localpty 有這個能力
// 但呼叫端沒用，等同沒有：憑證不進環境之後若又沒人注入，會話會停在
// 使用者看得到卻答不出來的密碼提示。
func (c *Conn) HasPasswordPrompt() bool {
	return c.auth != nil
}

// Pid 子程序 PID（0＝尚未啟動或已回收）。供診斷與環境不變式測試查
// /proc/<pid>/status 核對執行身分與 capability。
func (c *Conn) Pid() int {
	if c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

// Read 讀取 CLI 輸出（程序結束時回 EOF/EIO，bridge 據此收線）。
// 設有密碼提示注入時，密碼提示與注入後的回顯不會出現在回傳的位元組中——
// 錄影、即時監看與審計虛擬螢幕都掛在本方法的下游，故一併乾淨。
func (c *Conn) Read(p []byte) (int, error) {
	if c.auth != nil {
		return c.auth.Read(p)
	}
	return c.ptmx.Read(p)
}

// Write 將前端鍵入寫進 CLI stdin（提示注入亦經此路，故需序列化）
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ptmx.Write(p)
}

// WindowChange 同步終端尺寸到 PTY
func (c *Conn) WindowChange(rows, cols int) error {
	return pty.Setsize(c.ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}

// Close 關閉 PTY 並終止子程序（冪等；Wait 回收避免殭屍程序）
func (c *Conn) Close() {
	if c.ptmx != nil {
		c.ptmx.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
	}
	if c.onClose != nil {
		c.onClose()
		c.onClose = nil
	}
}
