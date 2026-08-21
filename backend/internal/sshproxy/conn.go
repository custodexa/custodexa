package sshproxy

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/asset"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	dialTimeout = 5 * time.Second
	defaultTerm = "xterm-256color"
)

// 連線錯誤分類：前端據此呈現可讀訊息，不洩漏內部細節
var (
	ErrAuthFailed  = errors.New("SSH 認證失敗，請確認資產憑證")
	ErrUnreachable = errors.New("無法連線到目標主機")
	ErrDialTimeout = errors.New("連線目標主機逾時")
)

// ConnConfig SSH 連線參數（憑證由後端注入，design D2）
type ConnConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
	Cols       int
	Rows       int
	// HostKey host key 驗證 callback（必填，host-key-verification）
	HostKey ssh.HostKeyCallback
}

// TerminalConn 終端類連線的最小介面（database-protocol 階段 0）：
// bridge 僅依賴此面——SSH 與未來的資料庫 CLI PTY（usql/redis-cli）同樣實作，
// 指令審計/錄製/監看/阻斷因此對任何終端協議自動沿用
type TerminalConn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	WindowChange(rows, cols int) error
	Close()
}

// SSHConn 一條已建立 PTY 與 shell 的 SSH 連線
type SSHConn struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

// authMethods 依憑證組裝認證方式：私鑰優先，密碼次之
func authMethods(cfg ConnConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("解析私鑰失敗: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}

	if len(methods) == 0 {
		return nil, errors.New("資產未設定可用憑證")
	}

	return methods, nil
}

// classifyDialError 將底層錯誤映射為使用者可讀的分類錯誤
func classifyDialError(err error) error {
	// host key 變更是關鍵安全訊號（host-key-verification D2），原樣透傳不得泛化
	if errors.Is(err, asset.ErrHostKeyChanged) {
		return asset.ErrHostKeyChanged
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrDialTimeout
	}
	if strings.Contains(err.Error(), "unable to authenticate") ||
		strings.Contains(err.Error(), "no supported methods remain") {
		return ErrAuthFailed
	}
	return ErrUnreachable
}

// Client 底層 ssh.Client（session-stats：供指標採集開新 channel）
func (c *SSHConn) Client() *ssh.Client {
	return c.client
}

// Dial 建立 SSH 連線、開 PTY 並啟動互動 shell
//
// HostKeyCallback 由呼叫端注入（host-key-verification TOFU）；
// 未注入時 fail-closed 拒線，杜絕無驗證路徑。
func Dial(cfg ConnConfig) (*SSHConn, error) {
	if cfg.HostKey == nil {
		return nil, errors.New("host key 驗證未配置，連線已拒絕")
	}
	methods, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            methods,
		HostKeyCallback: cfg.HostKey,
		Timeout:         dialTimeout,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, classifyDialError(err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("建立 SSH session 失敗: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(defaultTerm, cfg.Rows, cfg.Cols, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("請求 PTY 失敗: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("取得 stdin 失敗: %w", err)
	}

	// PTY 模式下遠端 shell 的 stderr 已併入 PTY 輸出流，無需另接 stderr
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("取得 stdout 失敗: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("啟動 shell 失敗: %w", err)
	}

	return &SSHConn{client: client, session: session, stdin: stdin, stdout: stdout}, nil
}

// Write 將前端鍵入寫進遠端 stdin
func (c *SSHConn) Write(p []byte) (int, error) {
	return c.stdin.Write(p)
}

// Read 從遠端 stdout 讀取輸出
func (c *SSHConn) Read(p []byte) (int, error) {
	return c.stdout.Read(p)
}

// WindowChange 同步終端尺寸到遠端 PTY（SSH window-change request）
func (c *SSHConn) WindowChange(rows, cols int) error {
	return c.session.WindowChange(rows, cols)
}

// Wait 阻塞直到遠端 shell 結束
func (c *SSHConn) Wait() error {
	return c.session.Wait()
}

// Close 依序釋放 session 與 client
func (c *SSHConn) Close() {
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		c.client.Close()
	}
}
