package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// testSSHServer 行程內 SSH 靶機：足以覆蓋改密的四種互動——
// 密碼認證、公鑰認證、exec 會話（chpasswd）與 SFTP 子系統（authorized_keys）。
//
// 用行程內伺服端而非真容器，是為了讓「連線在指令送出後中斷」「chpasswd 以非零
// 退出」這兩種**故障**可被精確注入；真靶機做不到穩定重現這兩者。
type testSSHServer struct {
	t        *testing.T
	listener net.Listener
	hostKey  ssh.Signer
	homeDir  string

	mu sync.Mutex
	// password 目前可用的密碼（chpasswd 成功後由伺服端自行更新，模擬真的改掉了）
	password string
	// authorizedKeys 目前 authorized_keys 的內容（SFTP 與公鑰認證共用同一份事實）
	authorizedKeys func() string

	// --- 故障注入開關 ---
	// chpasswdExitCode 非 0 即讓 exec 以該碼退出（遠端確定未變更）
	chpasswdExitCode int
	// chpasswdDropConn true＝收到指令後直接斷線（遠端狀態不可知）
	chpasswdDropConn bool
	// rejectVerifyLogin true＝chpasswd 之後的登入一律失敗（模擬改密成功但驗證階段異常）
	rejectVerifyLogin bool
	// sftpDisabled true＝拒絕 sftp subsystem 請求
	sftpDisabled bool
	// chpasswdEchoStdinToStderr true＝把收到的 stdin 原樣回吐 stderr。
	// 這是「遠端訊息是攻擊者可控輸入」的最小重現：目標機（被入侵或只是行為異常）
	// 藉此把本輪產生的新密碼塞進我方的錯誤訊息
	chpasswdEchoStdinToStderr bool

	// --- 注入器自證計數（故障注入必須證明真的觸發過）---
	chpasswdCalls     atomic.Int32
	chpasswdExitFired atomic.Int32
	chpasswdDropFired atomic.Int32
	verifyRejectFired atomic.Int32
	sftpRejectFired   atomic.Int32
	chpasswdEchoFired atomic.Int32
	passwordAuthCalls atomic.Int32
	publicKeyAuthOK   atomic.Int32
	// lastChpasswdStdin 最近一次 chpasswd 收到的 stdin（斷言憑證確實走 stdin）
	lastChpasswdStdin atomic.Value
	// lastExecCommand 最近一次 exec 的命令列（斷言憑證不進 argv）
	lastExecCommand atomic.Value
}

func newTestSSHServer(t *testing.T, username, password string) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	home := t.TempDir()
	s := &testSSHServer{t: t, listener: ln, hostKey: signer, homeDir: home, password: password}
	s.authorizedKeys = func() string {
		data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
		if err != nil {
			return ""
		}
		return string(data)
	}
	go s.serve(username)
	t.Cleanup(func() { ln.Close() })
	return s
}

// addr 回傳 host:port
func (s *testSSHServer) addr() string { return s.listener.Addr().String() }

func (s *testSSHServer) hostKeyCallback() ssh.HostKeyCallback {
	return ssh.FixedHostKey(s.hostKey.PublicKey())
}

func (s *testSSHServer) currentPassword() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.password
}

func (s *testSSHServer) setPassword(pw string) {
	s.mu.Lock()
	s.password = pw
	s.mu.Unlock()
}

func (s *testSSHServer) readAuthorizedKeys() string { return s.authorizedKeys() }

func (s *testSSHServer) serve(username string) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn, username)
	}
}

func (s *testSSHServer) handleConn(nConn net.Conn, username string) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.passwordAuthCalls.Add(1)
			if c.User() != username {
				return nil, fmt.Errorf("unknown user")
			}
			current := s.currentPassword()
			if string(pass) != current {
				return nil, fmt.Errorf("bad password")
			}
			s.mu.Lock()
			reject := s.rejectVerifyLogin
			s.mu.Unlock()
			// 驗證階段的注入：**只在 chpasswd 已執行後生效**——否則連「舊憑證登入」
			// 那一步都會失敗，測到的是登入失敗而非驗證失敗（受測路徑錯位）
			if reject && s.chpasswdCalls.Load() > 0 {
				s.verifyRejectFired.Add(1)
				return nil, fmt.Errorf("injected verify failure")
			}
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			for _, line := range strings.Split(s.readAuthorizedKeys(), "\n") {
				if keyMaterial(line) != "" && keyMaterial(line) == keyMaterial(want) {
					s.publicKeyAuthOK.Add(1)
					return &ssh.Permissions{}, nil
				}
			}
			return nil, fmt.Errorf("key rejected")
		},
	}
	cfg.AddHostKey(s.hostKey)

	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		nConn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go s.handleSession(ch, chReqs, nConn)
	}
}

func (s *testSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, raw net.Conn) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			cmd := parsePayloadString(req.Payload)
			s.lastExecCommand.Store(cmd)
			_ = req.Reply(true, nil)
			s.runExec(ch, cmd, raw)
			return
		case "subsystem":
			name := parsePayloadString(req.Payload)
			s.mu.Lock()
			disabled := s.sftpDisabled
			s.mu.Unlock()
			if name != "sftp" || disabled {
				if disabled {
					s.sftpRejectFired.Add(1)
				}
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(s.homeDir))
			if err != nil {
				ch.Close()
				return
			}
			_ = srv.Serve()
			ch.Close()
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// runExec 模擬 chpasswd：自 stdin 讀 user:password（非 root 時第一行為 sudo 密碼）
func (s *testSSHServer) runExec(ch ssh.Channel, cmd string, raw net.Conn) {
	s.chpasswdCalls.Add(1)
	data, _ := io.ReadAll(ch)
	s.lastChpasswdStdin.Store(string(data))

	s.mu.Lock()
	exitCode := s.chpasswdExitCode
	drop := s.chpasswdDropConn
	echo := s.chpasswdEchoStdinToStderr
	s.mu.Unlock()

	// 惡意／異常目標機：把收到的 stdin（含新密碼）當作錯誤訊息回吐。
	// 刻意不含 ": "——修補前的 sanitizeSSHErr 只截到第一個 ": " 前，整段原文會被保留
	if echo {
		s.chpasswdEchoFired.Add(1)
		payload := strings.ReplaceAll(strings.TrimSpace(string(data)), "\n", " ")
		_, _ = ch.Stderr().Write([]byte(payload + " rejected by pam"))
	}

	if drop {
		s.chpasswdDropFired.Add(1)
		raw.Close() // 指令已送達但回應永遠不到：遠端狀態不可知
		return
	}
	if exitCode != 0 {
		s.chpasswdExitFired.Add(1)
		sendExitStatus(ch, uint32(exitCode))
		ch.Close()
		return
	}
	// 成功：伺服端真的把密碼換掉，其後只有新密可登入
	if entry := lastNonEmptyLine(string(data)); entry != "" {
		if idx := strings.Index(entry, ":"); idx > 0 {
			s.setPassword(entry[idx+1:])
		}
	}
	sendExitStatus(ch, 0)
	ch.Close()
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	payload := []byte{0, 0, 0, 0}
	payload[0] = byte(code >> 24)
	payload[1] = byte(code >> 16)
	payload[2] = byte(code >> 8)
	payload[3] = byte(code)
	_, _ = ch.SendRequest("exit-status", false, payload)
}

// parsePayloadString SSH 封包的 string 欄位（4-byte 長度前綴）
func parsePayloadString(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || 4+n > len(payload) {
		return ""
	}
	return string(payload[4 : 4+n])
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

// seedAuthorizedKeys 直接在靶機 home 內建立 authorized_keys（測試前置）
func (s *testSSHServer) seedAuthorizedKeys(content string) {
	s.t.Helper()
	dir := filepath.Join(s.homeDir, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.t.Fatalf("mkdir .ssh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(content), 0o600); err != nil {
		s.t.Fatalf("write authorized_keys: %v", err)
	}
}

// testKeyPair 產生一組測試金鑰對（PEM 私鑰 ＋ authorized_keys 行）
func testKeyPair(t *testing.T, comment string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	return string(pem.EncodeToMemory(block)), line
}
