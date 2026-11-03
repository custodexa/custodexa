package asset

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// 多帳號行程內 SSH 靶機：支援 root 直接改密、三種 sudo 行為，並記錄每次認證與每個 session 的
// 指令與 stdin，供代改測試斷言「誰登入、跑了什麼、送了什麼」。

// sudo 行為（fakeAccount.sudo）
const (
	fakeSudoNone     = ""         // 沒有任何 sudo 規則：-n 回報需要密碼，讀密碼後仍拒絕
	fakeSudoNopasswd = "nopasswd" // 免密碼規則
	fakeSudoPassword = "password" // 需要密碼的規則
	fakeSudoBroken   = "broken"   // -n 以非零結束且訊息不含「需要密碼」
)

type fakeAccount struct {
	password string
	key      ssh.PublicKey
	sudo     string
	// sudoersRead 免密碼規則之外，另有可讀取 sudo 規則的唯讀規則（盤點的提權讀取）
	sudoersRead bool
}

type fakeAuthAttempt struct {
	user     string
	method   string // password／publickey
	password string
	ok       bool
}

type fakeSession struct {
	user  string
	cmd   string
	stdin string
}

type execSSHServer struct {
	t        *testing.T
	listener net.Listener
	hostKey  ssh.Signer

	mu       sync.Mutex
	accounts map[string]*fakeAccount
	attempts []fakeAuthAttempt
	sessions []fakeSession
	// echoStdin 把收到的 stdin 回吐 stderr（惡意或異常目標機）
	echoStdin bool
	// echoLoginPassword 把登入者在認證時送來的密碼也回吐 stderr（惡意目標機；密碼認證時它已拿到這組密碼）
	echoLoginPassword bool
	// rejectApply 帳號存在也拒絕套用（模擬 PAM 拒絕；目標密碼不變）
	rejectApply bool
}

func newExecSSHServer(t *testing.T) *execSSHServer {
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
	s := &execSSHServer{t: t, listener: ln, hostKey: signer, accounts: map[string]*fakeAccount{}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *execSSHServer) addr() string { return s.listener.Addr().String() }

func (s *execSSHServer) addAccount(user, password, sudo string) *fakeAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &fakeAccount{password: password, sudo: sudo}
	s.accounts[user] = a
	return a
}

func (s *execSSHServer) passwordOf(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.accounts[user]; a != nil {
		return a.password
	}
	return ""
}

func (s *execSSHServer) authAttempts() []fakeAuthAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fakeAuthAttempt(nil), s.attempts...)
}

func (s *execSSHServer) execSessions() []fakeSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]fakeSession(nil), s.sessions...)
}

// attemptsAs 某帳號的認證嘗試次數（可只數帶指定密碼者；password 為空則全數）。
func (s *execSSHServer) attemptsAs(user, password string) int {
	n := 0
	for _, a := range s.authAttempts() {
		if a.user == user && (password == "" || (a.method == "password" && a.password == password)) {
			n++
		}
	}
	return n
}

func (s *execSSHServer) handleConn(nConn net.Conn) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			a := s.accounts[c.User()]
			ok := a != nil && a.password != "" && a.password == string(pass)
			s.attempts = append(s.attempts, fakeAuthAttempt{user: c.User(), method: "password", password: string(pass), ok: ok})
			if !ok {
				return nil, fmt.Errorf("denied")
			}
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			a := s.accounts[c.User()]
			ok := a != nil && a.key != nil && string(a.key.Marshal()) == string(key.Marshal())
			s.attempts = append(s.attempts, fakeAuthAttempt{user: c.User(), method: "publickey", ok: ok})
			if !ok {
				return nil, fmt.Errorf("denied")
			}
			return &ssh.Permissions{}, nil
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
		go func() {
			for req := range chReqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				cmd := parsePayloadString(req.Payload)
				_ = req.Reply(true, nil)
				data, _ := io.ReadAll(ch)
				if out, ok := s.tarOutput(sconn.User(), cmd, string(data)); ok {
					_, _ = ch.Write(out)
					sendExitStatus(ch, 0)
					ch.Close()
					return
				}
				code, stderr := s.run(sconn.User(), cmd, string(data))
				if stderr != "" {
					_, _ = ch.Stderr().Write([]byte(stderr))
				}
				sendExitStatus(ch, uint32(code))
				ch.Close()
				return
			}
		}()
	}
}

// run 模擬指令；回傳退出碼與 stderr。
func (s *execSSHServer) run(user, cmd, stdin string) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append(s.sessions, fakeSession{user: user, cmd: cmd, stdin: stdin})
	echo := ""
	if s.echoStdin {
		echo = strings.ReplaceAll(strings.TrimSpace(stdin), "\n", " ") + " rejected by pam"
	}
	acct := s.accounts[user]
	if s.echoLoginPassword && acct != nil && acct.password != "" {
		echo += " login-secret=" + acct.password
	}
	switch cmd {
	case "chpasswd":
		if user != "root" {
			return 1, "chpasswd: permission denied"
		}
		return s.apply(stdin, echo)
	// 比對字面值而非常數：指令字串被改動時，靶機認不得，端到端測試即轉紅
	case "env LC_ALL=C sudo -n chpasswd":
		switch acct.sudo {
		case fakeSudoNopasswd:
			return s.apply(stdin, echo)
		case fakeSudoBroken:
			return 1, "sudo: unexpected failure " + echo
		default:
			return 1, "sudo: a password is required"
		}
	case "sudo -k -S -p '' chpasswd":
		first, rest, _ := strings.Cut(stdin, "\n")
		if acct.sudo != fakeSudoPassword || first != acct.password {
			return 1, "sudo: Sorry, try again."
		}
		return s.apply(rest, echo)
	}
	// 登入帳號自改：非 root 為 sudo -S -p '' sh -c 'chpasswd'，stdin 第一行是舊密碼
	if strings.HasPrefix(cmd, "sudo -S") {
		_, rest, _ := strings.Cut(stdin, "\n")
		return s.apply(rest, echo)
	}
	return 127, "command not found"
}

// apply 逐列套用「帳號:新密碼」；任何一列的帳號不存在即整批放棄（回非零）。
func (s *execSSHServer) apply(stdin, echo string) (int, string) {
	if s.rejectApply {
		return 1, "chpasswd: pam_chauthtok() failed " + echo
	}
	type pair struct{ user, pw string }
	var todo []pair
	for _, line := range strings.Split(strings.TrimRight(stdin, "\n"), "\n") {
		if line == "" {
			continue
		}
		u, p, ok := strings.Cut(line, ":")
		if !ok || s.accounts[u] == nil {
			return 1, "chpasswd: user does not exist " + echo
		}
		todo = append(todo, pair{u, p})
	}
	for _, p := range todo {
		s.accounts[p.user].password = p.pw
	}
	return 0, echo
}

// tarOutput 模擬盤點的提權讀取（第一段、免密碼）：帳號有讀取規則時回含 sudoers 一般檔的 tar 封存。
// 其餘情況不處理，交給 run（回 127，stdout 為空）。
func (s *execSSHServer) tarOutput(user, cmd, stdin string) ([]byte, bool) {
	if cmd != inventoryEscalatedCmdNoPassword {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acct := s.accounts[user]
	if acct == nil || !acct.sudoersRead || acct.sudo != fakeSudoNopasswd {
		return nil, false
	}
	s.sessions = append(s.sessions, fakeSession{user: user, cmd: cmd, stdin: stdin})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("root ALL=(ALL) ALL\n")
	_ = tw.WriteHeader(&tar.Header{Name: "sudoers", Typeflag: tar.TypeReg, Mode: 0o440, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.WriteHeader(&tar.Header{Name: "sudoers.d/", Typeflag: tar.TypeDir, Mode: 0o750})
	_ = tw.Close()
	return buf.Bytes(), true
}
