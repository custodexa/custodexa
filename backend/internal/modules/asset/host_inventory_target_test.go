package asset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// invTarget 行程內 SSH 靶機：依完整指令字串回固定輸出，記錄交握、帳號名與認證嘗試。
type invTarget struct {
	t        *testing.T
	ln       net.Listener
	hostKey  ssh.Signer
	password string

	mu         sync.Mutex
	responses  map[string]invResponse
	commands   []string
	stdins     []string // 與 commands 同序：每個 session 收到的 stdin
	handshakes int
	users      map[string]bool
	pwCalls    int
	pkCalls    int
	stall      time.Duration
}

type invResponse struct {
	Out  string
	Err  string // 寫到 stderr 的內容
	Exit uint32
}

func newInvTarget(t *testing.T, password string) *invTarget {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := &invTarget{t: t, ln: ln, hostKey: signer, password: password, responses: map[string]invResponse{}, users: map[string]bool{}}
	t.Cleanup(func() { ln.Close() })
	go tg.serve()
	return tg
}

func (tg *invTarget) addr() string { return tg.ln.Addr().String() }

func (tg *invTarget) hostKeyCallback() ssh.HostKeyCallback {
	return ssh.FixedHostKey(tg.hostKey.PublicKey())
}

// setStandard 以四個常數指令配置輸出。
func (tg *invTarget) setStandard(uid, passwd, group, sudo string) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.responses[inventoryCommands[0].Cmd] = invResponse{Out: uid}
	tg.responses[inventoryCommands[1].Cmd] = invResponse{Out: passwd}
	tg.responses[inventoryCommands[2].Cmd] = invResponse{Out: group}
	tg.responses[inventoryCommands[3].Cmd] = invResponse{Out: sudo}
}

func (tg *invTarget) set(cmdIdx int, r invResponse) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.responses[inventoryCommands[cmdIdx].Cmd] = r
}

func (tg *invTarget) recorded() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]string(nil), tg.commands...)
}

func (tg *invTarget) serve() {
	for {
		c, err := tg.ln.Accept()
		if err != nil {
			return
		}
		go tg.handle(c)
	}
}

func (tg *invTarget) handle(c net.Conn) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			tg.mu.Lock()
			tg.pwCalls++
			tg.users[meta.User()] = true
			tg.mu.Unlock()
			if string(pw) == tg.password {
				return nil, nil
			}
			return nil, errInvTestAuth
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			tg.mu.Lock()
			tg.pkCalls++
			tg.users[meta.User()] = true
			tg.mu.Unlock()
			return nil, errInvTestAuth
		},
	}
	cfg.AddHostKey(tg.hostKey)
	tg.mu.Lock()
	tg.handshakes++
	tg.mu.Unlock()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go tg.session(ch, creqs)
	}
}

func (tg *invTarget) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		cmd := ""
		if len(req.Payload) >= 4 {
			n := binary.BigEndian.Uint32(req.Payload[:4])
			if int(n) <= len(req.Payload)-4 {
				cmd = string(req.Payload[4 : 4+n])
			}
		}
		_ = req.Reply(true, nil)
		in, _ := io.ReadAll(ch)
		tg.mu.Lock()
		tg.commands = append(tg.commands, cmd)
		tg.stdins = append(tg.stdins, string(in))
		r, ok := tg.responses[cmd]
		stall := tg.stall
		tg.mu.Unlock()
		if stall > 0 {
			time.Sleep(stall)
		}
		if !ok {
			r = invResponse{Exit: 127}
		}
		_, _ = ch.Write([]byte(r.Out))
		if r.Err != "" {
			_, _ = ch.Stderr().Write([]byte(r.Err))
		}
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, r.Exit)
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

type invTestAuthError struct{}

func (invTestAuthError) Error() string { return "denied" }

var errInvTestAuth = invTestAuthError{}

// stdinOf 回傳指定指令每次被呼叫時收到的 stdin。
func (tg *invTarget) stdinOf(cmd string) []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	var out []string
	for i, c := range tg.commands {
		if c == cmd {
			out = append(out, tg.stdins[i])
		}
	}
	return out
}

func (tg *invTarget) setCmd(cmd string, r invResponse) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.responses[cmd] = r
}
