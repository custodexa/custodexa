package sshmaterial

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/custodexa/backend/internal/material"
	"golang.org/x/crypto/ssh"
)

// Password owns authentication material independently of any rotation material.
// Calls counts client callback invocations, not server authentication events.
type Password struct {
	secret *material.Secret
	calls  atomic.Int64
}

func NewPassword(secret *material.Secret) *Password { return &Password{secret: secret} }
func CopyPassword(raw []byte) *Password             { return NewPassword(material.Adopt(bytes.Clone(raw))) }
func (p *Password) Empty() bool                     { return p == nil || p.secret.IsEmpty() }
func (p *Password) Destroy() {
	if p != nil {
		p.secret.Destroy()
	}
}
func (p *Password) Calls() int64 {
	if p == nil {
		return 0
	}
	return p.calls.Load()
}

// Callback creates the immutable representation only when the SSH client asks.
// Library strings and marshaled packets are outside our erasure guarantee.
func (p *Password) Callback() (string, error) {
	if p == nil {
		return "", material.ErrDestroyed
	}
	p.calls.Add(1)
	return material.Use(p.secret, func(raw []byte) (string, error) { return string(raw), nil })
}

// Dial applies cancellation to both the TCP connection and the SSH handshake.
func Dial(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	socket, err := (&net.Dialer{Timeout: cfg.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	if cfg.Timeout > 0 {
		_ = socket.SetDeadline(time.Now().Add(cfg.Timeout))
	}
	conn, chans, reqs, err := ssh.NewClientConn(socket, addr, cfg)
	if err != nil {
		socket.Close()
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	_ = socket.SetDeadline(time.Time{})
	return ssh.NewClient(conn, chans, reqs), nil
}
