package sshproxy

import (
	"context"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/internal/sshmaterial/testkit"
	"golang.org/x/crypto/ssh"
	"testing"
)

func callbackDial(ctx context.Context, host string, port int, user string, _ *material.Secret, p *sshmaterial.Password, key ssh.HostKeyCallback) (*ssh.Client, func(), error) {
	c, err := Dial(ConnConfig{Context: ctx, Host: host, Port: port, Username: user, Password: p, HostKey: key, Cols: 120, Rows: 30})
	if err != nil {
		return nil, nil, err
	}
	return c.Client(), c.Close, nil
}
func TestSSHPasswordCallbackLifecycle(t *testing.T)   { testkit.Run(t, false, callbackDial) }
func TestSSHPasswordCallbackIntegration(t *testing.T) { testkit.Run(t, true, callbackDial) }
