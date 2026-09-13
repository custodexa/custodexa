package session

import (
	"context"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/internal/sshmaterial/testkit"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"testing"
)

func callbackDial(ctx context.Context, host string, port int, user string, owner *material.Secret, p *sshmaterial.Password, key ssh.HostKeyCallback) (*ssh.Client, func(), error) {
	c, err := dialSFTP(ctx, &asset.AssetCredentials{Asset: &model.Asset{Host: host, Port: port}, Username: user, Password: owner}, p, key)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { c.Close() }, nil
}
func TestSSHPasswordCallbackLifecycle(t *testing.T)   { testkit.Run(t, false, callbackDial) }
func TestSSHPasswordCallbackIntegration(t *testing.T) { testkit.Run(t, true, callbackDial, checkSFTP) }

func checkSFTP(client *ssh.Client) error {
	s, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Stat(".")
	return err
}
