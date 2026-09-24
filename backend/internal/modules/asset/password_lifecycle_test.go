package asset

import (
	"context"
	"fmt"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/internal/sshmaterial/testkit"
	"golang.org/x/crypto/ssh"
	"testing"
	"time"
)

func callbackCases(t *testing.T, integration bool) {
	for _, point := range []string{"probe", "rotation_password", "rotation_key"} {
		t.Run(point, func(t *testing.T) {
			testkit.Run(t, integration, func(ctx context.Context, host string, port int, user string, _ *material.Secret, p *sshmaterial.Password, key ssh.HostKeyCallback) (*ssh.Client, func(), error) {
				addr := fmt.Sprintf("%s:%d", host, port)
				var c *ssh.Client
				var err error
				switch point {
				case "probe":
					c, err = dialSSHProbe(ctx, addr, user, p, nil, key, 5*time.Second)
				case "rotation_password":
					c, err = dialSSHPassword(ctx, addr, user, p, key)
				case "rotation_key":
					c, err = dialSSHCredentials(ctx, addr, user, p, nil, key)
				}
				if err != nil {
					return nil, nil, err
				}
				return c, func() { c.Close() }, nil
			})
		})
	}
}
func TestSSHPasswordCallbackLifecycle(t *testing.T)   { callbackCases(t, false) }
func TestSSHPasswordCallbackIntegration(t *testing.T) { callbackCases(t, true) }
