package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/pkg/guacamole"
	"github.com/stretchr/testify/require"
)

func TestSidecarCredentialLifetime(t *testing.T) {
	for _, mode := range []string{"success", "handshake_failure", "cancel_before_handshake"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("sidecar-fixture")
			owner := material.Adopt(raw)
			params := map[string]string{"sftp-password": string(raw), "password": "vnc-fixture"}
			conn := NewConnection("vnc", params)
			defer conn.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			host, port := "127.0.0.1", 0
			done := make(chan error, 1)
			if mode == "cancel_before_handshake" {
				cancel()
			} else {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer ln.Close()
				port = ln.Addr().(*net.TCPAddr).Port
				go func() {
					peer, err := ln.Accept()
					if err != nil {
						done <- err
						return
					}
					defer peer.Close()
					_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
					reader := bufio.NewReader(peer)
					if _, err = guacamole.ReadInstruction(reader); err != nil {
						done <- err
						return
					}
					_, err = fmt.Fprint(peer, "4.args,3.1.0,13.sftp-password;")
					if err != nil {
						done <- err
						return
					}
					for i := 0; i < 5; i++ {
						inst, readErr := guacamole.ReadInstruction(reader)
						if readErr != nil {
							done <- readErr
							return
						}
						if inst.Opcode == "connect" && (len(inst.Args) != 2 || inst.Args[1] != "sidecar-fixture") {
							done <- fmt.Errorf("missing sidecar credential")
							return
						}
					}
					if mode == "handshake_failure" {
						_, err = fmt.Fprint(peer, "5.error,7.fixture;")
					} else {
						_, err = fmt.Fprint(peer, "5.ready,2.id;")
					}
					done <- err
				}()
			}
			err := connectWithMaterial(ctx, conn, host, port, owner)
			if mode == "success" {
				require.NoError(t, err)
				require.True(t, conn.Ready)
			} else if mode == "handshake_failure" {
				require.ErrorContains(t, err, "guacd 回傳錯誤: fixture")
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			if mode != "cancel_before_handshake" {
				require.NoError(t, <-done)
			}
			require.Equal(t, make([]byte, len(raw)), raw)
			require.NotContains(t, params, "sftp-password")
			require.NotContains(t, conn.Params, "password")
		})
	}
}
