package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/pkg/guacamole"
	"github.com/stretchr/testify/require"
)

func TestGuacdHandshakeDeadline(t *testing.T) {
	cases := []struct {
		name    string
		stage   string
		budget  time.Duration
		cancel  bool
		public  bool
		legacy  bool
		success bool
	}{
		{name: "args_earlier_deadline", budget: time.Second},
		{name: "cancel_after_accept", budget: 5 * time.Second, cancel: true},
		{name: "ready_silent", stage: "ready", budget: time.Second},
		{name: "ready_partial", stage: "partial", budget: time.Second},
		{name: "connect_default_30s", budget: 30 * time.Second, legacy: true},
		{name: "public_default_30s", budget: 30 * time.Second, legacy: true, public: true},
		{name: "success_handoff", stage: "success", budget: 200 * time.Millisecond, success: true},
		{name: "public_success_handoff", stage: "success", budget: 200 * time.Millisecond, public: true, success: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.legacy {
				t.Parallel()
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			require.NoError(t, ln.(*net.TCPListener).SetDeadline(time.Now().Add(2*time.Second)))

			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			ctx, cancel := context.WithTimeout(parent, tc.budget)
			defer cancel()
			raw := []byte("handshake-secret")
			secret := material.Adopt(raw)
			defer secret.Destroy()
			conn := NewConnection("vnc", map[string]string{
				"password": string(raw), "private-key": string(raw),
				"sftp-password": string(raw), "sftp-private-key": string(raw),
			})
			var publicClient *guacamole.Client
			done := make(chan error, 1)
			exited := make(chan struct{})
			start := time.Now()
			go func() {
				defer close(exited)
				port := ln.Addr().(*net.TCPAddr).Port
				if tc.public {
					client, dialErr := guacamole.NewClient("127.0.0.1", port)
					publicClient = client
					if dialErr != nil {
						done <- dialErr
					} else if tc.legacy {
						done <- client.Handshake("vnc", conn.Params)
					} else {
						done <- client.HandshakeContext(ctx, "vnc", conn.Params)
					}
				} else if tc.legacy {
					done <- conn.Connect("127.0.0.1", port)
				} else {
					done <- connectWithMaterial(ctx, conn, "127.0.0.1", port, secret)
				}
			}()
			peer, err := ln.Accept()
			require.NoError(t, err)
			peerDone := make(chan error, 1)
			peerExited := make(chan struct{})
			sendNext := make(chan struct{})
			stopPeer := make(chan struct{})
			go func() {
				defer close(peerExited)
				peerDone <- serveDeadlineHandshake(peer, tc.stage, sendNext, stopPeer)
			}()
			t.Cleanup(func() {
				close(stopPeer)
				_ = peer.Close()
				<-exited
				<-peerExited
				_ = conn.Close()
				if publicClient != nil {
					_ = publicClient.Close()
				}
			})
			t.Logf("accepted=true start=%s budget=%s elapsed=%s", start.Format(time.RFC3339Nano), tc.budget, time.Since(start))
			limit := start.Add(tc.budget + 500*time.Millisecond)
			if tc.legacy {
				limit = start.Add(31 * time.Second)
			}
			if tc.cancel {
				require.NoError(t, ctx.Err())
				cancelAt := time.Now()
				cancel()
				limit = cancelAt.Add(500 * time.Millisecond)
				t.Logf("cancel_at=%s elapsed=%s", cancelAt.Format(time.RFC3339Nano), cancelAt.Sub(start))
			}
			select {
			case err = <-done:
				t.Logf("returned elapsed=%s error=%v", time.Since(start), err)
			case <-time.After(time.Until(limit)):
				// Record failure before closing the peer to release the old implementation.
				t.Errorf("accepted=true: handshake did not return within budget/cancellation bound; budget=%s elapsed=%s", tc.budget, time.Since(start))
				return
			}
			<-exited
			if tc.success {
				require.NoError(t, err)
				if !tc.public {
					require.True(t, conn.IsReady())
				}
				// Cross the old child deadline, then cancel its parent before any next I/O.
				<-ctx.Done()
				cancelParent()
				close(sendNext)
				readDone := make(chan error, 1)
				readExited := make(chan struct{})
				go func() {
					defer close(readExited)
					client := publicClient
					if !tc.public {
						client = conn.GuacClient
					}
					inst, readErr := client.ReadInstruction()
					if readErr == nil && inst.Opcode != "sync" {
						readErr = fmt.Errorf("next opcode=%s, want sync", inst.Opcode)
					}
					if readErr == nil {
						readErr = client.WriteInstruction(guacamole.NewInstruction("sync", "1"))
					}
					readDone <- readErr
				}()
				select {
				case err = <-readDone:
				case <-time.After(500 * time.Millisecond):
					t.Error("post-deadline instruction remained blocked")
					_ = peer.Close()
					err = <-readDone
				}
				<-readExited
				require.NoError(t, err, "handoff must clear read/write deadlines and cancellation callback")
				if tc.public {
					require.NoError(t, publicClient.Close())
				} else {
					require.NoError(t, conn.Close())
				}
			} else {
				require.Error(t, err)
				if tc.cancel {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					var netErr net.Error
					require.True(t, errors.Is(err, context.DeadlineExceeded) ||
						(errors.As(err, &netErr) && netErr.Timeout()), "expected deadline failure: %v", err)
				}
				if tc.legacy {
					require.GreaterOrEqual(t, time.Since(start), 30*time.Second, "default must allow the complete 30-second budget")
				}
			}
			select {
			case peerErr := <-peerDone:
				require.NoError(t, peerErr, "peer must observe EOF after draining client data")
			case <-time.After(500 * time.Millisecond):
				t.Fatal("peer did not observe product socket closure")
			}
			<-peerExited
			if !tc.public {
				lockDone := make(chan struct{})
				go func() {
					defer close(lockDone)
					if conn.IsReady() {
						t.Error("closed or failed handshake is ready")
					}
					_ = conn.Close()
				}()
				select {
				case <-lockDone:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("Close/IsReady remained blocked after handshake returned")
				}
				require.Nil(t, conn.GuacClient)
				if !tc.legacy {
					require.Equal(t, make([]byte, len(raw)), raw)
				}
				for _, key := range []string{"password", "private-key", "sftp-password", "sftp-private-key"} {
					require.NotContains(t, conn.Params, key)
				}
			}
		})
	}
}

func serveDeadlineHandshake(peer net.Conn, stage string, sendNext, stop <-chan struct{}) error {
	reader := bufio.NewReader(peer)
	if stage != "" {
		if _, err := guacamole.ReadInstruction(reader); err != nil {
			return err
		}
		args := "4.args,3.1.0,8.password;"
		if stage == "success" {
			// Coalesce instructions to exercise reuse of the buffered reader.
			args += "5.ready,2.id;"
		}
		if _, err := io.WriteString(peer, args); err != nil {
			return err
		}
		for i := 0; i < 5; i++ {
			if _, err := guacamole.ReadInstruction(reader); err != nil {
				return err
			}
		}
		if stage == "partial" {
			if _, err := io.WriteString(peer, "5.ready,8.par"); err != nil {
				return err
			}
		}
		if stage == "success" {
			select {
			case <-sendNext:
			case <-stop:
				return nil
			}
			if _, err := io.WriteString(peer, "4.sync,1.1;"); err != nil {
				return err
			}
			inst, err := guacamole.ReadInstruction(reader)
			if err != nil {
				return err
			}
			if inst.Opcode != "sync" {
				return fmt.Errorf("handoff write opcode=%s, want sync", inst.Opcode)
			}
		}
	}
	_, err := io.Copy(io.Discard, reader)
	return err
}
