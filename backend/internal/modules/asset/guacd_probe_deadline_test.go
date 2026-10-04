package asset

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/guacamole"
	"github.com/stretchr/testify/require"
)

func TestGuacdProbeDeadline(t *testing.T) {
	for _, protocol := range []string{"rdp", "vnc"} {
		for _, mode := range []string{"args_budget", "args_earlier_deadline", "cancel_after_accept", "ready_silent", "shared_budget", "success"} {
			for _, rawHelper := range []bool{false, true} {
				if rawHelper && mode != "args_budget" {
					continue
				}
				name := protocol + "/" + mode
				if rawHelper {
					name += "/raw_helper"
				}
				t.Run(name, func(t *testing.T) {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					defer ln.Close()
					require.NoError(t, ln.(*net.TCPListener).SetDeadline(time.Now().Add(2*time.Second)))
					host, port := splitHostPortForTest(t, ln.Addr().String())
					var service *AssetService
					var mock sqlmock.Sqlmock
					if !rawHelper {
						_, mock, _ = setupAssetMockDB(t)
						service, err = NewAssetService(aesColumnCodec(t, make([]byte, 32)), host, port, audit.NewTxSink())
						require.NoError(t, err)
						expectAssetWithDefaultAccount(t, mock, service, protocol, "127.0.0.1", 5900)
						status := "unreachable"
						if mode == "success" {
							status = "reachable"
						}
						mock.ExpectBegin()
						mock.ExpectExec(`UPDATE "assets" SET "last_test_at"=\$1,"last_test_latency_ms"=\$2,"last_test_status"=\$3 WHERE id = \$4`).
							WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), status, 1).
							WillReturnResult(sqlmock.NewResult(0, 1))
						mock.ExpectCommit()
					}

					budget := time.Second
					timeout := 1
					if mode == "args_earlier_deadline" {
						budget = 200 * time.Millisecond
						timeout = 5
					} else if mode == "cancel_after_accept" {
						budget = 5 * time.Second
						timeout = 5
					}
					ctx := context.Background()
					cancel := func() {}
					if mode == "args_earlier_deadline" || mode == "cancel_after_accept" {
						ctx, cancel = context.WithTimeout(ctx, budget)
					}
					defer cancel()
					type outcome struct {
						result *ConnectionTestResult
						raw    guacamole.TestResult
						err    error
					}
					done := make(chan outcome, 1)
					exited := make(chan struct{})
					start := time.Now()
					go func() {
						defer close(exited)
						if rawHelper {
							done <- outcome{raw: guacamole.TestGuacamoleConnection(ctx, host, port, guacamole.TestConnectionParams{
								Protocol: protocol, Host: "127.0.0.1", Port: 5900, Password: "secret", Timeout: budget,
							})}
						} else {
							result, err := service.TestConnection(ctx, 1, timeout)
							done <- outcome{result: result, err: err}
						}
					}()
					peer, err := ln.Accept()
					require.NoError(t, err)
					peerDone := make(chan error, 1)
					peerExited := make(chan struct{})
					go func() {
						defer close(peerExited)
						peerDone <- serveDeadlineProbe(peer, mode)
					}()
					t.Cleanup(func() {
						_ = peer.Close()
						<-exited
						<-peerExited
					})
					t.Logf("accepted=true start=%s budget=%s elapsed=%s", start.Format(time.RFC3339Nano), budget, time.Since(start))
					limit := start.Add(budget + 500*time.Millisecond)
					if mode == "cancel_after_accept" {
						require.NoError(t, ctx.Err())
						cancelAt := time.Now()
						cancel()
						limit = cancelAt.Add(500 * time.Millisecond)
						t.Logf("cancel_at=%s elapsed=%s", cancelAt.Format(time.RFC3339Nano), cancelAt.Sub(start))
					}
					select {
					case got := <-done:
						t.Logf("returned elapsed=%s", time.Since(start))
						require.NoError(t, got.err)
						if rawHelper {
							require.False(t, got.raw.Success)
							require.Equal(t, guacamole.ErrorTypeTimeout, got.raw.ErrorType)
						} else {
							require.NotNil(t, got.result)
							require.Equal(t, mode == "success", got.result.Success)
							if mode == "success" {
								require.Empty(t, got.result.Code)
								require.Empty(t, got.result.ErrorCode)
							} else {
								require.Equal(t, apierror.CodeAssetTestTimeout, got.result.Code)
								require.Equal(t, ErrorCodeTimeout, got.result.ErrorCode)
								require.Equal(t, "連線逾時", got.result.Message)
							}
							require.Equal(t, protocol, got.result.Protocol)
							require.False(t, got.result.TestedAt.IsZero())
						}
					case <-time.After(time.Until(limit)):
						// Cleanup closes the peer only after recording the bounded-return failure.
						t.Errorf("accepted=true: probe did not return within budget/cancellation bound; budget=%s elapsed=%s", budget, time.Since(start))
						return
					}
					<-exited
					select {
					case peerErr := <-peerDone:
						if !errors.Is(peerErr, syscall.ECONNRESET) && !errors.Is(peerErr, syscall.EPIPE) {
							require.NoError(t, peerErr, "peer must observe EOF or a closed socket after draining client data")
						}
					case <-time.After(500 * time.Millisecond):
						t.Fatal("peer did not observe product socket closure")
					}
					<-peerExited
					if !rawHelper {
						require.NoError(t, mock.ExpectationsWereMet(), "latest test status must be persisted")
					}
				})
			}
		}
	}
}

func serveDeadlineProbe(peer net.Conn, mode string) error {
	reader := bufio.NewReader(peer)
	if mode == "ready_silent" || mode == "shared_budget" || mode == "success" {
		if _, err := guacamole.ReadInstruction(reader); err != nil {
			return err
		}
		if mode == "shared_budget" {
			time.Sleep(600 * time.Millisecond)
		}
		args := "4.args,3.1.0,8.password;"
		if mode == "success" {
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
		if mode == "shared_budget" {
			time.Sleep(600 * time.Millisecond)
			if _, err := io.WriteString(peer, "5.ready,2.id;"); err != nil {
				return err
			}
		}
	}
	_, err := io.Copy(io.Discard, reader)
	return err
}
