package sshproxy

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
)

type parityTerminal struct {
	*fakeTerminalConn
	first bool
}

func (p *parityTerminal) Read(b []byte) (int, error) {
	if !p.first {
		p.first = true
		return copy(b, []byte("parity-output\r\n")), nil
	}
	return p.fakeTerminalConn.Read(b)
}
func TestBridgeTransportParity(t *testing.T) {
	for _, transport := range []string{"websocket", "inprocess"} {
		for _, reason := range []string{endReasonNormal, endReasonIdleTimeout, endReasonMaxDuration} {
			t.Run(transport+"/"+reason, func(t *testing.T) {
				h, db, _ := setupPolicyGateTest(t)
				h.SessionService = session.NewSessionService(nil)
				sess := &model.Session{UserID: 1, Protocol: model.ProtocolSSH, Status: model.SessionStatusActive, StartTime: time.Now()}
				if err := db.Create(sess).Error; err != nil {
					t.Fatal(err)
				}
				var server, client Transport
				if transport == "websocket" {
					server, client = newWSPair(t)
				} else {
					server, client = NewInProcessTransportPair()
				}
				defer client.Close()
				conn := &parityTerminal{fakeTerminalConn: newFakeTerminalConn()}
				b := newBridge(server, conn, sess, h.SessionService, h.RecordingPath, 1, 1)
				b.checkInterval = 5 * time.Millisecond
				if reason == endReasonIdleTimeout {
					b.setTimeouts(200*time.Millisecond, 0)
				}
				if reason == endReasonMaxDuration {
					b.setTimeouts(0, 200*time.Millisecond)
				}
				rec, err := newRecordingTap(h.RecordingPath, sess.ID, 80, 24)
				if err != nil {
					t.Fatal(err)
				}
				b.attachRecording(rec)
				done := make(chan struct{})
				go func() {
					b.Run()
					rec.Close(h.SessionService, sess.ID)
					h.closeSession(sess, b.EndReason())
					close(done)
				}()
				frames := make(chan []Message, 1)
				go func() {
					var messages []Message
					for {
						_, raw, err := client.ReadMessage()
						if err != nil {
							break
						}
						var m Message
						if json.Unmarshal(raw, &m) == nil {
							messages = append(messages, m)
							if reason == endReasonNormal && m.Type == MsgData {
								client.Close()
							}
						}
					}
					frames <- messages
				}()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					b.stop()
					t.Fatal("bridge did not settle")
				}
				messages := <-frames
				if b.EndReason() != reason {
					t.Fatalf("reason=%s want=%s", b.EndReason(), reason)
				}
				var got model.Session
				if err := db.First(&got, sess.ID).Error; err != nil {
					t.Fatal(err)
				}
				if got.Status != model.SessionStatusClosed || got.EndTime == nil || got.EndReason != reason {
					t.Fatalf("session not settled: %+v", got)
				}
				if !got.HasRecording || got.RecordingSize <= 0 {
					t.Fatalf("recording not settled: %+v", got)
				}
				raw, err := os.ReadFile(got.RecordingPath)
				if err != nil || !bytes.Contains(raw, []byte("parity-output")) {
					t.Fatalf("recording=%q err=%v", raw, err)
				}
				if reason != endReasonNormal {
					want := apierror.CodeSessionIdleTimeout
					if reason == endReasonMaxDuration {
						want = apierror.CodeSessionMaxDuration
					}
					found := false
					for _, m := range messages {
						if m.Code == string(want) {
							found = true
						}
					}
					if !found {
						t.Fatalf("missing timeout code %s: %+v", want, messages)
					}
				}
				select {
				case <-conn.closed:
				default:
					t.Fatal("target not closed")
				}
			})
		}
	}
}
