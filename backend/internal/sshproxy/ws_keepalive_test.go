package sshproxy

import (
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/gorilla/websocket"
)

func shortWSKeepalive(t *testing.T) {
	t.Helper()
	oldPing, oldRead := wsKeepalivePingInterval, wsKeepaliveReadTimeout
	wsKeepalivePingInterval, wsKeepaliveReadTimeout = 20*time.Millisecond, 90*time.Millisecond
	t.Cleanup(func() { wsKeepalivePingInterval, wsKeepaliveReadTimeout = oldPing, oldRead })
}

func readUntilClosed(ws *websocket.Conn) (<-chan struct{}, <-chan struct{}) {
	done := make(chan struct{})
	pingSeen := make(chan struct{}, 1)
	ws.SetPingHandler(func(data string) error {
		select {
		case pingSeen <- struct{}{}:
		default:
		}
		return ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	go func() {
		defer close(done)
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return done, pingSeen
}

func TestBridgeWSKeepaliveClosesHalfOpenAndSettlesSession(t *testing.T) {
	shortWSKeepalive(t)
	h, db, _ := setupPolicyGateTest(t)
	h.SessionService = session.NewSessionService(nil)
	h.Registry = proxy.NewConnectionRegistry()
	sess := &model.Session{UserID: 1, Protocol: model.ProtocolSSH, Status: model.SessionStatusActive, StartTime: time.Now()}
	if err := db.Create(sess).Error; err != nil {
		t.Fatal(err)
	}
	server, client := newWSPair(t)
	defer client.Close()
	b := newBridge(server, newFakeTerminalConn(), sess, h.SessionService, h.RecordingPath, 1, 1)
	h.Registry.Register(sess.ID, b.terminate)
	done := make(chan struct{})
	go func() {
		b.Run()
		h.Registry.Unregister(sess.ID)
		h.closeSession(sess, b.EndReason())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		b.stop()
		t.Fatal("half-open bridge remained active after read deadline")
	}
	var got model.Session
	if err := db.First(&got, sess.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status == model.SessionStatusActive || h.Registry.Has(sess.ID) {
		t.Fatalf("half-open bridge not settled: status=%s registered=%v", got.Status, h.Registry.Has(sess.ID))
	}
}

func TestBridgeWSKeepalivePongPreventsFalseClose(t *testing.T) {
	shortWSKeepalive(t)
	server, client := newWSPair(t)
	b := newBridge(server, newFakeTerminalConn(), nil, nil, "", 0, 0)
	done := make(chan struct{})
	go func() { b.Run(); close(done) }()
	peerDone, pingSeen := readUntilClosed(client)
	select {
	case <-pingSeen:
	case <-time.After(time.Second):
		b.stop()
		t.Fatal("bridge did not send a WebSocket ping")
	}
	select {
	case <-done:
		t.Fatal("responsive bridge client was closed before two read deadlines")
	case <-time.After(230 * time.Millisecond):
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		b.stop()
		t.Fatal("bridge did not close after client closed")
	}
	<-peerDone
}

func TestConsoleWSKeepaliveClosesHalfOpenAndSettlesSession(t *testing.T) {
	shortWSKeepalive(t)
	f := newConsoleFixture(t, &stubDialect{currentDB: "app"})
	server, client := newWSPair(t)
	defer client.Close()
	f.s.ws = server
	done := make(chan struct{})
	go func() { f.env.h.runConsoleSession(f.s, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		server.Close()
		<-done
		t.Fatal("half-open console remained active after read deadline")
	}
	var got model.Session
	if err := f.env.db.First(&got, f.s.sess.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status == model.SessionStatusActive || f.env.h.Registry.Has(got.ID) {
		t.Fatalf("half-open console not settled: status=%s registered=%v", got.Status, f.env.h.Registry.Has(got.ID))
	}
}

func TestConsoleWSKeepalivePongPreventsFalseClose(t *testing.T) {
	shortWSKeepalive(t)
	f := newConsoleFixture(t, &stubDialect{currentDB: "app"})
	server, client := newWSPair(t)
	f.s.ws = server
	done := make(chan struct{})
	go func() { f.env.h.runConsoleSession(f.s, nil); close(done) }()
	peerDone, pingSeen := readUntilClosed(client)
	select {
	case <-pingSeen:
	case <-time.After(time.Second):
		server.Close()
		t.Fatal("console did not send a WebSocket ping")
	}
	select {
	case <-done:
		t.Fatal("responsive console client was closed before two read deadlines")
	case <-time.After(230 * time.Millisecond):
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		server.Close()
		t.Fatal("console did not close after client closed")
	}
	<-peerDone
}

func TestWSKeepalivePingWriteFailureClosesTransport(t *testing.T) {
	shortWSKeepalive(t)
	server, client := newWSPair(t)
	defer client.Close()
	done := make(chan struct{})
	defer close(done)
	failed := make(chan struct{})
	var mu sync.Mutex
	startWSKeepalive(server, &mu, done, func() { close(failed) })
	server.Close()
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("failed WebSocket ping did not trigger the close callback")
	}
}
