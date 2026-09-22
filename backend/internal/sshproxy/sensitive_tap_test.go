package sshproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type sensitiveCapture struct {
	rows []gatewayapi.CommandAlert
	err  error
}

func (s *sensitiveCapture) RecordAlert(_ context.Context, a gatewayapi.CommandAlert) error {
	s.rows = append(s.rows, a)
	return s.err
}
func (s *sensitiveCapture) RecordAlerts(ctx context.Context, as []gatewayapi.CommandAlert) error {
	for _, a := range as {
		if err := s.RecordAlert(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

type sensitivePanicScanner struct{}

func (sensitivePanicScanner) Write([]byte) []sensitivescan.Match {
	panic("private output must not appear in logs")
}
func (sensitivePanicScanner) Flush() []sensitivescan.Match { return nil }

type sensitiveReadConn struct {
	*fakeTerminalConn
	r *bytes.Reader
}

func (c *sensitiveReadConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func sensitiveRules() []model.AlertRule {
	return []model.AlertRule{{ID: 1, Name: "card", Pattern: sensitivescan.CardPattern, Direction: "output", Enabled: true, Severity: "high"}}
}

func testSensitiveTap(t *testing.T, sink *sensitiveCapture, protocol string) *sensitiveTap {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.AutoMigrate(&model.AlertRule{}); err != nil {
		t.Fatal(err)
	}
	rules := sensitiveRules()
	if err := db.Create(&rules).Error; err != nil {
		t.Fatal(err)
	}
	m := audit.NewAlertMatcher(db, sink)
	if err := m.LoadRules(); err != nil {
		t.Fatal(err)
	}
	return newSensitiveTap(m, &model.Session{ID: 9, UserID: 2}, protocol, sink, nil, gatewayapi.PrincipalKindUnknown)
}

func TestSensitiveTapOutputSinkEOFFlush(t *testing.T) {
	for _, protocol := range []string{"ssh", "k8s"} {
		t.Run(protocol, func(t *testing.T) {
			sink := &sensitiveCapture{}
			tap := testSensitiveTap(t, sink, protocol)
			runSensitiveBridge(t, tap, "4111111111111111")
			if len(sink.rows) != 1 {
				t.Fatalf("EOF hits=%d", len(sink.rows))
			}
			meta, ok := audit.ParseOutputAlert(sink.rows[0].ReasonCode)
			if !ok || meta.Count != 1 {
				t.Fatalf("EOF metadata %+v", meta)
			}
		})
	}
}

func runSensitiveBridge(t *testing.T, tap *sensitiveTap, output string) {
	t.Helper()
	server, client := newWSPair(t)
	conn := &sensitiveReadConn{newFakeTerminalConn(), bytes.NewReader([]byte(output))}
	var target TerminalConn = conn
	if _, ok := tap.scanner.(sensitivePanicScanner); ok {
		target = &sensitiveStagedConn{fakeTerminalConn: newFakeTerminalConn(), first: []byte("4111111111111111\n"), rest: []byte("still flowing"), wait: tap.done}
	}
	b := newBridge(server, target, nil, nil, "", 0, 0)
	evidence := &captureSink{}
	b.outputSinks = []outputSink{tap, evidence}
	done := make(chan struct{})
	go func() { defer close(done); b.pumpOutput() }()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := ""
	for len(got) < len(output) {
		_, raw, err := client.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type == MsgData {
			got += msg.Data
		}
	}
	if got != output {
		t.Fatalf("target bytes changed: %q", got)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge failed to finish")
	}
	if evidence.String() != output {
		t.Fatal("recording/monitor bytes changed")
	}
}

func TestSensitiveTapFailureKeepsSessionOutput(t *testing.T) {
	t.Run("panic", func(t *testing.T) {
		sink := &sensitiveCapture{}
		tap := startSensitiveTap(sensitivePanicScanner{}, audit.NewOutputAlerts(model.Session{ID: 1}, sensitiveRules(), sink), 1, nil)
		runSensitiveBridge(t, tap, "4111111111111111\nstill flowing")
	})
	t.Run("sink_error", func(t *testing.T) {
		sink := &sensitiveCapture{err: errors.New("write failed")}
		tap := testSensitiveTap(t, sink, "ssh")
		runSensitiveBridge(t, tap, "4111111111111111\nstill flowing")
	})
}

func TestSensitiveTapConsoleParsedOutput(t *testing.T) {
	sink := &sensitiveCapture{}
	tap := testSensitiveTap(t, sink, "postgres")
	s := &consoleSession{sensitive: tap, out: make(chan []byte, 2)}
	card := "4111111111111111"
	s.send(consoleResultMessage{Type: consoleMsgResult, Sets: []dbconsole.ResultSet{{Rows: [][]*string{{&card}}}}})
	tap.Close()
	if len(sink.rows) != 1 {
		t.Fatalf("console output hits=%d", len(sink.rows))
	}
	raw := <-s.out
	var msg consoleResultMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	if *msg.Sets[0].Rows[0][0] != card {
		t.Fatal("console evidence changed")
	}
	for _, p := range []string{"rdp", "vnc"} {
		if testSensitiveTap(t, &sensitiveCapture{}, p) != nil {
			t.Fatal("graphical protocol scanned")
		}
	}
}

type sensitiveStagedConn struct {
	*fakeTerminalConn
	first, rest []byte
	wait        <-chan struct{}
	stage       int
}

func (c *sensitiveStagedConn) Read(p []byte) (int, error) {
	switch c.stage {
	case 0:
		c.stage++
		return copy(p, c.first), nil
	case 1:
		<-c.wait
		c.stage++
		return copy(p, c.rest), nil
	default:
		return 0, io.EOF
	}
}

// Hold the first scan while filling the bounded queue, so overflow is deterministic.
type sensitiveHeldScanner struct {
	entered, release chan struct{}
	calls            int
}

func (s *sensitiveHeldScanner) Write([]byte) []sensitivescan.Match {
	s.calls++
	if s.calls == 1 {
		close(s.entered)
		<-s.release
	}
	return nil
}
func (s *sensitiveHeldScanner) Flush() []sensitivescan.Match { return nil }

func TestSensitiveTapOverflowAudit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	defer sqlDB.Close()
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = db
	defer func() { database.DB = old }()
	service := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	defer service.Shutdown(context.Background())
	sess := model.Session{ID: 91, UserID: 7}
	scanner := &sensitiveHeldScanner{entered: make(chan struct{}), release: make(chan struct{})}
	tap := startSensitiveTap(scanner, audit.NewOutputAlerts(sess, sensitiveRules(), &sensitiveCapture{}), sess.ID, outputScanDisabledAudit(service, sess))
	tap.WriteOutput([]byte("first"))
	<-scanner.entered
	tap.WriteOutput(bytes.Repeat([]byte("x"), 65*4096))
	tap.WriteOutput([]byte("4111111111111111"))
	close(scanner.release)
	tap.Close()
	tap.WriteOutput([]byte("later"))
	var rows []model.AuditLog
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Action != model.ActionOutputScanDisabled || rows[0].ResourceID == nil || *rows[0].ResourceID != sess.ID || rows[0].Details != `{"session_id":91,"reason":"queue_overflow"}` {
		t.Fatalf("overflow audit rows=%+v", rows)
	}
	if scanner.calls != 1 {
		t.Fatalf("scans after overflow: %d", scanner.calls)
	}
	raw, _ := json.Marshal(rows)
	if bytes.Contains(raw, []byte("4111111111111111")) {
		t.Fatal("audit retained output")
	}
}
