package sshproxy

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sensitivescan"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

type sensitiveScanner interface {
	Write([]byte) []sensitivescan.Match
	Flush() []sensitivescan.Match
}

// sensitiveTap owns a bounded asynchronous side channel. It never mutates or
// waits for target output. Overflow disables scanning, rather than concatenating
// nonadjacent frames. Recorder/monitor and the client retain original bytes.
type sensitiveTap struct {
	mu         sync.Mutex
	closed     bool
	overflow   bool
	queue      chan []byte
	done       chan struct{}
	scanner    sensitiveScanner
	alerts     *audit.OutputAlerts
	sessionID  uint
	onDisabled func()
}

func newSensitiveTap(m *audit.AlertMatcher, sess *model.Session, protocol string, sink gatewayapi.AlertSink, auditLog *audit.AuditLogService, subjectKind string) *sensitiveTap {
	if m == nil || sess == nil {
		return nil
	}
	rules := m.OutputRules(protocol, subjectKind)
	if len(rules) == 0 {
		return nil
	}
	compiled, err := sensitivescan.Compile(rules, protocol)
	if err != nil {
		log.Printf("[SensitiveTap] compile failed session=%d", sess.ID)
		return nil
	}
	switch protocol {
	case "ssh", "k8s", "mysql", "postgres", "mssql", "redis":
	default:
		return nil
	}
	return startSensitiveTap(sensitivescan.NewStreamScanner(compiled), audit.NewOutputAlerts(*sess, rules, sink), sess.ID, outputScanDisabledAudit(auditLog, *sess))
}

func startSensitiveTap(scanner sensitiveScanner, alerts *audit.OutputAlerts, sessionID uint, onDisabled func()) *sensitiveTap {
	t := &sensitiveTap{queue: make(chan []byte, 64), done: make(chan struct{}), scanner: scanner, alerts: alerts, sessionID: sessionID, onDisabled: onDisabled}
	go t.run()
	return t
}

func (t *sensitiveTap) WriteOutput(p []byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	for len(p) > 0 {
		n := len(p)
		if n > 4096 {
			n = 4096
		}
		chunk := append([]byte(nil), p[:n]...)
		select {
		case t.queue <- chunk:
			p = p[n:]
		default:
			t.closed = true
			t.overflow = true
			close(t.queue)
			log.Printf("[SensitiveTap] queue overflow; scanning disabled session=%d", t.sessionID)
			return
		}
	}
}

func (t *sensitiveTap) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.queue)
	}
	t.mu.Unlock()
	<-t.done
}

func (t *sensitiveTap) run() {
	defer close(t.done)
	defer func() {
		t.mu.Lock()
		overflow := t.overflow
		t.mu.Unlock()
		if overflow && t.onDisabled != nil {
			t.onDisabled()
		}
	}()
	defer func() {
		if recover() != nil {
			// Panic values may contain output; never log the recovered object.
			log.Printf("[SensitiveTap] scanner panic; scanning disabled session=%d", t.sessionID)
			t.mu.Lock()
			if !t.closed {
				t.closed = true
				close(t.queue)
			}
			t.mu.Unlock()
		}
	}()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	report := func(err error) {
		if err != nil {
			log.Printf("[SensitiveTap] alert write failed session=%d", t.sessionID)
		}
	}
	for {
		select {
		case p, ok := <-t.queue:
			t.mu.Lock()
			overflow := t.overflow
			t.mu.Unlock()
			if !ok || overflow {
				if !overflow {
					report(t.alerts.Add(t.scanner.Flush(), time.Now()))
				}
				report(t.alerts.Flush(time.Now(), true))
				return
			}
			report(t.alerts.Add(t.scanner.Write(p), time.Now()))
		case now := <-tick.C:
			report(t.alerts.Flush(now, false))
		}
	}
}

// Console result values are already parsed text; do not scan JSON wire encoding
// or echoed statements. Cell boundaries prevent joining unrelated numbers.
func (s *consoleSession) scanSensitiveResult(v any) {
	if s.sensitive == nil {
		return
	}
	switch msg := v.(type) {
	case consoleResultMessage:
		for _, set := range msg.Sets {
			for _, row := range set.Rows {
				for _, cell := range row {
					if cell != nil {
						s.sensitive.WriteOutput([]byte(*cell + "\n"))
					}
				}
			}
		}
	}
}

// Called once by the scanner worker after overflow; never blocks terminal output.
// The existing audit service owns persistence, integrity stamping and forwarding.
func outputScanDisabledAudit(service *audit.AuditLogService, sess model.Session) func() {
	return func() {
		if service == nil {
			log.Printf("[SensitiveTap] disabled audit unavailable session=%d", sess.ID)
			return
		}
		id := sess.ID
		service.Log(&audit.AuditLogEntry{
			UserID: sess.UserID, Action: model.ActionOutputScanDisabled,
			Resource: model.ResourceSession, ResourceID: &id, AssetID: sess.AssetID,
			Status:  model.StatusFailure,
			Details: fmt.Sprintf(`{"session_id":%d,"reason":"queue_overflow"}`, sess.ID),
		})
	}
}
