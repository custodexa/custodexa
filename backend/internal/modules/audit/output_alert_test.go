package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sensitivescan"
)

func TestOutputAlertNoPlaintextAndExistingTee(t *testing.T) {
	_, db := setupAlertDB(t)
	notifier := NewAlertNotifier(db, nil)
	forwarder := NewSyslogForwarder(db)
	forwarder.setting = model.SyslogSetting{Enabled: true, Host: "test"}
	alertNotifierMu.Lock()
	oldN := alertNotifierInstance
	alertNotifierInstance = notifier
	alertNotifierMu.Unlock()
	syslogForwarderMu.Lock()
	oldF := syslogForwarderInstance
	syslogForwarderInstance = forwarder
	syslogForwarderMu.Unlock()
	defer func() {
		alertNotifierMu.Lock()
		alertNotifierInstance = oldN
		alertNotifierMu.Unlock()
		syslogForwarderMu.Lock()
		syslogForwarderInstance = oldF
		syslogForwarderMu.Unlock()
	}()
	rules := []model.AlertRule{{ID: 1, Name: "card", Pattern: sensitivescan.CardPattern, Direction: "output", Enabled: true, Severity: "high"}}
	compiled, err := sensitivescan.Compile(rules, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	a := NewOutputAlerts(model.Session{ID: 9, UserID: 3}, rules, NewAlertRecorder(db))
	const card = "4111111111111111"
	now := time.Now()
	if err := a.Add(compiled.Scan(card+"\n"+card), now); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(now, true); err != nil {
		t.Fatal(err)
	}
	var rows []model.CommandAlert
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	row := rows[0]
	raw, _ := json.Marshal(row)
	if row.Command != "" || strings.Contains(string(raw), card) {
		t.Fatalf("plaintext in full row: %s", raw)
	}
	meta, ok := ParseOutputAlert(row.ReasonCode)
	if !ok || meta.Count != 2 {
		t.Fatalf("metadata: %+v", meta)
	}
	select {
	case msg := <-notifier.queue:
		payload, _ := json.Marshal(buildAlertPayload(msg, alertSubjectNames{}))
		if strings.Contains(string(payload), card) {
			t.Fatal("webhook leaks original")
		}
		if text := buildSlackText("en-US", alertEventCommandAlert, msg, alertSubjectNames{}); !strings.Contains(text, "may contain") || strings.Contains(text, card) {
			t.Fatalf("slack: %s", text)
		}
	default:
		t.Fatal("notification not enqueued")
	}
	select {
	case msg := <-forwarder.ch:
		if strings.Contains(string(msg.payload), card) || !strings.Contains(string(msg.payload), row.ReasonCode) {
			t.Fatal("syslog metadata/contents")
		}
	default:
		t.Fatal("syslog not enqueued")
	}
}

func TestAlertDedupWindow(t *testing.T) {
	sink := &recordingAlertSink{}
	rules := []model.AlertRule{{ID: 1, Name: "key", Severity: "high"}, {ID: 2, Name: "card", Severity: "high"}}
	a := NewOutputAlerts(model.Session{ID: 9}, rules, sink)
	now := time.Unix(100, 0)
	for i := 0; i < 30; i++ {
		if err := a.Add([]sensitivescan.Match{{RuleID: 1, Start: int64(i * 10), End: int64(i*10 + 5)}}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Flush(now.Add(OutputAlertWindow-time.Nanosecond), false); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 0 {
		t.Fatal("window emitted early")
	}
	if err := a.Flush(now.Add(OutputAlertWindow), false); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 1 {
		t.Fatalf("batches: %+v", sink.alerts)
	}
	meta, _ := ParseOutputAlert(sink.alerts[0].ReasonCode)
	if meta.Count != 30 {
		t.Fatalf("count=%d", meta.Count)
	}
	if err := a.Add([]sensitivescan.Match{{RuleID: 1, Start: 400, End: 416}, {RuleID: 2, Start: 500, End: 516}}, now.Add(OutputAlertWindow)); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(now, true); err != nil {
		t.Fatal(err)
	}
	if len(sink.alerts) != 3 {
		t.Fatalf("independent rule/windows=%d", len(sink.alerts))
	}
}
