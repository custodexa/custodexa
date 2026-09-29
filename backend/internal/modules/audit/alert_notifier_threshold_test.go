package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// thresholdSink records which alert severities a single webhook endpoint received.
type thresholdSink struct {
	mu  sync.Mutex
	got []string
}

func newThresholdSink(t *testing.T) (*thresholdSink, string) {
	t.Helper()
	s := &thresholdSink{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Alert struct {
				Severity string `json:"severity"`
			} `json:"alert"`
		}
		_ = json.Unmarshal(body, &payload)
		s.mu.Lock()
		s.got = append(s.got, payload.Alert.Severity)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return s, server.URL
}

func (s *thresholdSink) severities() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.got...)
	sort.Strings(out)
	return out
}

// TestNotifySeverityThreshold pins both directions of the per-channel push threshold:
// a channel set to "high" must not receive medium/low alerts, yet it must still
// receive high alerts and alerts whose severity is empty or unknown (those cannot
// be classified, and the two credential-rotation alerts have push as their only exit).
func TestNotifySeverityThreshold(t *testing.T) {
	highOnly, highURL := newThresholdSink(t)
	mediumUp, mediumURL := newThresholdSink(t)
	all, allURL := newThresholdSink(t)
	unset, unsetURL := newThresholdSink(t)

	n := newTestNotifier()
	n.setChannels([]model.NotificationChannel{
		{ID: 1, Name: "p1", Type: model.NotificationChannelTypeWebhook, URL: highURL, Enabled: true, MinSeverity: model.AlertSeverityHigh},
		{ID: 2, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: mediumURL, Enabled: true, MinSeverity: model.AlertSeverityMedium},
		{ID: 3, Name: "siem", Type: model.NotificationChannelTypeWebhook, URL: allURL, Enabled: true, MinSeverity: model.AlertSeverityLow},
		// Rows that bypassed the DB default (unit fixtures) behave as "all alerts".
		{ID: 4, Name: "legacy", Type: model.NotificationChannelTypeWebhook, URL: unsetURL, Enabled: true},
	})

	for i, sev := range []string{model.AlertSeverityHigh, model.AlertSeverityMedium, model.AlertSeverityLow, "", "critical"} {
		alert := sampleAlert()
		alert.ID = uint(100 + i)
		alert.Severity = sev
		n.notify(alert)
	}

	want := map[string][]string{
		"p1":     {"", "critical", "high"},
		"ops":    {"", "critical", "high", "medium"},
		"siem":   {"", "critical", "high", "low", "medium"},
		"legacy": {"", "critical", "high", "low", "medium"},
	}
	got := map[string][]string{
		"p1": highOnly.severities(), "ops": mediumUp.severities(),
		"siem": all.severities(), "legacy": unset.severities(),
	}
	for name, w := range want {
		if len(got[name]) != len(w) {
			t.Errorf("channel %s received %v, want %v", name, got[name], w)
			continue
		}
		for i := range w {
			if got[name][i] != w[i] {
				t.Errorf("channel %s received %v, want %v", name, got[name], w)
				break
			}
		}
	}
}

// TestNotifyThresholdSparesEventsAndTestSend: the threshold applies to the alert queue
// only. System events carry no severity and the test send is how an admin checks the
// channel, so a "high only" channel still receives both.
func TestNotifyThresholdSparesEventsAndTestSend(t *testing.T) {
	url, received := captureOne(t)
	ch := model.NotificationChannel{ID: 1, Name: "p1", Type: model.NotificationChannelTypeWebhook,
		URL: url, Enabled: true, MinSeverity: model.AlertSeverityHigh}

	n := newTestNotifier()
	n.setChannels([]model.NotificationChannel{ch})
	n.NotifyEvent(notifycat.EventDailyReviewOverdue, map[string]string{"date": "2026-09-29"})

	var event notifyEventPayload
	if err := json.Unmarshal(awaitBody(t, received), &event); err != nil {
		t.Fatalf("event payload: %v", err)
	}
	if event.Event != string(notifycat.EventDailyReviewOverdue) {
		t.Fatalf("event = %q, want daily_review_overdue", event.Event)
	}

	status, err := SendTestNotification(&ch)
	if err != nil || status != http.StatusOK {
		t.Fatalf("test send to a high-only channel: status=%d err=%v", status, err)
	}
	var test map[string]any
	if err := json.Unmarshal(awaitBody(t, received), &test); err != nil {
		t.Fatalf("test payload: %v", err)
	}
	if test["event"] != "test" {
		t.Fatalf("test payload event = %v, want test", test["event"])
	}
}
