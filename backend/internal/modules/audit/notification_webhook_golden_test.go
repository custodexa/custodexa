package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
)

// 既有 webhook 欄位與 Slack 文字的黃金檔。
//
// 黃金檔由新增 notification 物件之前的程式產生（NDL_GOLDEN_UPDATE=1 時寫檔）。比對時去掉頂層的
// notification 物件、把隨機的投遞識別換成固定字樣，其餘逐欄相同；Slack 文字整段相同。

const goldenDir = "testdata/notification_golden"

var goldenDeliveryID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// normalizeGoldenBody 去掉 notification 物件並固定投遞識別；JSON 以縮排重排方便審視 diff。
func normalizeGoldenBody(t *testing.T, raw []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("本文不是 JSON: %v (%s)", err, raw)
	}
	delete(m, "notification")
	if v, ok := m["delivery_id"].(string); ok && goldenDeliveryID.MatchString(v) {
		m["delivery_id"] = "<delivery_id>"
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

type goldenSample struct {
	name  string
	setup func(e *ndlEnv)
}

// goldenSamples 黃金檔必須涵蓋的樣本：帶會話脈絡的規則告警、新來源位址告警、指令稽核降級告警（有無降級情境行）、
// 敏感內容存取告警、輸出含疑似敏感內容告警、系統安全告警、帶投票數的系統事件。
func goldenSamples() []goldenSample {
	asset := uint(7)
	return []goldenSample{
		{"rule_alert", func(e *ndlEnv) {
			e.db.Exec(`INSERT INTO users (id, username) VALUES (3, 'alice')`)
			e.db.Exec(`INSERT INTO assets (id, name) VALUES (7, 'db-prod-01')`)
			e.db.Exec(`INSERT INTO sessions (id, client_ip) VALUES (31, '203.0.113.7')`)
			a := model.CommandAlert{RuleName: "rm-root", Command: "rm -rf / && echo <x>", Severity: model.AlertSeverityHigh,
				SessionID: 31, UserID: 3, AssetID: &asset, TriggeredAt: e.clock.now(), Disposition: "pending",
				Kind: model.AlertKindRule, Blocked: true}
			e.db.Create(&a)
			e.enqueueAlert(a)
		}},
		{"new_source_ip", func(e *ndlEnv) {
			e.db.Exec(`INSERT INTO users (id, username) VALUES (3, 'alice')`)
			e.db.Exec(`INSERT INTO sessions (id, client_ip) VALUES (31, '203.0.113.7')`)
			a := model.CommandAlert{RuleName: string(model.AlertKindNewSourceIP), Severity: model.AlertSeverityMedium, SessionID: 31,
				UserID: 3, TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindNewSourceIP}
			e.db.Create(&a)
			e.enqueueAlert(a)
		}},
		{"audit_degraded_with_reason", func(e *ndlEnv) {
			at := e.clock.now()
			e.db.Exec(`INSERT INTO session_commands (session_id, degraded, executed_at, degrade_reason) VALUES (40, 1, ?, ?)`, at, model.DegradeAltScreen)
			a := model.CommandAlert{RuleName: model.AlertReasonDegradedSpan, Severity: model.AlertSeverityMedium, SessionID: 40, UserID: 1,
				TriggeredAt: at, Disposition: "pending", Kind: model.AlertKindAuditDegraded, ReasonCode: model.AlertReasonDegradedSpan}
			e.db.Create(&a)
			e.enqueueAlert(a)
		}},
		{"audit_degraded_without_reason", func(e *ndlEnv) {
			a := model.CommandAlert{RuleName: model.AlertReasonDegradedSpan, Severity: model.AlertSeverityMedium, SessionID: 41, UserID: 1,
				TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindAuditDegraded, ReasonCode: model.AlertReasonDegradedSpan}
			e.db.Create(&a)
			e.enqueueAlert(a)
		}},
		{"sensitive_reveal", func(e *ndlEnv) {
			e.db.Exec(`INSERT INTO users (id, username) VALUES (3, 'alice')`)
			a := model.CommandAlert{RuleName: string(model.AlertKindSensitiveReveal), Severity: model.AlertSeverityMedium, SessionID: 31,
				UserID: 3, TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindSensitiveReveal}
			e.db.Create(&a)
			e.enqueueAlert(a)
		}},
		{"possible_sensitive_output", func(e *ndlEnv) {
			a := model.CommandAlert{RuleName: "output-rule", Command: "cat /etc/shadow", Severity: model.AlertSeverityHigh, SessionID: 31,
				UserID: 3, TriggeredAt: e.clock.now(), Disposition: "pending", Kind: model.AlertKindRule, ReasonCode: OutputAlertPrefix + "3"}
			e.db.Create(&a)
			e.enqueueAlert(a)
		}},
		{"system_event_votes", func(e *ndlEnv) {
			e.enqueueEvent(notifycat.EventAccessRequestApprovalProgress, map[string]string{
				"request_id": "12", "votes": "1", "required": "2", "asset_name": "db-prod-01", "requester_name": "alice", "decider_name": "bob"})
		}},
	}
}

// captureGolden 跑一個樣本：webhook 與 slack 各一個通道，回傳兩者收到的第一則本文。
func captureGolden(t *testing.T, s goldenSample) (hookBody, slackBody []byte) {
	t.Helper()
	e := newNDLEnv(t)
	hook := newStubSrv(t, e.clock, nil)
	slack := newStubSrv(t, e.clock, nil)
	e.channel("hook", "webhook", hook.srv.URL, true, "low")
	e.channel("slack", model.NotificationChannelTypeSlack, slack.srv.URL, true, "low")
	s.setup(e)
	e.w.RunOnce()
	if hook.count() != 1 || slack.count() != 1 {
		t.Fatalf("%s: hook=%d slack=%d", s.name, hook.count(), slack.count())
	}
	return hook.body(0), slack.body(0)
}

// captureSystemAlertGolden 系統安全告警樣本（帶快照紀錄）。
func captureSystemAlertGolden(t *testing.T, chType string) []byte {
	t.Helper()
	e := newNDLEnv(t)
	srv := newStubSrv(t, e.clock, nil)
	ch := e.channel("c", chType, srv.srv.URL, true, "low")
	row := e.snapshotRow(ch.ID, srv.srv.URL, 0, 0)
	e.db.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).Update("dest_type", chType)
	e.w.RunOnce()
	if srv.count() != 1 {
		t.Fatalf("系統安全告警樣本 %s: 收到 %d", chType, srv.count())
	}
	return srv.body(0)
}

func goldenFiles(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, s := range goldenSamples() {
		h, sl := captureGolden(t, s)
		out[s.name+".webhook.json"] = normalizeGoldenBody(t, h)
		out[s.name+".slack.json"] = normalizeGoldenBody(t, sl)
	}
	out["system_security_alert.webhook.json"] = normalizeGoldenBody(t, captureSystemAlertGolden(t, model.NotificationChannelTypeWebhook))
	out["system_security_alert.slack.json"] = normalizeGoldenBody(t, captureSystemAlertGolden(t, model.NotificationChannelTypeSlack))
	return out
}

func TestWebhookExistingFieldsGolden(t *testing.T) {
	// 系統事件既有的 sent_at 以伺服器時區輸出（決策 14：既有欄位不改）；固定一個非 UTC 的時區，
	// 「改成 UTC」這類變動才看得出來。
	prevLocal := time.Local
	time.Local = time.FixedZone("UTC+8", 8*3600)
	t.Cleanup(func() { time.Local = prevLocal })
	files := goldenFiles(t)
	if os.Getenv("NDL_GOLDEN_UPDATE") == "1" {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(goldenDir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("已寫入 %d 個黃金檔", len(files))
		return
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		want, err := os.ReadFile(filepath.Join(goldenDir, name))
		if err != nil {
			t.Fatalf("缺黃金檔 %s: %v", name, err)
		}
		if !bytes.Equal(want, files[name]) {
			t.Errorf("%s 既有欄位與黃金檔不同\n--- 黃金檔\n%s\n--- 現在\n%s", name, want, files[name])
		}
	}
	// 樣本內容的自我檢查：黃金檔確實涵蓋 goldenSamples 列出的成分。
	mustContain := map[string][]string{
		"rule_alert.webhook.json":                {`"client_ip": "203.0.113.7"`, `"username": "alice"`, `"asset_name": "db-prod-01"`},
		"new_source_ip.webhook.json":             {`"client_ip": "203.0.113.7"`},
		"new_source_ip.slack.json":               {"203.0.113.7"},
		"audit_degraded_with_reason.slack.json":  {"全螢幕"},
		"possible_sensitive_output.webhook.json": {`"possible_sensitive_output"`},
		"system_event_votes.webhook.json":        {`"votes": "1"`},
		"system_security_alert.webhook.json":     {`"delivery_id": "\u003cdelivery_id\u003e"`},
	}
	for name, subs := range mustContain {
		for _, s := range subs {
			if !strings.Contains(string(files[name]), s) {
				t.Errorf("%s 應含 %q", name, s)
			}
		}
	}
	if strings.Contains(string(files["audit_degraded_without_reason.slack.json"]), "全螢幕") {
		t.Error("查不到降級原因時 Slack 文字不應有降級情境行")
	}
}
