package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 告警的來源位址：列表與 webhook payload 各一個可選欄，皆經 join sessions 帶出。
//
// 位址**不冗餘進 command_alerts**（session_id 是 NOT NULL，保證 join 得到），
// 故這兩個欄位的正確性取決於 join 有沒有接上——而 join 漏掉的症狀是欄位恆空，
// 不是錯誤。兩支測試因此都斷言「有值」而不只是「不炸」。

func TestCommandAlertListCarriesClientIP(t *testing.T) {
	db := setupTimelineDB(t)
	svc := NewCommandAlertService(db)
	ts := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)

	sess := &model.Session{SessionID: "alert-ip-1", Status: "closed", Protocol: "ssh",
		UserID: 7, ClientIP: "203.0.113.42", StartTime: ts}
	if err := db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := db.Exec(`INSERT INTO command_alerts (rule_id, rule_name, session_id, user_id,
		command, severity, triggered_at, kind, reason_code)
		VALUES (NULL, 'new_source_ip', ?, 7, '', 'medium', ?, 'new_source_ip', 'new_source_ip_session')`,
		sess.ID, ts).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	// 所屬會話缺失的舊告警：LEFT JOIN 之下仍要列得出來，只是少一個位址
	if err := db.Exec(`INSERT INTO command_alerts (rule_id, rule_name, session_id, user_id,
		command, severity, triggered_at, kind, reason_code)
		VALUES (1, 'rm-guard', 99999, 7, 'rm -rf /', 'high', ?, 'rule', '')`,
		ts.Add(time.Minute)).Error; err != nil {
		t.Fatalf("seed orphan alert: %v", err)
	}

	res, err := svc.List(&CommandAlertFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if res.Total != 2 || len(res.Data) != 2 {
		t.Fatalf("列表應 2 筆（含會話缺失那筆），實得 total=%d len=%d", res.Total, len(res.Data))
	}
	byKind := map[string]CommandAlertView{}
	for _, v := range res.Data {
		byKind[v.Kind] = v
	}
	if got := byKind[model.AlertKindNewSourceIP].ClientIP; got != "203.0.113.42" {
		t.Errorf("新來源位址告警的 client_ip = %q, want 203.0.113.42（join 未接上時此欄恆空）", got)
	}
	if got := byKind["rule"].ClientIP; got != "" {
		t.Errorf("會話缺失的告警 client_ip 應為空，實得 %q", got)
	}
	// 既有欄位零變動
	if byKind["rule"].Command != "rm -rf /" || byKind["rule"].Severity != "high" {
		t.Errorf("既有欄位受影響: %+v", byKind["rule"])
	}
}

func TestAlertWebhookPayloadCarriesClientIP(t *testing.T) {
	alert := model.CommandAlert{
		ID: 5, SessionID: 11, UserID: 7, Command: "", Severity: "medium",
		RuleName: model.AlertKindNewSourceIP, Kind: model.AlertKindNewSourceIP,
		ReasonCode: model.AlertReasonNewSourceIPSession,
		TriggeredAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}
	names := alertSubjectNames{User: "alice", ClientIP: "203.0.113.42"}

	raw, err := json.Marshal(buildAlertPayload(alert, names))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Event   string                 `json:"event"`
		Alert   map[string]any         `json:"alert"`
		Session map[string]any         `json:"session"`
		Extra   map[string]any         `json:"-"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Session["client_ip"] != "203.0.113.42" {
		t.Errorf("payload session.client_ip = %v, want 203.0.113.42", got.Session["client_ip"])
	}
	// 既有欄位集合不變（純加法：收端不需改動即可繼續解析）
	for _, k := range []string{"id", "user_id", "asset_id", "username"} {
		if _, ok := got.Session[k]; !ok {
			t.Errorf("payload session 缺既有欄位 %q（純加法被破壞）", k)
		}
	}
	for _, k := range []string{"id", "command", "severity", "rule_name", "kind", "reason_code", "triggered_at"} {
		if _, ok := got.Alert[k]; !ok {
			t.Errorf("payload alert 缺既有欄位 %q", k)
		}
	}

	// 位址查不到時整個欄位不出現，而非送出空字串
	raw2, err := json.Marshal(buildAlertPayload(alert, alertSubjectNames{User: "alice"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got2 struct {
		Session map[string]any `json:"session"`
	}
	if err := json.Unmarshal(raw2, &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got2.Session["client_ip"]; ok {
		t.Errorf("位址查不到時不應出現 client_ip 鍵，實得 %v", got2.Session["client_ip"])
	}
}
