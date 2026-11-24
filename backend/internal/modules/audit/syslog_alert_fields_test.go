package audit

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// syslog 轉發的指令告警欄位快照（規則告警與機器欄位不變的 syslog 部分）：
// 欄位名與值固定，降級告警的 rule_name 是機器碼 audit_degraded_span、kind 與 reason_code 照帶。
func TestSyslogAlertFieldsSnapshot(t *testing.T) {
	f := NewSyslogForwarder(nil)
	f.setting = model.SyslogSetting{Enabled: true, Host: "test"}
	asset := uint(7)
	at := time.Date(2026, 11, 20, 1, 2, 3, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		alert model.CommandAlert
		want  map[string]any
	}{
		{"規則告警", model.CommandAlert{ID: 11, TriggeredAt: at, UserID: 3, SessionID: 31, AssetID: &asset, RuleName: "rm-root",
			Severity: "high", Command: "rm -rf /", Kind: model.AlertKindRule},
			map[string]any{"id": float64(11), "triggered_at": "2026-11-20T01:02:03Z", "user_id": float64(3), "session_id": float64(31),
				"asset_id": float64(7), "rule_name": "rm-root", "severity": "high", "command": "rm -rf /", "kind": "rule", "reason_code": ""}},
		{"降級告警", model.CommandAlert{ID: 12, TriggeredAt: at, UserID: 1, SessionID: 40, RuleName: model.AlertReasonDegradedSpan,
			Severity: "medium", Kind: model.AlertKindAuditDegraded, ReasonCode: model.AlertReasonDegradedSpan},
			map[string]any{"id": float64(12), "triggered_at": "2026-11-20T01:02:03Z", "user_id": float64(1), "session_id": float64(40),
				"asset_id": nil, "rule_name": "audit_degraded_span", "severity": "medium", "command": "", "kind": "audit_degraded",
				"reason_code": "audit_degraded_span"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.alert
			f.EnqueueAlert(&a)
			select {
			case msg := <-f.ch:
				var got map[string]any
				if err := json.Unmarshal(msg.payload, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, tc.want) || msg.msgID != "alert" {
					t.Fatalf("syslog 欄位快照不符:\n得 %v\n應 %v", got, tc.want)
				}
			default:
				t.Fatal("syslog 未入列")
			}
		})
	}
}
