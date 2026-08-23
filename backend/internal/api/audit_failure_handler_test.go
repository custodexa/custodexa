package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// TestToFailureEventItems 失效事件回應形狀：
// cause_code 為權威表述、cause_params 以物件而非「JSON 裡的 JSON」出口、
// 壞資料不得讓整份列表失敗
func TestToFailureEventItems(t *testing.T) {
	rows := []model.AuditFailureEvent{
		{
			ID: 1, Mechanism: model.MechanismRecordingText, StartedAt: time.Now(),
			Cause:       "寫入錄製事件失敗：no space left",
			CauseCode:   model.CauseRecordingWriteFailed,
			CauseParams: `{"detail":"no space left","session_id":"7"}`,
		},
		{ID: 2, Mechanism: model.MechanismAuditWrite, StartedAt: time.Now(),
			CauseCode: model.CauseAuditWriteBatchDropped, CauseParams: ""},
		{ID: 3, Mechanism: model.MechanismSyslogForward, StartedAt: time.Now(),
			CauseCode: model.CauseSyslogConnectFailed, CauseParams: "not-json{"},
	}

	items := toFailureEventItems(rows)
	if len(items) != 3 {
		t.Fatalf("items 數量 = %d, want 3", len(items))
	}

	raw, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		CauseCode   string            `json:"cause_code"`
		Cause       string            `json:"cause"`
		CauseParams map[string]string `json:"cause_params"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, raw)
	}
	if got.CauseCode != model.CauseRecordingWriteFailed {
		t.Errorf("cause_code = %q", got.CauseCode)
	}
	if got.CauseParams["session_id"] != "7" || got.CauseParams["detail"] != "no space left" {
		t.Errorf("cause_params 應為已解碼物件, got %v", got.CauseParams)
	}
	if got.Cause == "" {
		t.Error("cause 散文 fallback 應保留（既有讀取點不白屏）")
	}

	// 空字串與壞 JSON 一律退空物件，不吞整份列表
	if items[1].CauseParams == nil || len(items[1].CauseParams) != 0 {
		t.Errorf("空 cause_params 應為空物件, got %v", items[1].CauseParams)
	}
	if items[2].CauseParams == nil || len(items[2].CauseParams) != 0 {
		t.Errorf("壞 JSON 應退空物件, got %v", items[2].CauseParams)
	}
}
