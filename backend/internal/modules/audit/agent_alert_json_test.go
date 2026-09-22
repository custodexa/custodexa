package audit

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
	"reflect"
	"testing"
)

func TestBreakerAlertJSONCompatibility(t *testing.T) {
	type originalRow model.CommandAlert
	type originalView struct {
		originalRow
		Username  string `json:"username"`
		AssetName string `json:"asset_name"`
		ClientIP  string `json:"client_ip,omitempty"`
	}
	v := CommandAlertView{CommandAlert: model.CommandAlert{ID: 7, SessionID: 19, Kind: model.AlertKindNewSourceIP, UserID: 2}, Username: "agent", AssetName: "fixture", ClientIP: "192.0.2.4"}
	old, _ := json.Marshal(originalView{originalRow(v.CommandAlert), v.Username, v.AssetName, v.ClientIP})
	current, _ := json.Marshal(v)
	var a, b map[string]any
	json.Unmarshal(old, &a)
	json.Unmarshal(current, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal(string(old), string(current))
	}
	v.Kind = model.AlertKindAgentBreaker
	v.SessionID = 0
	current, _ = json.Marshal(v)
	json.Unmarshal(current, &b)
	if b["session_id"] != nil || b["username"] != "agent" || b["asset_name"] != "fixture" {
		t.Fatal(string(current))
	}
}
