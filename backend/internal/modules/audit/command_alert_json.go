package audit

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
)

// An embedded model's MarshalJSON must not swallow the view's joined columns.
func (v CommandAlertView) MarshalJSON() ([]byte, error) {
	type row model.CommandAlert
	type view struct {
		row
		Username  string `json:"username"`
		AssetName string `json:"asset_name"`
		ClientIP  string `json:"client_ip,omitempty"`
	}
	plain := view{row(v.CommandAlert), v.Username, v.AssetName, v.ClientIP}
	if v.Kind == model.AlertKindAgentBreaker && v.SessionID == 0 {
		return json.Marshal(struct {
			view
			SessionID *uint `json:"session_id"`
		}{view: plain})
	}
	return json.Marshal(plain)
}
