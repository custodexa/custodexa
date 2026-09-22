package database

import (
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"testing"
	"time"
)

func TestAgentBreakerAlertPostgres(t *testing.T) {
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), fmt.Sprintf("w32_alert_%d", time.Now().UnixNano()))
	for _, m := range migrations {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	for _, kind := range []string{model.AlertKindNewSourceIP, model.AlertKindAgentBreaker} {
		a := model.CommandAlert{RuleName: kind, Kind: kind, ReasonCode: "fixture", UserID: 1, Severity: "high", TriggeredAt: time.Now(), Disposition: model.AlertDispositionPending}
		err := db.Create(&a).Error
		if kind == model.AlertKindNewSourceIP {
			if err == nil {
				t.Fatal("non-breaker accepted null session")
			}
			a.SessionID = 19
			if err = db.Create(&a).Error; err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		var saved model.CommandAlert
		if err := db.First(&saved, a.ID).Error; err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(saved)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		json.Unmarshal(raw, &obj)
		if kind == model.AlertKindAgentBreaker {
			if obj["session_id"] != nil {
				t.Fatal(string(raw))
			}
		} else if obj["session_id"] != float64(19) {
			t.Fatal(string(raw))
		}
	}
	if err := rollbackAgentBreakerAlert(db); err == nil {
		t.Fatal("Down must explicitly refuse evidence destruction")
	}
}
