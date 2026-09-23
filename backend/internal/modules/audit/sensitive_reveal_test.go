package audit

import (
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

func TestSensitiveRevealAlertKindFilter(t *testing.T) {
	svc, db := setupAlertDB(t)
	rule := seedAlert(t, db, "ordinary command")
	if err := db.Model(rule).Update("kind", model.AlertKindRule).Error; err != nil {
		t.Fatal(err)
	}
	err := gatewayapi.RecordAlert(context.Background(), NewAlertRecorder(db), gatewayapi.CommandAlert{
		Kind: model.AlertKindSensitiveReveal, RuleName: model.AlertKindSensitiveReveal,
		ReasonCode: model.AlertKindSensitiveReveal, Level: "medium", SessionID: 1,
		Actor: gatewayapi.Actor{UserID: 9}, OccurredAt: time.Now(),
		Disposition: model.AlertDispositionPending, Note: `{"source_type":"clipboard_event","source_id":5}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[string]int64{"": 2, model.AlertKindSensitiveReveal: 1, model.AlertKindRule: 1, "unknown": 0, "' OR 1=1 --": 0} {
		result, err := svc.List(&CommandAlertFilter{Kind: kind})
		if err != nil {
			t.Fatalf("kind=%q: %v", kind, err)
		}
		if result.Total != want || int64(len(result.Data)) != want {
			t.Fatalf("kind=%q total=%d rows=%d want=%d", kind, result.Total, len(result.Data), want)
		}
		if kind == model.AlertKindSensitiveReveal && (result.Data[0].Command != "" || result.Data[0].Note == "" || result.Data[0].UserID != 9) {
			t.Fatalf("reveal list lost metadata: %+v", result.Data[0])
		}
	}
}
