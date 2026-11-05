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

type allowReveal struct{}

func (allowReveal) GetBool(string) bool { return true }

// 揭露告警的來源碼：鍵盤紀錄寫 keystroke_record，其餘來源維持 kind，前端依此分句。
func TestSensitiveRevealReasonCodeBySource(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{"keystroke_record", model.AlertReasonKeystrokeReveal},
		{"clipboard_event", model.AlertKindSensitiveReveal},
	} {
		_, db := setupAlertDB(t)
		svc := NewSensitiveRevealService(allowReveal{}, NewAlertRecorder(db), nil)
		svc.Report(context.Background(), SensitiveRevealInput{
			Actor: gatewayapi.Actor{UserID: 9}, SourceType: tc.source, SourceID: 5, SessionID: 1,
		})
		var row model.CommandAlert
		if err := db.Where("kind = ?", model.AlertKindSensitiveReveal).First(&row).Error; err != nil {
			t.Fatalf("%s: %v", tc.source, err)
		}
		if row.ReasonCode != tc.want || row.Kind != model.AlertKindSensitiveReveal {
			t.Errorf("%s: kind=%q reason_code=%q want %q", tc.source, row.Kind, row.ReasonCode, tc.want)
		}
	}
}
