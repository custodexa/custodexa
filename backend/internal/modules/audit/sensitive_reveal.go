package audit

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

type sensitiveRevealPolicy interface{ GetBool(string) bool }
type sensitiveRevealFailures interface {
	Report(string, string, map[string]string)
}

// SensitiveRevealInput intentionally has no content/command field. Only metadata
// from a successfully audited reveal may enter the additional alert channel.
type SensitiveRevealInput struct {
	Actor           gatewayapi.Actor
	SourceType      string
	SourceID        uint
	SessionID       uint
	AssetID         *uint
	AccessRequestID *uint
	Reason          string
	RequestID       string
}

type SensitiveRevealService struct {
	policy   sensitiveRevealPolicy
	alerts   gatewayapi.AlertSink
	failures sensitiveRevealFailures
}

func NewSensitiveRevealService(p sensitiveRevealPolicy, alerts gatewayapi.AlertSink, failures sensitiveRevealFailures) *SensitiveRevealService {
	return &SensitiveRevealService{policy: p, alerts: alerts, failures: failures}
}

// Report runs after the reveal audit commits and before content delivery. Alert
// storage errors are observable through the audit-failure chain, but cannot
// change the independently successful reveal audit into a delivery failure.
func (s *SensitiveRevealService) Report(ctx context.Context, in SensitiveRevealInput) {
	if !s.policy.GetBool(policy.PolicyAlertOnSensitiveReveal) {
		return
	}
	details := map[string]any{
		"source_type": in.SourceType, "source_id": in.SourceID,
		"session_id": in.SessionID, "user_id": in.Actor.UserID, "username": in.Actor.Username,
	}
	if in.AssetID != nil {
		details["asset_id"] = *in.AssetID
	}
	if in.AccessRequestID != nil {
		details["access_request_id"] = *in.AccessRequestID
	}
	if in.Reason != "" {
		details["reason"] = in.Reason
	}
	if in.RequestID != "" {
		details["request_id"] = in.RequestID
	}
	// All values above are strings/integers; marshaling cannot fail.
	note, _ := json.Marshal(details)
	err := gatewayapi.RecordAlert(ctx, s.alerts, gatewayapi.CommandAlert{
		Kind: model.AlertKindSensitiveReveal, RuleName: model.AlertKindSensitiveReveal,
		ReasonCode: model.AlertKindSensitiveReveal, Level: "medium", Command: "",
		SessionID: in.SessionID, Actor: in.Actor, AssetID: in.AssetID,
		OccurredAt: time.Now().UTC(), Disposition: model.AlertDispositionPending, Note: string(note),
	})
	if err != nil {
		log.Printf("[SensitiveReveal] alert write failed: source=%s id=%d err=%v", in.SourceType, in.SourceID, err)
		if s.failures != nil {
			s.failures.Report(model.MechanismAuditWrite, model.CauseSensitiveRevealAlertWriteFailed,
				map[string]string{"detail": err.Error(), "surface": "sensitive_reveal", "source_type": in.SourceType, "source_id": strconv.FormatUint(uint64(in.SourceID), 10)})
		}
	}
}
