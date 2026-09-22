package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"time"
)

// ProbeBreakerDependencies keeps principal, authorization and grant ownership in
// their modules; all DB callbacks participate in this transaction.
type ProbeBreakerDependencies struct {
	LockPrincipal func(*gorm.DB, uint) (uint, error)
	Classify      func(*gorm.DB, uint, uint) (string, error)
	Trip          func(*gorm.DB, uint, uint, time.Time) (bool, error)
	Finish        func(uint)
	Limits        func() (int, int)
	Notify        OwnerEventWriter
}
type ProbeBreaker struct {
	db     *gorm.DB
	sink   port.TxSink
	alerts txAlertSink
	deps   ProbeBreakerDependencies
	now    func() time.Time
}

func NewProbeBreaker(db *gorm.DB, sink port.TxSink, alerts gatewayapi.AlertSink, deps ProbeBreakerDependencies) *ProbeBreaker {
	txAlerts, _ := alerts.(txAlertSink)
	return &ProbeBreaker{db: db, sink: sink, alerts: txAlerts, deps: deps, now: time.Now}
}

type ProbeBreakerResult struct {
	Class   string
	Count   int64
	Tripped bool
}

func (s *ProbeBreaker) RecordDenied(ctx context.Context, userID, tokenID, assetID uint, endpoint string) (ProbeBreakerResult, error) {
	var result ProbeBreakerResult
	var ownerID uint
	var alert model.CommandAlert
	if s.deps.LockPrincipal == nil || s.deps.Classify == nil || s.deps.Trip == nil || s.deps.Finish == nil || s.deps.Limits == nil || s.deps.Notify == nil || s.alerts == nil {
		return result, errors.New("probe breaker dependencies unavailable")
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		ownerID, err = s.deps.LockPrincipal(tx, userID)
		if err != nil {
			return err
		}
		result.Class, err = s.deps.Classify(tx, userID, assetID)
		if err != nil {
			return err
		}
		if result.Class != "never_visible" && result.Class != "revoked" && result.Class != "retired" {
			return errors.New("invalid probe class")
		}
		at := s.now().UTC().Truncate(time.Microsecond)
		event := model.AgentProbeEvent{UserID: userID, AgentTokenID: tokenID, AssetRef: assetID, Endpoint: endpoint, Class: result.Class, CreatedAt: at}
		if err := tx.Create(&event).Error; err != nil {
			return err
		}
		details, _ := json.Marshal(map[string]any{"event": "agent_probe_denied", "probe_id": event.ID, "user_id": userID, "agent_token_id": tokenID, "asset_ref": assetID, "class": result.Class, "endpoint": endpoint})
		if err := port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: gatewayapi.Actor{UserID: userID}, Action: string(model.ActionRead), Resource: string(model.ResourceAsset), ResourceID: &assetID, AssetID: &assetID, Status: string(model.StatusFailure), Details: string(details)}); err != nil {
			return err
		}
		threshold, window := s.deps.Limits()
		if threshold < 1 || window < 1 {
			return errors.New("invalid probe policy")
		}
		// Database aggregate under the principal lock: retries and parallel instances
		// share one distinct set. No in-process counter can multiply the threshold.
		if err := tx.Model(&model.AgentProbeEvent{}).Where("user_id=? AND class=? AND created_at>=? AND created_at<=?", userID, "never_visible", at.Add(-time.Duration(window)*time.Second), at).Distinct("asset_ref").Count(&result.Count).Error; err != nil {
			return err
		}
		if result.Class != "never_visible" || result.Count < int64(threshold) {
			return nil
		}
		result.Tripped, err = s.deps.Trip(tx, userID, tokenID, at)
		if err != nil || !result.Tripped {
			return err
		}
		alert, err = s.alerts.RecordAlertInTx(tx, gatewayapi.CommandAlert{Kind: model.AlertKindAgentBreaker, RuleName: model.AlertKindAgentBreaker, ReasonCode: "RULE_AGENT_BREAKER_TRIPPED", Actor: gatewayapi.Actor{UserID: userID}, AssetID: &assetID, Command: "", Level: "high", OccurredAt: at, Disposition: model.AlertDispositionPending, Blocked: true})
		if err != nil {
			return err
		}
		details, _ = json.Marshal(map[string]any{"event": "agent_breaker_tripped", "user_id": userID, "owner_id": ownerID, "agent_token_id": tokenID, "alert_id": alert.ID, "distinct_count": result.Count})
		return port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: gatewayapi.Actor{Username: "system"}, Action: string(model.ActionSuspend), Resource: string(model.ResourceAgentToken), ResourceID: &tokenID, Status: string(model.StatusSuccess), Details: string(details)})
	})
	if err != nil {
		return ProbeBreakerResult{}, err
	}
	if result.Tripped {
		s.deps.Finish(tokenID)
		s.alerts.PublishCommitted([]model.CommandAlert{alert})
		s.deps.Notify(ownerID, notifycat.EventAgentBreakerTripped, map[string]string{"owner_id": fmt.Sprint(ownerID), "user_id": fmt.Sprint(userID), "token_id": fmt.Sprint(tokenID)})
	}
	return result, nil
}
