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
	// TokenName 交易內讀 agent token 的名稱（給通知用；可為 nil，nil 時通知不帶 token 名稱）
	TokenName func(*gorm.DB, uint) string
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
		if err := port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: gatewayapi.Actor{Username: "system"}, Action: string(model.ActionSuspend), Resource: string(model.ResourceAgentToken), ResourceID: &tokenID, Status: string(model.StatusSuccess), Details: string(details)}); err != nil {
			return err
		}
		// 熔斷、探測紀錄、告警列與通知內容同交易（savepoint）：通知寫不進去只回到 savepoint，
		// 熔斷照常生效，下一次被拒的探測不需重新累積
		tokenName := ""
		if s.deps.TokenName != nil {
			tokenName = s.deps.TokenName(tx, tokenID)
		}
		s.deps.Notify(tx, agentBreakerNotice(ownerID, userID, tokenID, assetID, result.Count, window, tokenName))
		return nil
	})
	if err != nil {
		return ProbeBreakerResult{}, err
	}
	if result.Tripped {
		s.deps.Finish(tokenID)
		s.alerts.PublishCommitted([]model.CommandAlert{alert})
	}
	return result, nil
}

// agentBreakerNotice 熔斷的通知事實：agent、負責人、資產以識別碼參照交給分派解析；token 名稱由產生點帶入。
func agentBreakerNotice(ownerID, userID, tokenID, assetID uint, count int64, windowSeconds int, tokenName string) AgentOwnerNotice {
	params := map[string]string{
		"user_id": fmt.Sprint(userID), "token_id": fmt.Sprint(tokenID), "distinct_count": fmt.Sprint(count),
	}
	if m := agentWindowMinutesParam(windowSeconds); m != "" {
		params["window_minutes"] = m
	}
	refs := map[string]NotificationNameRef{
		"agent_name": {Kind: notifycat.IDKindUser, ID: userID},
		"owner_name": {Kind: notifycat.IDKindUser, ID: ownerID},
	}
	if assetID != 0 {
		refs["asset_name"] = NotificationNameRef{Kind: notifycat.IDKindAsset, ID: assetID}
	}
	return AgentOwnerNotice{OwnerID: ownerID, Event: notifycat.EventAgentBreakerTripped, Params: params,
		NameRefs: refs, Names: map[string]string{"token_name": tokenName}}
}
