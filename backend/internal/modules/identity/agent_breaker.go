package identity

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"strings"
	"time"
)

// LockProbePrincipal serializes all probe counting and token issuance using the
// same user row. The lock is database-owned and works across server processes.
func LockProbePrincipal(tx *gorm.DB, userID uint) (uint, error) {
	var user model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, userID).Error; err != nil {
		return 0, err
	}
	if user.Kind != model.KindAgent || user.OwnerUserID == nil {
		return 0, ErrAgentOwnerRequired
	}
	return *user.OwnerUserID, nil
}

// TripProbeBreakerInTx preserves credential projection auditing via changeState.
func (s *AgentTokenService) TripProbeBreakerInTx(tx *gorm.DB, userID, tokenID uint, at time.Time) (bool, error) {
	var token model.AgentToken
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("user_id=?", userID).First(&token, tokenID).Error; err != nil {
		return false, err
	}
	if token.SuspendedAt != nil || token.RevokedAt != nil {
		return false, nil
	}
	if err := tx.Model(&model.User{}).Where("id=? AND breaker_pending_at IS NULL", userID).Update("breaker_pending_at", at).Error; err != nil {
		return false, err
	}
	if err := s.changeState(tx, userID, tokenID, "agent_breaker_tripped", gatewayapi.Actor{Username: "system"}, true); err != nil {
		return false, err
	}
	return true, nil
}
func (s *AgentTokenService) FinishProbeBreaker(tokenID uint) {
	s.finishTermination(tokenID, gatewayapi.Actor{Username: "system"})
}
func (s *AgentTokenService) ReleaseProbeBreaker(userID uint, reason, role string, actor gatewayapi.Actor) error {
	if strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		return &PrincipalError{Code: apierror.CodeBadParams, Status: 400}
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var user, caller model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, userID).Error; err != nil {
			return err
		}
		if err := tx.First(&caller, actor.UserID).Error; err != nil {
			return err
		}
		if caller.Kind != model.KindHuman || user.Kind != model.KindAgent || user.OwnerUserID == nil || (role != model.RoleAdmin && *user.OwnerUserID != actor.UserID) {
			return &PrincipalError{Code: apierror.CodePermissionDenied, Status: 403}
		}
		if user.BreakerPendingAt == nil {
			return &PrincipalError{Code: apierror.CodeConflictAgentBreakerNotPending, Status: 409}
		}
		if err := tx.Model(&user).Where("breaker_pending_at IS NOT NULL").Update("breaker_pending_at", nil).Error; err != nil {
			return err
		}
		details, err := json.Marshal(map[string]any{"event": "agent_breaker_released", "user_id": userID, "owner_id": *user.OwnerUserID, "reason": reason})
		if err != nil {
			return err
		}
		return port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: actor, Action: string(model.ActionUpdate), Resource: string(model.ResourceUser), ResourceID: &userID, Status: string(model.StatusSuccess), Details: string(details)})
	})
}
