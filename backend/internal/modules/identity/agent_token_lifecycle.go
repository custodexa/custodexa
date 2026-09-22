package identity

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// AgentSessionTermination records actual close outcomes independently of token
// invalidation. Durations are audit evidence, not a promised public deadline.
type AgentSessionTermination struct {
	TerminatedIDs []uint
	FailedIDs     []uint
	Late          map[uint]time.Duration
}

type AgentSessionTerminator interface {
	TerminateByAgentToken(tokenID uint, reason string) (AgentSessionTermination, error)
}

func (s *AgentTokenService) SetSessionTerminator(t AgentSessionTerminator)    { s.terminator = t }
func (s *UserService) SetAgentTokenService(tokens *AgentTokenService)         { s.agentTokens = tokens }
func (s *OIDCProviderService) SetAgentTokenService(tokens *AgentTokenService) { s.agentTokens = tokens }

func (s *AgentTokenService) recordLifecycle(tx *gorm.DB, tokenID uint, action model.AuditAction, actor gatewayapi.Actor, details map[string]any, status model.AuditStatus) error {
	data, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return port.WriteInTx(s.sink, tx, port.AuditEvent{Actor: actor, Action: string(action), Resource: string(model.ResourceAgentToken), ResourceID: &tokenID, Status: string(status), Details: string(data)})
}
func (s *AgentTokenService) finishTermination(tokenID uint, actor gatewayapi.Actor) {
	if s.terminator == nil {
		return
	} // State-only callers run inside credential transactions.
	result, err := s.terminator.TerminateByAgentToken(tokenID, model.EndReasonAdminTerminate)
	if len(result.TerminatedIDs) == 0 && len(result.FailedIDs) == 0 && len(result.Late) == 0 && err == nil {
		return
	}
	// This transaction is AFTER invalidation committed. Audit/close failure cannot
	// resurrect the credential. Failures retain machine reasons and session IDs.
	auditErr := s.db.Transaction(func(tx *gorm.DB) error {
		status := model.StatusSuccess
		details := map[string]any{"terminated_session_ids": result.TerminatedIDs, "failed_session_ids": result.FailedIDs}
		if err != nil || len(result.FailedIDs) > 0 {
			status = model.StatusFailure
			details["reason"] = "session_termination_failed"
		}
		if e := s.recordLifecycle(tx, tokenID, model.ActionAgentSessionsTerminated, actor, details, status); e != nil {
			return e
		}
		for id, elapsed := range result.Late {
			if e := s.recordLifecycle(tx, tokenID, model.ActionAgentSessionsTerminateLate, actor, map[string]any{"session_id": id, "elapsed_seconds": elapsed.Seconds()}, model.StatusFailure); e != nil {
				return e
			}
		}
		return nil
	})
	if auditErr != nil {
		log.Printf("[AgentToken] termination audit failed token_id=%d: %v", tokenID, auditErr)
	}
	if err != nil {
		log.Printf("[AgentToken] termination query failed token_id=%d: %v", tokenID, err)
	}
}

// invalidateUserAccess runs outside the owner/agent write transaction. Token
// state is suspended before any physical I/O, then every token is attempted.
func (s *AgentTokenService) invalidateUserAccess(userID uint, reason string) error {
	var agents []uint
	if err := s.db.Unscoped().Model(&model.User{}).Where("kind = ? AND (id = ? OR owner_user_id = ?)", model.KindAgent, userID, userID).Pluck("id", &agents).Error; err != nil {
		return err
	}
	if len(agents) == 0 {
		return nil
	}
	var tokens []model.AgentToken
	if err := s.db.Where("user_id IN ?", agents).Order("id").Find(&tokens).Error; err != nil {
		return err
	}
	var failures []error
	for _, token := range tokens {
		if token.RevokedAt == nil {
			if err := s.Suspend(token.UserID, token.ID, reason, gatewayapi.Actor{Username: "system"}); err != nil {
				failures = append(failures, err)
			}
		} else {
			s.finishTermination(token.ID, gatewayapi.Actor{Username: "system"})
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("停用 %d 把 token 失敗: %w", len(failures), failures[0])
	}
	return nil
}

// Provider invalidation must not advance the human user's credential_epoch:
// local-password sessions remain independent of an external provider. Suspend
// owned tokens in the provider transaction, then close them after commit.
func (s *AgentTokenService) suspendProviderOwnersInTx(tx *gorm.DB, providerID uint) ([]uint, error) {
	var ownerIDs []uint
	// No agent owners means no additional identity-table dependency for old fixtures.
	if err := tx.Model(&model.User{}).Where("kind = ?", model.KindAgent).Distinct().Pluck("owner_user_id", &ownerIDs).Error; err != nil {
		return nil, err
	}
	if len(ownerIDs) == 0 {
		return nil, nil
	}
	var affected []uint
	if err := tx.Model(&model.UserExternalIdentity{}).Where("provider_id = ? AND user_id IN ?", providerID, ownerIDs).Distinct().Pluck("user_id", &affected).Error; err != nil {
		return nil, err
	}
	for _, id := range affected {
		if err := s.suspendOwnedInTx(tx, id); err != nil {
			return nil, err
		}
	}
	return affected, nil
}

func (s *AuthService) SetAgentTokenService(tokens *AgentTokenService) { s.agentTokens = tokens }

// Called after credential-epoch transactions; never invalidates a newly issued token.
func (s *AgentTokenService) finishSuspendedOwner(ownerID uint) {
	var ids []uint
	err := s.db.Model(&model.AgentToken{}).Select("agent_tokens.id").Joins("JOIN users ON users.id = agent_tokens.user_id").Where("users.owner_user_id = ? AND agent_tokens.suspended_at IS NOT NULL", ownerID).Order("agent_tokens.id").Pluck("agent_tokens.id", &ids).Error
	if err != nil {
		log.Printf("[AgentToken] suspended token lookup owner_id=%d: %v", ownerID, err)
		return
	}
	for _, id := range ids {
		s.finishTermination(id, gatewayapi.Actor{Username: "system"})
	}
}
