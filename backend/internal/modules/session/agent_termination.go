package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TerminateByAgentToken shares Terminate's CAS, but reports physical-close
// failures instead of treating a disconnected database row as proof of closure.
func (s *SessionService) TerminateByAgentToken(tokenID uint, reason string) (identity.AgentSessionTermination, error) {
	result := identity.AgentSessionTermination{TerminatedIDs: []uint{}, FailedIDs: []uint{}, Late: map[uint]time.Duration{}}
	started := time.Now()
	var sessions []model.Session
	if err := database.DB.Where("agent_token_id = ? AND status = ?", tokenID, model.SessionStatusActive).Order("id").Find(&sessions).Error; err != nil {
		return result, fmt.Errorf("查詢 token 會話失敗: %w", err)
	}
	for _, sess := range sessions {
		err := s.terminateWithRevocation(sess.ID, reason, true, true)
		elapsed := time.Since(started)
		if elapsed > 3*time.Second {
			result.Late[sess.ID] = elapsed
		}
		if errors.Is(err, ErrSessionAlreadyClosed) {
			continue
		}
		if err != nil {
			result.FailedIDs = append(result.FailedIDs, sess.ID)
			continue
		}
		result.TerminatedIDs = append(result.TerminatedIDs, sess.ID)
	}
	return result, nil
}
