package session

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"time"
)

// SetAgentActorSource binds identity and task-owned snapshots inside the creation transaction.
func (s *SessionService) SetAgentActorSource(source func(*gorm.DB, *model.Session) error) {
	s.agentActorSource = source
}
func (s *SessionService) SetAuditSink(sink port.TxSink) { s.auditSink = sink }

func (s *SessionService) recordRevoked(tx *gorm.DB, sess *model.Session, reason string, at time.Time) error {
	// Older standalone session callers may omit audit injection; production wiring
	// supplies it unconditionally. New agent sessions must never lose this event.
	if s.auditSink == nil {
		if sess.ActorKind != nil && *sess.ActorKind == model.KindAgent {
			return port.ErrTxSinkMissing
		}
		return nil
	}
	data, err := json.Marshal(map[string]any{"event": "revoked_during_session", "session_id": sess.ID, "reason": reason, "revoked_during_session_at": at.UTC(), "agent_token_id": sess.AgentTokenID, "access_request_id": sess.AccessRequestID})
	if err != nil {
		return err
	}
	return port.WriteInTx(s.auditSink, tx, port.AuditEvent{Actor: gatewayapi.Actor{Username: "system"}, Action: string(model.ActionRevoke), Resource: string(model.ResourceSession), ResourceID: &sess.ID, AssetID: sess.AssetID, Status: string(model.StatusSuccess), Details: string(data)})
}
