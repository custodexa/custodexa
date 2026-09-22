package identity

import (
	"context"
	"encoding/json"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// Identity owns the reads; audit owns canonical encoding and comparison.
func SnapshotPrincipalStates(ctx context.Context, tx *gorm.DB) ([]audit.PrincipalState, error) {
	var users []model.User
	if err := tx.WithContext(ctx).Select("id", "kind", "owner_user_id").Find(&users).Error; err != nil {
		return nil, err
	}
	out := make([]audit.PrincipalState, 0, len(users))
	for _, u := range users {
		p := audit.PrincipalState{ID: uint64(u.ID), Kind: u.Kind}
		if u.OwnerUserID != nil {
			owner := uint64(*u.OwnerUserID)
			p.OwnerID = &owner
		}
		out = append(out, p)
	}
	return out, nil
}
func SnapshotAgentTokenStates(ctx context.Context, tx *gorm.DB) ([]audit.AgentTokenState, error) {
	var tokens []model.AgentToken
	if err := tx.WithContext(ctx).Select("id", "user_id", "revoked_at", "suspended_at", "token_hash", "expires_at").Find(&tokens).Error; err != nil {
		return nil, err
	}
	out := make([]audit.AgentTokenState, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, audit.AgentTokenState{ID: uint64(token.ID), UserID: uint64(token.UserID), Revoked: token.RevokedAt != nil, Suspended: token.SuspendedAt != nil, Fingerprint: audit.CredentialFingerprint(token.TokenHash), ExpiresAt: token.ExpiresAt})
	}
	return out, nil
}

// recordPrincipalState is authoritative projection evidence. HTTP activity rows
// remain separate; only this marker participates in state replay.
func recordPrincipalState(tx *gorm.DB, user *model.User, action model.AuditAction) error {
	details, err := json.Marshal(map[string]any{"state_table": audit.StateTablePrincipals, "user_id": user.ID, "kind": user.Kind, "owner_user_id": user.OwnerUserID})
	if err != nil {
		return err
	}
	return port.WriteInTx(audit.NewTxSink(), tx, port.AuditEvent{Actor: gatewayapi.Actor{Username: "system"}, Action: string(action), Resource: string(model.ResourceUser), ResourceID: &user.ID, Status: string(model.StatusSuccess), Details: string(details)})
}
