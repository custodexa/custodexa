package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

// BindAgentSessionPrincipal snapshots the live owner, and serializes with token invalidation.
func BindAgentSessionPrincipal(tx *gorm.DB, sess *model.Session) error {
	var user, owner model.User
	if err := tx.First(&user, sess.UserID).Error; err != nil {
		return err
	}
	if user.Kind != model.KindAgent || !user.Active || user.OwnerUserID == nil || sess.AgentTokenID == nil {
		return errors.New("invalid agent session principal")
	}
	if err := tx.First(&owner, *user.OwnerUserID).Error; err != nil {
		return err
	}
	if !owner.Active {
		return errors.New("inactive agent owner")
	}
	var token model.AgentToken
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("user_id=?", user.ID).First(&token, *sess.AgentTokenID).Error; err != nil {
		return err
	}
	if token.RevokedAt != nil || token.SuspendedAt != nil || !token.ExpiresAt.After(time.Now()) {
		return errors.New("inactive agent token")
	}
	kind := model.KindAgent
	ownerID := owner.ID
	sess.AgentTokenName = &token.Name // Creation-time snapshot; never re-read by response handlers.
	sess.ActorKind = &kind
	sess.OwnerUserID = &ownerID
	return nil
}
