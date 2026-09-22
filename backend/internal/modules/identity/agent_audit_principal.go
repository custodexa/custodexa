package identity

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

func ReadAgentAuditPrincipal(tx *gorm.DB, id uint) (audit.AgentPrincipalFacts, error) {
	var user model.User
	if err := tx.First(&user, id).Error; err != nil {
		return audit.AgentPrincipalFacts{}, err
	}
	facts := audit.AgentPrincipalFacts{Kind: user.Kind}
	if user.OwnerUserID != nil {
		facts.OwnerID = *user.OwnerUserID
	}
	return facts, nil
}
