package session

import (
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// Only the persisted session owner ID determines attribution; never the agent's current owner.
func fillSessionOwnerNames(sessions []model.Session) error {
	ids := make([]uint, 0)
	seen := make(map[uint]bool)
	for i := range sessions {
		sessions[i].OwnerUsername = ""
		if sessions[i].ActorKind != nil && *sessions[i].ActorKind == model.KindAgent && sessions[i].OwnerUserID != nil && !seen[*sessions[i].OwnerUserID] {
			id := *sessions[i].OwnerUserID
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var owners []model.User
	if err := database.DB.Select("id", "username").Where("id IN ?", ids).Find(&owners).Error; err != nil {
		return err
	}
	names := make(map[uint]string, len(owners))
	for _, owner := range owners {
		names[owner.ID] = owner.Username
	}
	for i := range sessions {
		if sessions[i].ActorKind != nil && *sessions[i].ActorKind == model.KindAgent && sessions[i].OwnerUserID != nil {
			sessions[i].OwnerUsername = names[*sessions[i].OwnerUserID]
		}
	}
	return nil
}
