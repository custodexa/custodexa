package session

import (
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// Only the persisted session owner and delegator IDs determine attribution; never the
// agent's current owner. Both names resolve in one bounded batch for the page.
func fillSessionOwnerNames(sessions []model.Session) error {
	ids := make([]uint, 0)
	seen := make(map[uint]bool)
	collect := func(id *uint) {
		if id == nil || seen[*id] {
			return
		}
		seen[*id] = true
		ids = append(ids, *id)
	}
	for i := range sessions {
		sessions[i].OwnerUsername = ""
		sessions[i].OnBehalfOfUsername = ""
		if sessions[i].ActorKind != nil && *sessions[i].ActorKind == model.KindAgent {
			collect(sessions[i].OwnerUserID)
			collect(sessions[i].OnBehalfOfUserID)
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
		if sessions[i].ActorKind == nil || *sessions[i].ActorKind != model.KindAgent {
			continue
		}
		if sessions[i].OwnerUserID != nil {
			sessions[i].OwnerUsername = names[*sessions[i].OwnerUserID]
		}
		if sessions[i].OnBehalfOfUserID != nil {
			sessions[i].OnBehalfOfUsername = names[*sessions[i].OnBehalfOfUserID]
		}
	}
	return nil
}
