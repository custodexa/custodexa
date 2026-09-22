package identity

import "github.com/custodexa/backend/internal/model"

// fillAgentOwnerNames projects only current usernames in one bounded batch for the returned page.
func (s *UserService) fillAgentOwnerNames(users []model.User) error {
	ids := make([]uint, 0)
	seen := make(map[uint]bool)
	for i := range users {
		users[i].OwnerUsername = ""
		if users[i].Kind == model.KindAgent && users[i].OwnerUserID != nil && !seen[*users[i].OwnerUserID] {
			id := *users[i].OwnerUserID
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var owners []model.User
	if err := s.db.Select("id", "username").Where("id IN ?", ids).Find(&owners).Error; err != nil {
		return err
	}
	names := make(map[uint]string, len(owners))
	for _, owner := range owners {
		names[owner.ID] = owner.Username
	}
	for i := range users {
		if users[i].Kind == model.KindAgent && users[i].OwnerUserID != nil {
			users[i].OwnerUsername = names[*users[i].OwnerUserID]
		}
	}
	return nil
}
