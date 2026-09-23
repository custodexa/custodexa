package identity

import "github.com/custodexa/backend/internal/model"

// fillTokenCreatorNames projects only current usernames in one bounded batch for the
// returned page. It takes the caller's query error first so the list path stays a single
// expression: a failed query leaves the page untouched and returns that error unchanged.
func (s *AgentTokenService) fillTokenCreatorNames(tokens []model.AgentToken, err error) error {
	if err != nil {
		return err
	}
	ids := make([]uint, 0, len(tokens))
	seen := make(map[uint]bool, len(tokens))
	for i := range tokens {
		tokens[i].CreatedByUsername = ""
		if id := tokens[i].CreatedBy; id != 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var users []model.User
	if err := s.db.Model(&model.User{}).Select("id", "username").Where("id IN ?", ids).Find(&users).Error; err != nil {
		return err
	}
	names := make(map[uint]string, len(users))
	for _, u := range users {
		names[u.ID] = u.Username
	}
	for i := range tokens {
		tokens[i].CreatedByUsername = names[tokens[i].CreatedBy]
	}
	return nil
}
