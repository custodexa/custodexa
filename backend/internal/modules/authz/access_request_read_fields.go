package authz

import (
	"time"

	"github.com/custodexa/backend/internal/model"
)

// attachReadFields adds only display projections after the existing scope query.
// Bounds are request ceilings, not an authorization to decide an item.
func (s *AccessRequestService) attachReadFields(reqs []*model.AccessRequest, now time.Time) error {
	if len(reqs) == 0 {
		return nil
	}
	ids := make([]uint, 0, len(reqs))
	for _, r := range reqs {
		ids = append(ids, executorIDValue(r.ExecutorUserID, r.RequesterID))
	}
	var principals []model.AccessRequestExecutor
	if err := s.db.Table("users u").Select("u.id, u.username, u.kind, u.owner_user_id, COALESCE(owner.username, '') AS owner_username").Joins("LEFT JOIN users owner ON owner.id = u.owner_user_id").Where("u.id IN ?", ids).Scan(&principals).Error; err != nil {
		return err
	}
	byID := map[uint]model.AccessRequestExecutor{}
	for _, p := range principals {
		byID[p.ID] = p
	}
	for _, r := range reqs {
		if p, ok := byID[executorIDValue(r.ExecutorUserID, r.RequesterID)]; ok {
			r.ExecutorInfo = &p
		}
		for i := range r.Items {
			item := &r.Items[i]
			duration, start, accounts, err := decisionValues(r, item, DecideInput{}, now)
			if err != nil {
				return err
			}
			// Preserve @ALL as the existing closed-scope sentinel, never pretend it is a named account.
			item.DecisionBounds = &model.AccessRequestDecisionBounds{MaxDuration: duration, EarliestStart: start, Accounts: accounts}
		}
	}
	return nil
}
