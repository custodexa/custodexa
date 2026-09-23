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
	deciders, err := s.deciderNames(reqs)
	if err != nil {
		return err
	}
	assets, err := s.assetLabels(reqs)
	if err != nil {
		return err
	}
	for _, r := range reqs {
		if p, ok := byID[executorIDValue(r.ExecutorUserID, r.RequesterID)]; ok {
			r.ExecutorInfo = &p
		}
		for i := range r.Items {
			item := &r.Items[i]
			item.DecidedByUsername = ""
			if item.DecidedBy != nil {
				item.DecidedByUsername = deciders[*item.DecidedBy]
			}
			item.FillRequestedAccounts()
			label := assets[item.AssetID]
			item.AssetName, item.AssetDeleted = label.Name, label.Deleted
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

// deciderNames resolves every item decider in one query; an automatic approval has no
// decider row and therefore no name.
func (s *AccessRequestService) deciderNames(reqs []*model.AccessRequest) (map[uint]string, error) {
	names := map[uint]string{}
	ids := make([]uint, 0)
	seen := map[uint]bool{}
	for _, r := range reqs {
		for i := range r.Items {
			id := r.Items[i].DecidedBy
			if id == nil || *id == 0 || seen[*id] {
				continue
			}
			seen[*id] = true
			ids = append(ids, *id)
		}
	}
	if len(ids) == 0 {
		return names, nil
	}
	var users []model.User
	if err := s.db.Model(&model.User{}).Select("id", "username").Where("id IN ?", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	for _, u := range users {
		names[u.ID] = u.Username
	}
	return names, nil
}

// assetLabel is the display half of an asset: the name a reviewer reads, plus whether the
// asset has since been soft-deleted.
type assetLabel struct {
	Name    string
	Deleted bool
}

// assetLabels resolves every item's asset name in one unscoped query, so a soft-deleted
// target still reads as a name rather than a bare id. Batched on purpose: the reviewer's
// queue must not turn into one asset fetch per item.
func (s *AccessRequestService) assetLabels(reqs []*model.AccessRequest) (map[uint]assetLabel, error) {
	labels := map[uint]assetLabel{}
	ids := make([]uint, 0)
	seen := map[uint]bool{}
	for _, r := range reqs {
		for i := range r.Items {
			id := r.Items[i].AssetID
			if id == 0 || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return labels, nil
	}
	var rows []struct {
		ID        uint
		Name      string
		DeletedAt *time.Time
	}
	if err := s.db.Unscoped().Model(&model.Asset{}).Select("id", "name", "deleted_at").Where("id IN ?", ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		labels[row.ID] = assetLabel{Name: row.Name, Deleted: row.DeletedAt != nil}
	}
	return labels, nil
}
