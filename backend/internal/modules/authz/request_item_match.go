package authz

import (
	"errors"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

var (
	ErrRequestItemAsset  = errors.New("request item asset or principal mismatch")
	ErrRequestItemScope  = errors.New("request item account scope mismatch")
	ErrRequestItemWindow = errors.New("request item is inactive or outside its approved window")
)

// MatchRequestItem is the single source used by issuance and every redemption path.
// AssetAuthorizationService owns the authz DB connection; no global DB dependency.
func (s *AssetAuthorizationService) MatchRequestItem(requestID, userID, assetID uint, username string, at time.Time) (*model.AccessRequestItem, error) {
	var req model.AccessRequest
	if err := s.db.First(&req, requestID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRequestItemAsset
		}
		return nil, err
	}
	if executorIDValue(req.ExecutorUserID, req.RequesterID) != userID {
		return nil, ErrRequestItemAsset
	}
	var item model.AccessRequestItem
	if err := s.db.Where("request_id=? AND asset_id=?", requestID, assetID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRequestItemAsset
		}
		return nil, err
	}
	if req.ExecutorUserID != nil {
		// Same live visibility predicate as submission; no approved-time visibility snapshot.
		check := AccessRequestService{db: s.db, authzRepo: s.repo}
		visible, err := check.RequestItemVisible(req.RequesterID, req.ExecutorUserID, assetID)
		if err != nil {
			return nil, err
		}
		if !visible {
			return nil, ErrRequestItemAsset
		}
	}
	if req.ClosedAt != nil || item.Status != model.AccessRequestApproved || item.RevokedAt != nil || item.ApprovedDateStart == nil || item.ApprovedDurationMinutes == nil || at.Before(*item.ApprovedDateStart) || !at.Before(item.ApprovedDateStart.Add(time.Duration(*item.ApprovedDurationMinutes)*time.Minute)) {
		return nil, ErrRequestItemWindow
	}
	if item.AuthorizationID == nil {
		return nil, ErrRequestItemWindow
	}
	var grant model.AssetAuthorization
	if err := s.db.First(&grant, *item.AuthorizationID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRequestItemWindow
		}
		return nil, err
	}
	if grant.Source != model.AuthorizationSourceTicket || grant.UserID == nil || *grant.UserID != userID || grant.AssetID == nil || *grant.AssetID != assetID || grant.DateStart != nil && at.Before(*grant.DateStart) || grant.DateExpired != nil && !at.Before(*grant.DateExpired) {
		return nil, ErrRequestItemWindow
	}
	if !item.Accounts.Contains(username) || !grant.Accounts.Contains(username) {
		return nil, ErrRequestItemScope
	}
	return &item, nil
}
func (s *AssetAuthorizationService) RequestEnvelopeRequired(userID uint) (bool, error) {
	if s == nil {
		return false, errors.New("authorization service unavailable")
	}
	var user model.User
	if err := s.db.Select("id", "kind").First(&user, userID).Error; err != nil {
		return false, err
	}
	return user.Kind == model.KindAgent, nil
}
func (s *AssetAuthorizationService) latestTicketScope(userID, assetID uint, now time.Time) (EffectiveAccountScope, error) {
	var tickets []model.AssetAuthorization
	err := s.db.Where(subjectCondition+" AND permission=? AND "+nodeObjectCondition+" AND "+validityCondition+" AND source=?", userID, userID, model.PermissionConnect, assetID, assetID, now, now, model.AuthorizationSourceTicket).Order("created_at DESC,id DESC").Find(&tickets).Error
	if err != nil {
		return EffectiveAccountScope{}, err
	}
	result := EffectiveAccountScope{Usernames: map[string]bool{}}
	if len(tickets) == 0 {
		return result, nil
	}
	selected := tickets[0]
	if len(tickets) > 1 {
		ids := make([]uint, 0, len(tickets))
		byID := map[uint]model.AssetAuthorization{}
		for _, ticket := range tickets {
			ids = append(ids, ticket.ID)
			byID[ticket.ID] = ticket
		}
		var item model.AccessRequestItem
		err := s.db.Where("authorization_id IN ? AND status=? AND revoked_at IS NULL", ids, model.AccessRequestApproved).Order("decided_at DESC,id DESC").First(&item).Error
		if err == nil {
			selected = byID[*item.AuthorizationID]
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return result, err
		}
	}
	result.Matched = true
	result.All = selected.Accounts.IsAll()
	for _, name := range selected.Accounts {
		result.Usernames[name] = true
	}
	return result, nil
}
