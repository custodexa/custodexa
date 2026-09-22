package session

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// These selectors share the existing CAS and physical connection close path.
// Only successful terminations are returned as evidence; races/failures aren't claimed.
func (s *SessionService) terminateRequestSelection(q *gorm.DB, reason string) ([]uint, error) {
	var sessions []model.Session
	if err := q.Where("status=?", model.SessionStatusActive).Order("id").Find(&sessions).Error; err != nil {
		return nil, err
	}
	ids := []uint{}
	var failures []error
	for _, sess := range sessions {
		err := s.terminate(sess.ID, reason, true)
		if errors.Is(err, ErrSessionAlreadyClosed) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("session %d: %w", sess.ID, err))
			continue
		}
		ids = append(ids, sess.ID)
	}
	return ids, errors.Join(failures...)
}
func (s *SessionService) TerminateByUserAssetWithIDs(userID, assetID uint, reason string) ([]uint, error) {
	return s.terminateRequestSelection(database.DB.Where("user_id=? AND asset_id=?", userID, assetID), reason)
}
func (s *SessionService) TerminateByAccessRequest(requestID uint, reason string) ([]uint, error) {
	return s.terminateRequestSelection(database.DB.Where("access_request_id=?", requestID), reason)
}
