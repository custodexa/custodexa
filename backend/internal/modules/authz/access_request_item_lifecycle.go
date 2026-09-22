package authz

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// Optional extension preserves the existing count-only consumer interface.
// Both methods use SessionService's existing terminate/CAS/physical-close path.
type requestSessionTerminator interface {
	TerminateByUserAssetWithIDs(userID, assetID uint, reason string) ([]uint, error)
	TerminateByAccessRequest(requestID uint, reason string) ([]uint, error)
}

func (s *AccessRequestService) closeRequestInTx(tx *gorm.DB, req *model.AccessRequest, now time.Time) (bool, error) {
	if req.ClosedAt != nil {
		return false, nil
	}
	items, err := requestItems(tx, req)
	if err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	hadGrant := false
	for _, item := range items {
		if item.Status == model.AccessRequestPending {
			return false, nil
		}
		if item.AuthorizationID != nil {
			hadGrant = true
		}
		if item.Status == model.AccessRequestApproved && (item.ApprovedDateStart == nil || item.ApprovedDurationMinutes == nil || item.ApprovedDateStart.Add(time.Duration(*item.ApprovedDurationMinutes)*time.Minute).After(now)) {
			return false, nil
		}
	}
	if !hadGrant {
		return false, nil
	}
	result := tx.Model(req).Where("closed_at IS NULL").Update("closed_at", now)
	return result.RowsAffected == 1, result.Error
}
func (s *AccessRequestService) closeRequestSessions(requestID uint) []uint {
	if sessions, ok := s.sessions.(requestSessionTerminator); ok {
		ids, err := sessions.TerminateByAccessRequest(requestID, model.EndReasonRevoked)
		if err != nil {
			log.Printf("[AccessRequest] task close sessions failed request=%d: %v", requestID, err)
		}
		return ids
	}
	return nil
}
func (s *AccessRequestService) revokeAssetSessions(req *model.AccessRequest, assetID uint) []uint {
	if s.sessions == nil {
		return nil
	}
	executor := executorIDValue(req.ExecutorUserID, req.RequesterID)
	var user model.User
	err := s.db.Select("id", "kind").First(&user, executor).Error
	// An unreadable principal must not suppress required termination.
	if err == nil && user.Kind != model.KindAgent && !s.policies.GetBool(policy.PolicyAccessRevokeDisconnect) {
		return nil
	}
	if sessions, ok := s.sessions.(requestSessionTerminator); ok {
		ids, err := sessions.TerminateByUserAssetWithIDs(executor, assetID, model.EndReasonRevoked)
		if err != nil {
			log.Printf("[AccessRequest] revoke sessions failed: %v", err)
		}
		return ids
	}
	_, err = s.sessions.TerminateByUserAsset(executor, assetID, model.EndReasonRevoked)
	if err != nil {
		log.Printf("[AccessRequest] revoke sessions failed: %v", err)
	}
	return nil
}
func (s *AccessRequestService) RevokeItem(actorID uint, isAdmin bool, username string, requestID, itemID uint, note string) (*model.AccessRequest, error) {
	if note == "" {
		return nil, ErrDecisionNoteRequired
	}
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	closed := false
	var revoked []model.AccessRequestItem
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.lockRequest(tx, req, now, false); err != nil {
			return err
		}
		items, err := requestItems(tx, req)
		if err != nil {
			return err
		}
		for i := range items {
			item := &items[i]
			if itemID != 0 && item.ID != itemID {
				continue
			}
			if item.Status != model.AccessRequestApproved || item.AuthorizationID == nil {
				continue
			}
			if !isAdmin {
				if item.DecidedBy != nil {
					if *item.DecidedBy != actorID {
						return ErrNotRevokeEligible
					}
				} else {
					covered, e := s.authzRepo.ApproverScopeCoversRequestTx(tx, actorID, item.AssetID, req.RequesterID)
					if e != nil {
						return e
					}
					if !covered {
						return ErrNotRevokeEligible
					}
				}
			}
			var ticket model.AssetAuthorization
			if err := tx.First(&ticket, *item.AuthorizationID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					continue
				}
				return err
			}
			if ticket.DateExpired != nil && !ticket.DateExpired.After(now) {
				continue
			}
			res := tx.Where("id=? AND source=? AND deleted_at IS NULL", ticket.ID, model.AuthorizationSourceTicket).Delete(&model.AssetAuthorization{})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return ErrAccessRequestConflict
			}
			res = tx.Model(item).Where("status=? AND revoked_at IS NULL", model.AccessRequestApproved).Updates(map[string]any{"status": model.AccessRequestItemRevoked, "revoked_at": now, "revoked_by": actorID, "revoke_note": note})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return ErrAccessRequestConflict
			}
			revoked = append(revoked, *item)
		}
		if len(revoked) == 0 {
			return ErrTicketNotActive
		}
		if itemID == 0 {
			// Whole-envelope revocation also retires pending siblings, so later approval cannot revive the task.
			if err := tx.Model(&model.AccessRequestItem{}).Where("request_id=? AND status=?", req.ID, model.AccessRequestPending).Updates(map[string]any{"status": model.AccessRequestItemRevoked, "revoked_at": now, "revoked_by": actorID, "revoke_note": note}).Error; err != nil {
				return err
			}
			if err := tx.Model(req).Where("revoked_at IS NULL").Updates(map[string]any{"revoked_at": now, "revoked_by": actorID, "revoke_note": note}).Error; err != nil {
				return err
			}
		}
		if err := s.aggregateItems(tx, req, now); err != nil {
			return err
		}
		closed, err = s.closeRequestInTx(tx, req, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	terminated := []uint{}
	for _, item := range revoked {
		terminated = append(terminated, s.revokeAssetSessions(req, item.AssetID)...)
	}
	if closed {
		terminated = append(terminated, s.closeRequestSessions(req.ID)...)
	}
	unique := []uint{}
	seen := map[uint]bool{}
	for _, id := range terminated {
		if !seen[id] {
			unique = append(unique, id)
			seen[id] = true
		}
	}
	details := map[string]any{"item_id": itemID, "terminated_session_ids": unique}
	if len(revoked) == 1 {
		details["authorization_id"] = revoked[0].AuthorizationID
	}
	data, _ := json.Marshal(details)
	s.logAudit(actorID, username, model.ActionRevoke, req.ID, string(data))
	s.notify(notifycat.EventTicketRevoked, req.ID, s.assetName(req.AssetID), nil)
	return s.reload(req.ID)
}

// finishPendingItems keeps the legacy parent terminal states and item dedup in sync.
func (s *AccessRequestService) finishPendingItems(requestID uint, status model.AccessRequestStatus, now time.Time) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var req model.AccessRequest
		if err := tx.First(&req, requestID).Error; err != nil {
			return err
		}
		res := tx.Model(&req).Where("status=?", model.AccessRequestPending).Updates(map[string]any{"status": status, "updated_at": now, "decided_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrAccessRequestConflict
		}
		if err := tx.Model(&model.AccessRequestItem{}).Where("request_id=? AND status=?", requestID, model.AccessRequestPending).Updates(map[string]any{"status": model.AccessRequestItemRevoked, "revoked_at": now}).Error; err != nil {
			return err
		}
		var approved int64
		if err := tx.Model(&model.AccessRequestItem{}).Where("request_id=? AND status=?", requestID, model.AccessRequestApproved).Count(&approved).Error; err != nil {
			return err
		}
		if approved > 0 {
			return s.aggregateItems(tx, &req, now)
		}
		return nil
	})
}

// ExpireApprovedItems is also called by the existing pending-expiry scheduler.
// Effective matching uses the time window directly, never waits for this sweep.
func (s *AccessRequestService) ExpireApprovedItems(now time.Time) (int, error) {
	var ids []uint
	window := "julianday(i.approved_date_start) + i.approved_duration_minutes / 1440.0 > julianday(?)"
	if s.db.Dialector.Name() == "postgres" {
		window = "i.approved_date_start + i.approved_duration_minutes * interval '1 minute' > ?"
	}
	activeItems := "EXISTS (SELECT 1 FROM access_request_items i WHERE i.request_id=access_requests.id AND i.deleted_at IS NULL AND (i.status='pending' OR (i.status='approved' AND (i.approved_date_start IS NULL OR i.approved_duration_minutes IS NULL OR " + window + "))))"
	if err := s.db.Model(&model.AccessRequest{}).Where("closed_at IS NULL AND id IN (?)", s.db.Model(&model.AccessRequestItem{}).Select("request_id").Where("authorization_id IS NOT NULL")).Where("NOT "+activeItems, now).Order("id").Limit(expireBatchLimit).Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	closedCount := 0
	for _, id := range ids {
		closed := false
		err := s.db.Transaction(func(tx *gorm.DB) error {
			var req model.AccessRequest
			if err := tx.First(&req, id).Error; err != nil {
				return err
			}
			if err := s.lockRequest(tx, &req, now, false); err != nil {
				return err
			}
			var err error
			closed, err = s.closeRequestInTx(tx, &req, now)
			return err
		})
		if err != nil {
			return closedCount, err
		}
		if closed {
			closedCount++
			terminated := s.closeRequestSessions(id)
			b, _ := json.Marshal(map[string]any{"cause": "task_expired", "terminated_session_ids": terminated})
			s.logAudit(0, "system", model.ActionExpire, id, string(b))
		}
	}
	return closedCount, nil
}
