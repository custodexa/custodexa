package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

var ErrAgentCannotDecide = errors.New("agent cannot approve or reject requests")

type ItemDecision struct {
	ItemID          uint       `json:"item_id"`
	DurationMinutes *int       `json:"duration_minutes"`
	DateStart       *time.Time `json:"date_start"`
	Accounts        *[]string  `json:"accounts"`
	Remove          bool       `json:"remove"`
}

func (s *AccessRequestService) humanDecider(tx *gorm.DB, id uint) error {
	var user model.User
	if err := tx.Select("id", "kind").First(&user, id).Error; err != nil {
		return err
	}
	if user.Kind == model.KindAgent {
		return ErrAgentCannotDecide
	}
	return nil
}
func (s *AccessRequestService) lockRequest(tx *gorm.DB, req *model.AccessRequest, now time.Time, pending bool) error {
	q := tx.Model(&model.AccessRequest{}).Where("id=?", req.ID)
	if pending {
		q = q.Where("status=? AND pending_expires_at>?", model.AccessRequestPending, now)
	}
	res := q.Update("updated_at", now)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return ErrAccessRequestConflict
	}
	return tx.First(req, req.ID).Error
}
func requestItems(tx *gorm.DB, req *model.AccessRequest) ([]model.AccessRequestItem, error) {
	var items []model.AccessRequestItem
	err := tx.Where("request_id=?", req.ID).Order("id").Find(&items).Error
	return items, err
}
func itemInputDecision(input DecideInput, itemID uint) (DecideInput, bool) {
	if input.Items != nil {
		for _, v := range input.Items {
			if v.ItemID == itemID {
				return DecideInput{ItemID: itemID, DurationMinutes: v.DurationMinutes, DateStart: v.DateStart, Accounts: v.Accounts, Remove: v.Remove, Note: input.Note}, true
			}
		}
		return DecideInput{}, false
	}
	return input, input.ItemID == 0 || input.ItemID == itemID
}
func decisionValues(req *model.AccessRequest, item *model.AccessRequestItem, in DecideInput, now time.Time) (int, time.Time, model.AccountScope, error) {
	duration := req.RequestedDurationMinutes
	if in.DurationMinutes != nil {
		if *in.DurationMinutes < 1 || *in.DurationMinutes > duration {
			return 0, now, nil, ErrDecisionIncrease
		}
		duration = *in.DurationMinutes
	}
	start := now
	if req.RequestedDateStart != nil && req.RequestedDateStart.After(start) {
		start = *req.RequestedDateStart
	}
	if in.DateStart != nil {
		if in.DateStart.Before(start) {
			return 0, now, nil, ErrDecisionIncrease
		}
		start = *in.DateStart
	}
	scope := item.Accounts
	if in.Accounts != nil {
		normalized, err := NormalizeGrantAccounts(in.Accounts)
		if err != nil {
			return 0, now, nil, ErrDecisionIncrease
		}
		if !scope.IsAll() {
			if normalized.IsAll() {
				return 0, now, nil, ErrDecisionIncrease
			}
			for _, name := range normalized {
				if !scope.Contains(name) {
					return 0, now, nil, ErrDecisionIncrease
				}
			}
		}
		scope = normalized
	}
	return duration, start, scope, nil
}
func (s *AccessRequestService) itemSnapshot(tx *gorm.DB, item *model.AccessRequestItem, auto bool) (string, error) {
	var asset model.Asset
	if err := tx.First(&asset, item.AssetID).Error; err != nil {
		return "", err
	}
	segment, required, err := s.policies.RequestDecisionPolicyInTx(tx, asset.AccessPolicy)
	if err != nil {
		return "", err
	}
	snapshot := map[string]any{"segment": segment, "required_approvals": required}
	if auto {
		snapshot["required_approvals"] = 0
		snapshot["auto_basis"] = segment
	}
	b, err := json.Marshal(snapshot)
	return string(b), err
}
func (s *AccessRequestService) approveItemInTx(tx *gorm.DB, req *model.AccessRequest, item *model.AccessRequestItem, actor *uint, in DecideInput, auto bool, now time.Time) error {
	duration, start, scope, err := decisionValues(req, item, in, now)
	if err != nil {
		return err
	}
	snapshot, err := s.itemSnapshot(tx, item, auto)
	if err != nil {
		return err
	}
	if auto {
		var facts map[string]any
		if err := json.Unmarshal([]byte(snapshot), &facts); err != nil {
			return err
		}
		if req.Kind == model.AccessRequestKindBreakGlass {
			facts["auto_basis"] = "break_glass"
			b, _ := json.Marshal(facts)
			snapshot = string(b)
		} else if facts["segment"] == model.AccessPolicyApproval {
			return ErrAccessRequestConflict
		}
	}
	executor := executorIDValue(req.ExecutorUserID, req.RequesterID)
	grantedBy := req.RequesterID
	if actor != nil {
		grantedBy = *actor
	}
	expiry := start.Add(time.Duration(duration) * time.Minute)
	values := map[string]any{"status": model.AccessRequestApproved, "accounts": scope, "approved_duration_minutes": duration, "approved_date_start": start, "decided_by": actor, "decided_at": now, "policy_snapshot": snapshot}
	if item.ID != 0 {
		res := tx.Model(item).Where("status=?", model.AccessRequestPending).Updates(values)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrAccessRequestConflict
		}
	} else {
		// Break-glass has no pending item: an existing normal pending item must not block it.
		item.Status = model.AccessRequestApproved
		item.Accounts = scope
		item.ApprovedDurationMinutes = &duration
		item.ApprovedDateStart = &start
		item.DecidedBy = actor
		item.DecidedAt = &now
		item.PolicySnapshot = snapshot
		if err := tx.Session(&gorm.Session{SkipHooks: true}).Create(item).Error; err != nil {
			return err
		}
	}
	grant := model.AssetAuthorization{UserID: &executor, AssetID: &item.AssetID, Permission: model.PermissionConnect, DateStart: &start, DateExpired: &expiry, GrantedBy: grantedBy, Source: model.AuthorizationSourceTicket, Accounts: scope}
	if err := tx.Create(&grant).Error; err != nil {
		return err
	}
	if err := recordAgentVisibilityExposures(tx, executor, []uint{item.AssetID}); err != nil {
		return err
	}
	return tx.Model(item).Update("authorization_id", grant.ID).Error
}
func (s *AccessRequestService) aggregateItems(tx *gorm.DB, req *model.AccessRequest, now time.Time) error {
	items, err := requestItems(tx, req)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return ErrAccessRequestConflict
	}
	status := model.AccessRequestRejected
	auto := true
	for _, item := range items {
		if item.Status == model.AccessRequestApproved || item.Status == model.AccessRequestItemRevoked && item.AuthorizationID != nil {
			status = model.AccessRequestApproved
		}
		if item.DecidedBy != nil {
			auto = false
		}
	}
	for _, item := range items {
		if item.Status == model.AccessRequestPending {
			status = model.AccessRequestPending
			auto = false
			break
		}
	}
	first := items[0]
	updates := map[string]any{"status": status, "auto_approved": auto && status == model.AccessRequestApproved, "authorization_id": first.AuthorizationID, "approved_duration_minutes": first.ApprovedDurationMinutes, "approved_date_start": first.ApprovedDateStart, "approver_id": first.DecidedBy, "decided_at": first.DecidedAt, "accounts": first.Accounts, "updated_at": now}
	if auto && status == model.AccessRequestApproved {
		updates["decision_note"] = "system"
	}
	return tx.Model(req).Updates(updates).Error
}
func (s *AccessRequestService) approveRequestItems(actorID uint, isAdmin bool, requestID uint, input DecideInput) (*model.AccessRequest, error) {
	if err := s.humanDecider(s.db, actorID); err != nil {
		return nil, err
	}
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	if actorID == req.RequesterID || req.ExecutorUserID != nil && actorID == *req.ExecutorUserID {
		return nil, ErrSelfApproval
	}
	now := time.Now()
	reached := false
	var maxVotes int64
	required := s.policies.GetInt(policy.PolicyAccessRequestMinApprovals)
	if required < 1 {
		required = 1
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := s.lockRequest(tx, req, now, true); err != nil {
			return err
		}
		if err := s.humanDecider(tx, actorID); err != nil {
			return err
		}
		required, err = s.policies.RequestApprovalThresholdInTx(tx)
		if err != nil {
			return err
		}
		if required < 1 {
			required = 1
		}
		items, err := requestItems(tx, req)
		if err != nil {
			return err
		}
		selected := 0
		seen := map[uint]bool{}
		if input.Items != nil {
			if input.ItemID != 0 || input.Accounts != nil || input.DurationMinutes != nil || input.DateStart != nil || input.Remove {
				return ErrRequestItemsShape
			}
			for _, v := range input.Items {
				if v.ItemID == 0 || seen[v.ItemID] {
					return ErrRequestItemsShape
				}
				seen[v.ItemID] = true
			}
		}
		for i := range items {
			item := &items[i]
			in, ok := itemInputDecision(input, item.ID)
			if !ok {
				continue
			}
			if item.Status != model.AccessRequestPending {
				if input.ItemID != 0 || input.Items != nil {
					return ErrAccessRequestConflict
				}
				continue
			}
			selected++
			if !isAdmin {
				covered, e := s.authzRepo.ApproverScopeCoversRequestTx(tx, actorID, item.AssetID, req.RequesterID)
				if e != nil {
					return e
				}
				if !covered {
					return ErrNotEligibleApprover
				}
			}
			if _, _, _, err := decisionValues(req, item, in, now); err != nil {
				return err
			}
			if in.Remove {
				snapshot, e := s.itemSnapshot(tx, item, false)
				if e != nil {
					return e
				}
				if e = tx.Model(item).Where("status=?", model.AccessRequestPending).Updates(map[string]any{"status": model.AccessRequestRejected, "decided_by": actorID, "decided_at": now, "policy_snapshot": snapshot}).Error; e != nil {
					return e
				}
				continue
			}
			vote := model.AccessRequestApproval{RequestID: req.ID, ItemID: &item.ID, ApproverID: actorID, Note: input.Note}
			if err := tx.Create(&vote).Error; err != nil {
				if dberr.IsUniqueViolation(err) {
					return ErrAlreadyApprovedByActor
				}
				return err
			}
			var votes int64
			if err := tx.Model(&model.AccessRequestApproval{}).Where("request_id=? AND item_id=?", req.ID, item.ID).Count(&votes).Error; err != nil {
				return err
			}
			if votes > maxVotes {
				maxVotes = votes
			}
			if int(votes) >= required {
				reached = true
				if err := s.approveInTx(tx, req, &actorID, inForItem(in, item.ID), false, now); err != nil {
					return err
				}
			}
		}
		if selected == 0 || input.Items != nil && selected != len(input.Items) {
			return ErrAccessRequestConflict
		}
		if err := s.aggregateItems(tx, req, now); err != nil {
			return err
		}
		return tx.Model(req).Update("decision_note", input.Note).Error
	})
	if err != nil {
		return nil, err
	}
	if reached {
		s.notify(notifycat.EventAccessRequestApproved, req.ID, s.assetName(req.AssetID), map[string]string{"mode": notifycat.ApprovalModeManual})
	} else {
		s.notify(notifycat.EventAccessRequestApprovalProgress, req.ID, s.assetName(req.AssetID), map[string]string{"votes": fmt.Sprint(maxVotes), "required": fmt.Sprint(required)})
	}
	return s.reload(requestID)
}
func inForItem(in DecideInput, id uint) DecideInput { in.ItemID = id; in.Items = nil; return in }

// approveInTx is shared by manual approval, reason/open auto approval and break-glass.
func (s *AccessRequestService) approveInTx(tx *gorm.DB, req *model.AccessRequest, actor *uint, input DecideInput, auto bool, now time.Time) error {
	if !req.PendingExpiresAt.After(now) {
		return ErrAccessRequestConflict
	}
	items, err := requestItems(tx, req)
	if err != nil {
		return err
	}
	if len(items) == 0 && req.Kind == model.AccessRequestKindBreakGlass {
		items = []model.AccessRequestItem{{RequestID: req.ID, RequesterID: req.RequesterID, AssetID: req.AssetID, Accounts: req.Accounts}}
	}
	matched := false
	for i := range items {
		item := &items[i]
		in, ok := itemInputDecision(input, item.ID)
		if !ok || item.ID != 0 && item.Status != model.AccessRequestPending {
			continue
		}
		matched = true
		if err := s.approveItemInTx(tx, req, item, actor, in, auto, now); err != nil {
			return err
		}
	}
	if !matched {
		return ErrAccessRequestConflict
	}
	return s.aggregateItems(tx, req, now)
}
func (s *AccessRequestService) RejectItem(actorID uint, isAdmin bool, requestID, itemID uint, note string) (*model.AccessRequest, error) {
	if err := s.humanDecider(s.db, actorID); err != nil {
		return nil, err
	}
	if note == "" {
		return nil, ErrDecisionNoteRequired
	}
	req, err := s.loadPending(requestID)
	if err != nil {
		return nil, err
	}
	if actorID == req.RequesterID || req.ExecutorUserID != nil && actorID == *req.ExecutorUserID {
		return nil, ErrSelfApproval
	}
	now := time.Now()
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// Rejection remains possible after the pending deadline, as in the legacy API.
		res := tx.Model(req).Where("status=?", model.AccessRequestPending).Update("updated_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrAccessRequestConflict
		}
		if err := s.humanDecider(tx, actorID); err != nil {
			return err
		}
		items, err := requestItems(tx, req)
		if err != nil {
			return err
		}
		count := 0
		for i := range items {
			item := &items[i]
			if itemID != 0 && item.ID != itemID {
				continue
			}
			if item.Status != model.AccessRequestPending {
				continue
			}
			count++
			if !isAdmin {
				covered, e := s.authzRepo.ApproverScopeCoversRequestTx(tx, actorID, item.AssetID, req.RequesterID)
				if e != nil {
					return e
				}
				if !covered {
					return ErrNotEligibleApprover
				}
			}
			snapshot, e := s.itemSnapshot(tx, item, false)
			if e != nil {
				return e
			}
			if err := tx.Model(item).Where("status=?", model.AccessRequestPending).Updates(map[string]any{"status": model.AccessRequestRejected, "decided_by": actorID, "decided_at": now, "policy_snapshot": snapshot}).Error; err != nil {
				return err
			}
		}
		if count == 0 {
			return ErrAccessRequestConflict
		}
		if err := s.aggregateItems(tx, req, now); err != nil {
			return err
		}
		return tx.Model(req).Update("decision_note", note).Error
	})
	if err != nil {
		return nil, err
	}
	s.notify(notifycat.EventAccessRequestRejected, req.ID, s.assetName(req.AssetID), nil)
	return s.reload(req.ID)
}
