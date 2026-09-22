package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

var (
	ErrRequestItemsShape     = errors.New("single-asset and items input must be exclusive; one to twenty distinct assets required")
	ErrAccountNotOnAsset     = errors.New("VALIDATION_ACCOUNT_NOT_ON_ASSET")
	ErrAgentAccountsRequired = errors.New("VALIDATION_AGENT_ACCOUNTS_REQUIRED")
	ErrExecutorNotAgent      = errors.New("VALIDATION_EXECUTOR_NOT_AGENT")
	ErrAgentRequestRate      = errors.New("RULE_AGENT_REQUEST_RATE")
)

type AccountNotOnAssetError struct {
	ItemIndex int
	AssetID   uint
}

func (e *AccountNotOnAssetError) Error() string { return ErrAccountNotOnAsset.Error() }
func (e *AccountNotOnAssetError) Unwrap() error { return ErrAccountNotOnAsset }

type ItemInput struct {
	AssetID  uint
	Accounts *[]string
}
type DuplicatePendingItemError struct {
	RequestID uint
	ItemID    uint
}

func (e *DuplicatePendingItemError) Error() string {
	return fmt.Sprintf("%s（單號 %d，項 %d）", ErrDuplicatePendingRequest, e.RequestID, e.ItemID)
}
func (e *DuplicatePendingItemError) Unwrap() error { return ErrDuplicatePendingRequest }

type AgentRequestRateError struct {
	Count     int64
	Limit     int
	Dimension string
}

func (e *AgentRequestRateError) Error() string {
	return fmt.Sprintf("%s (%s %d/%d)", ErrAgentRequestRate, e.Dimension, e.Count, e.Limit)
}
func (e *AgentRequestRateError) Unwrap() error { return ErrAgentRequestRate }

type preparedRequestItem struct {
	asset   model.Asset
	scope   model.AccountScope
	segment string
}

// RequestItemVisible re-evaluates both sides of an assisted request on every call.
// The later MatchRequestItem envelope gate uses this same visibility predicate.
func (s *AccessRequestService) RequestItemVisible(requesterID uint, executorID *uint, assetID uint) (bool, error) {
	for _, id := range []uint{requesterID, executorIDValue(executorID, requesterID)} {
		visible, err := s.authzRepo.CheckPermission(id, assetID, []model.PermissionType{model.PermissionView, model.PermissionConnect})
		if err != nil {
			return false, err
		}
		if !visible {
			visible, err = s.authzRepo.ApproverScopeCoversAsset(id, assetID)
			if err != nil {
				return false, err
			}
		}
		if !visible {
			return false, nil
		}
		if executorID == nil {
			break
		}
	}
	return true, nil
}
func executorIDValue(executor *uint, requester uint) uint {
	if executor != nil {
		return *executor
	}
	return requester
}

func (s *AccessRequestService) submitItems(requesterID uint, username, role string, input SubmitAccessRequestInput) (*model.AccessRequest, error) {
	if role == model.RoleAdmin || role == model.RoleAuditor {
		return nil, ErrRequesterExempt
	}
	items := input.Items
	if items != nil {
		if input.AssetID != 0 || input.Accounts != nil {
			return nil, ErrRequestItemsShape
		}
	} else {
		items = []ItemInput{{AssetID: input.AssetID, Accounts: input.Accounts}}
	}
	if len(items) == 0 || len(items) > 20 {
		return nil, ErrRequestItemsShape
	}
	seen := map[uint]bool{}
	for _, item := range items {
		if item.AssetID == 0 || seen[item.AssetID] {
			return nil, ErrRequestItemsShape
		}
		seen[item.AssetID] = true
	}
	var executor model.User
	if input.ExecutorUserID != nil {
		if err := s.db.First(&executor, *input.ExecutorUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrExecutorNotAgent
			}
			return nil, err
		}
		if executor.Kind != model.KindAgent || !executor.Active {
			return nil, ErrExecutorNotAgent
		}
	}
	prepared := make([]preparedRequestItem, 0, len(items))
	requesterKind := ""
	for itemIndex, item := range items {
		// Fold the trusted requester kind into the pre-existing asset fetch: no
		// separate kind/rate query is added to the human path.
		var found struct {
			model.Asset
			RequesterKind string
		}
		err := s.db.Model(&model.Asset{}).Select("assets.*, (SELECT kind FROM users WHERE id = ? AND deleted_at IS NULL) AS requester_kind", requesterID).First(&found, item.AssetID).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrAccessRequestNotFound
			}
			return nil, err
		}
		requesterKind = found.RequesterKind
		visible, err := s.RequestItemVisible(requesterID, input.ExecutorUserID, item.AssetID)
		if err != nil {
			return nil, err
		}
		if !visible {
			return nil, ErrAccessRequestNotFound
		}
		agentExec := requesterKind == model.KindAgent || input.ExecutorUserID != nil
		segment := s.accessPolicy.AccessPolicyOf(&found.Asset)
		if segment == model.AccessPolicyOpen && !agentExec {
			return nil, ErrPolicyOpenNoRequest
		}
		if agentExec && (item.Accounts == nil || model.NormalizeAccountScope(*item.Accounts).IsAll()) {
			return nil, ErrAgentAccountsRequired
		}
		scope, err := NormalizeGrantAccounts(item.Accounts)
		if err != nil {
			return nil, err
		}
		if agentExec && scope.IsAll() {
			return nil, ErrAgentAccountsRequired
		}
		if !scope.IsAll() {
			for _, name := range scope {
				if s.accountPresent == nil {
					return nil, fmt.Errorf("request account source unavailable")
				}
				present, err := s.accountPresent(s.db, item.AssetID, name)
				if err != nil {
					return nil, err
				}
				if !present {
					return nil, &AccountNotOnAssetError{ItemIndex: itemIndex, AssetID: item.AssetID}
				}
			}
		}
		prepared = append(prepared, preparedRequestItem{found.Asset, scope, segment})
	}
	maxDuration := s.policies.GetInt(policy.PolicyAccessRequestMaxDurationMinutes)
	if input.DurationMinutes < 1 || input.DurationMinutes > maxDuration {
		return nil, &DurationExceedsPolicyError{MaxMinutes: maxDuration}
	}
	now := time.Now()
	if input.DateStart != nil && input.DateStart.Before(now) {
		return nil, ErrStartInPast
	}
	timeout := s.policies.GetInt(policy.PolicyAccessRequestPendingTimeoutHours)
	var req *model.AccessRequest
	create := func() error {
		return s.db.Transaction(func(tx *gorm.DB) error {
			if requesterKind == model.KindAgent {
				// Row lock serializes counting and inserting across processes.
				if tx.Dialector.Name() == "postgres" {
					var locked model.User
					if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&locked, requesterID).Error; err != nil {
						return err
					}
				}
				if err := s.checkAgentRequestRate(tx, requesterID, now); err != nil {
					return err
				}
			}
			req = &model.AccessRequest{RequesterID: requesterID, ExecutorUserID: input.ExecutorUserID, AssetID: prepared[0].asset.ID, Accounts: prepared[0].scope, Reason: input.Reason, RequestedDurationMinutes: input.DurationMinutes, RequestedDateStart: input.DateStart, Status: model.AccessRequestPending, PendingExpiresAt: now.Add(time.Duration(timeout) * time.Hour), Kind: model.AccessRequestKindNormal}
			if err := tx.Create(req).Error; err != nil {
				return err
			}
			pending := false
			for _, p := range prepared {
				item := model.AccessRequestItem{RequestID: req.ID, RequesterID: requesterID, AssetID: p.asset.ID, Accounts: p.scope, Status: model.AccessRequestPending}
				if err := tx.Create(&item).Error; err != nil {
					return err
				}
				if p.segment == model.AccessPolicyApproval {
					pending = true
					continue
				}
				if err := s.approveInTx(tx, req, nil, DecideInput{ItemID: item.ID}, true, now); err != nil {
					return err
				}
			}
			if pending {
				return tx.Model(req).Updates(map[string]any{"status": model.AccessRequestPending, "auto_approved": false}).Error
			}
			req.Status = model.AccessRequestApproved
			req.AutoApproved = true
			return tx.Model(req).Updates(map[string]any{"status": req.Status, "auto_approved": true}).Error
		})
	}
	err := create()
	if err != nil && dberr.IsUniqueViolation(err) {
		expired := false
		for _, p := range prepared {
			if s.expireOverduePendingFor(requesterID, p.asset.ID, now) {
				expired = true
			}
		}
		if expired {
			err = create()
		}
	}
	if err != nil {
		var rate *AgentRequestRateError
		if errors.As(err, &rate) {
			s.logAgentRequestRate(requesterID, username, rate)
			return nil, err
		}
		if dberr.IsUniqueViolation(err) {
			for _, p := range prepared {
				var item model.AccessRequestItem
				if s.db.Where("requester_id=? AND asset_id=? AND status=?", requesterID, p.asset.ID, model.AccessRequestPending).First(&item).Error == nil {
					return nil, &DuplicatePendingItemError{item.RequestID, item.ID}
				}
			}
			return nil, s.duplicatePendingError(requesterID, prepared[0].asset.ID)
		}
		return nil, err
	}
	if req.AutoApproved {
		s.logAudit(requesterID, username, model.ActionApprove, req.ID, `{"auto":true,"decided_by":"system"}`)
		s.notify(notifycat.EventAccessRequestApproved, req.ID, prepared[0].asset.Name, map[string]string{"mode": notifycat.ApprovalModeAuto})
	} else {
		s.notify(notifycat.EventAccessRequestCreated, req.ID, prepared[0].asset.Name, nil)
	}
	result, err := s.reload(req.ID)
	if err != nil {
		return nil, err
	}
	if err := s.db.Where("request_id=?", req.ID).Order("id").Find(&result.Items).Error; err != nil {
		return nil, err
	}
	return result, nil
}

func (s *AccessRequestService) checkAgentRequestRate(tx *gorm.DB, id uint, now time.Time) error {
	hourly, pending, err := s.policies.AgentRequestLimitsInTx(tx)
	if err != nil {
		return err
	}
	for _, limit := range []struct {
		dimension string
		maximum   int
		hour      bool
	}{{"hour", hourly, true}, {"pending", pending, false}} {
		var n int64
		q := tx.Model(&model.AccessRequest{}).Where("requester_id=?", id)
		if limit.hour {
			q = q.Where("created_at >= ?", now.Add(-time.Hour))
		} else {
			q = q.Where("status=? AND pending_expires_at>?", model.AccessRequestPending, now)
		}
		if err := q.Count(&n).Error; err != nil {
			return err
		}
		if n >= int64(limit.maximum) {
			return &AgentRequestRateError{n, limit.maximum, limit.dimension}
		}
	}
	return nil
}
func (s *AccessRequestService) SetAccountPresenceSource(source func(*gorm.DB, uint, string) (bool, error)) {
	s.accountPresent = source
}

func (s *AccessRequestService) logAgentRequestRate(id uint, username string, e *AgentRequestRateError) {
	if s.audit == nil {
		return
	}
	details, _ := json.Marshal(map[string]any{"code": "RULE_AGENT_REQUEST_RATE", "dimension": e.Dimension, "count": e.Count, "limit": e.Limit})
	s.audit.Log(&audit.AuditLogEntry{UserID: id, Username: username, Action: model.ActionCreate, Resource: model.ResourceAccessRequest, Status: model.StatusDenied, Details: string(details)})
}
