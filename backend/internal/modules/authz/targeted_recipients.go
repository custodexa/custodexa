package authz

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 定向通知的收件人判定：誰需要處理這張連線申請、這張破窗單。
//
// 不另寫一條反向的 SQL：先求一個保證不漏的候選人集合，再對每位候選人呼叫與核決相同的判定
// （有效審核者、待審或待補審過濾加單號）。同一個判定也用在送出前的重驗（只對一位呼叫）。
// 所有查詢都在呼叫端給的連線上執行；分派前的求得與送出前的重驗都在交易之外，傳的是一般連線。
//
// 與核決資格刻意不同的地方（通知策略）：已在範圍內每一項都投過核准票的人不送；被鎖定但仍啟用的帳號照送
// （鎖定是暫時的，不看 locked_until）；待審清單的筆數上限不套用在判定上。

// RecipientVerdict 送出前重驗的結論。
type RecipientVerdict int

const (
	// RecipientNeeded 這位收件人仍需要處理這張單：照送。
	RecipientNeeded RecipientVerdict = iota
	// RecipientResolved 收件人的權限仍在，但這張單不再需要他（已被決定、撤回、逾期、已補審，或他已投完票）。
	RecipientResolved
	// RecipientIneligible 收件人已不具資格（不是有效審核者、已停用或刪除、不是 human，或審核範圍已不涵蓋這張單）。
	RecipientIneligible
)

// approverCandidatesSQL 能通過審核範圍條件的人一定在這個集合內：範圍條件的每一個子查詢都以
// 「approver_id = 操作者，或 approver_group_id 屬於操作者所在群組」為前提。
const approverCandidatesSQL = `SELECT approver_id AS id FROM approver_scopes WHERE deleted_at IS NULL AND approver_id IS NOT NULL
UNION
SELECT gm.user_id AS id FROM user_group_members gm JOIN approver_scopes s ON s.approver_group_id = gm.user_group_id
WHERE s.deleted_at IS NULL`

// approverCandidates 審核者候選人（遞增排序、去重）。
func approverCandidates(db *gorm.DB) ([]uint, error) {
	var ids []uint
	if err := db.Raw(`SELECT id FROM (` + approverCandidatesSQL + `) c ORDER BY id`).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("查詢審核者候選人失敗: %w", err)
	}
	return ids, nil
}

// liveHumanUser 帳號存在、未刪除、啟用且不是 agent（不看是否被鎖定）。
func liveHumanUser(db *gorm.DB, userID uint) (bool, error) {
	var n int64
	if err := db.Model(&model.User{}).Where("id = ? AND active = ? AND kind <> ?", userID, true, model.KindAgent).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢收件人帳號失敗: %w", err)
	}
	return n > 0, nil
}

// effectiveApprover 有效審核者（審核端點守門用的同一述詞）。
func effectiveApprover(db *gorm.DB, userID uint) (bool, error) {
	ok, _, err := evaluateEffectiveApprover(db, userID)
	return ok, err
}

// accessRequestNeedsActor 這張連線申請是否需要這位使用者處理。全部成立才是：
// 有效審核者；通過他的待審過濾加單號（不帶清單上限：涵蓋仍待審未逾期、範圍內仍有待審項目、
// 不是申請人或執行者、申請人與執行者都不是他擁有的 agent）；範圍內仍待審的項目中至少一項他還沒投核准票；
// human、啟用、未刪除。
func (s *AccessRequestService) accessRequestNeedsActor(db *gorm.DB, requestID, userID uint, now time.Time) (bool, error) {
	if ok, err := liveHumanUser(db, userID); err != nil || !ok {
		return false, err
	}
	if ok, err := effectiveApprover(db, userID); err != nil || !ok {
		return false, err
	}
	var n int64
	if err := pendingScopeFilterOn(db, userID, false, now).Where("id = ?", requestID).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢待審過濾失敗: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	return s.hasUnvotedPendingItemInScope(db, requestID, userID)
}

// hasUnvotedPendingItemInScope 範圍內仍待審的項目中，至少一項這位審核者還沒投過核准票。
// 範圍判定用核決時逐項呼叫的同一個函式（ApproverScopeCoversRequestTx）。
func (s *AccessRequestService) hasUnvotedPendingItemInScope(db *gorm.DB, requestID, userID uint) (bool, error) {
	var req model.AccessRequest
	if err := db.Select("id", "asset_id", "requester_id").First(&req, requestID).Error; err != nil {
		return false, fmt.Errorf("讀取申請失敗: %w", err)
	}
	var items []model.AccessRequestItem
	if err := db.Where("request_id = ? AND status = ?", requestID, model.AccessRequestPending).Order("id").Find(&items).Error; err != nil {
		return false, fmt.Errorf("讀取申請項目失敗: %w", err)
	}
	if len(items) == 0 {
		// 沒有項目的舊單：以整張單的票判斷
		var total int64
		if err := db.Model(&model.AccessRequestItem{}).Where("request_id = ?", requestID).Count(&total).Error; err != nil {
			return false, fmt.Errorf("讀取申請項目失敗: %w", err)
		}
		if total > 0 {
			return false, nil
		}
		var votes int64
		if err := db.Model(&model.AccessRequestApproval{}).Where("request_id = ? AND approver_id = ?", requestID, userID).
			Count(&votes).Error; err != nil {
			return false, fmt.Errorf("讀取核准票失敗: %w", err)
		}
		return votes == 0, nil
	}
	for _, item := range items {
		covered, err := s.authzRepo.ApproverScopeCoversRequestTx(db, userID, item.AssetID, req.RequesterID)
		if err != nil {
			return false, err
		}
		if !covered {
			continue
		}
		var votes int64
		if err := db.Model(&model.AccessRequestApproval{}).Where("item_id = ? AND approver_id = ?", item.ID, userID).
			Count(&votes).Error; err != nil {
			return false, fmt.Errorf("讀取核准票失敗: %w", err)
		}
		if votes == 0 {
			return true, nil
		}
	}
	return false, nil
}

// scopeCoversAnyItem 審核範圍是否涵蓋這張單的任一項目（不看項目狀態；沒有項目的舊單看整張單的資產）。
func (s *AccessRequestService) scopeCoversAnyItem(db *gorm.DB, requestID, userID uint) (bool, error) {
	var req model.AccessRequest
	if err := db.Select("id", "asset_id", "requester_id").First(&req, requestID).Error; err != nil {
		return false, fmt.Errorf("讀取申請失敗: %w", err)
	}
	var assetIDs []uint
	if err := db.Model(&model.AccessRequestItem{}).Where("request_id = ?", requestID).Order("id").Pluck("asset_id", &assetIDs).Error; err != nil {
		return false, fmt.Errorf("讀取申請項目失敗: %w", err)
	}
	if len(assetIDs) == 0 {
		assetIDs = []uint{req.AssetID}
	}
	for _, assetID := range assetIDs {
		covered, err := s.authzRepo.ApproverScopeCoversRequestTx(db, userID, assetID, req.RequesterID)
		if err != nil || covered {
			return covered, err
		}
	}
	return false, nil
}

// recipientStillEligible 收件人的權限是否還在：有效審核者、啟用的 human、審核範圍仍涵蓋這張單。
// 送出前重驗以它區分「事情已了結」（仍在）與「人不對了」（不在）。
func (s *AccessRequestService) recipientStillEligible(db *gorm.DB, requestID, userID uint) (bool, error) {
	if ok, err := liveHumanUser(db, userID); err != nil || !ok {
		return false, err
	}
	if ok, err := effectiveApprover(db, userID); err != nil || !ok {
		return false, err
	}
	return s.scopeCoversAnyItem(db, requestID, userID)
}

// TargetedAccessRequestRecipients 需要處理這張連線申請的審核者（遞增排序）。
func (s *AccessRequestService) TargetedAccessRequestRecipients(db *gorm.DB, requestID uint, now time.Time) ([]uint, error) {
	candidates, err := approverCandidates(db)
	if err != nil {
		return nil, err
	}
	out := make([]uint, 0, len(candidates))
	for _, id := range candidates {
		ok, err := s.accessRequestNeedsActor(db, requestID, id, now)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, id)
		}
	}
	return out, nil
}

// TargetedAccessRequestVerdict 送出前重驗：這位收件人是否仍需要處理這張連線申請。
func (s *AccessRequestService) TargetedAccessRequestVerdict(db *gorm.DB, requestID, userID uint, now time.Time) (RecipientVerdict, error) {
	needed, err := s.accessRequestNeedsActor(db, requestID, userID, now)
	if err != nil {
		return RecipientIneligible, err
	}
	if needed {
		return RecipientNeeded, nil
	}
	eligible, err := s.recipientStillEligible(db, requestID, userID)
	if err != nil {
		return RecipientIneligible, err
	}
	if eligible {
		return RecipientResolved, nil
	}
	return RecipientIneligible, nil
}

// TargetedAccessRequestAwaiting 這張連線申請是否仍待決定（不含收件人條件：待審、未逾期、至少一項仍待審）。
// 沒有任何收件人時，以它判斷是否仍需要提醒「沒有可送個人訊息的收件人」。
func TargetedAccessRequestAwaiting(db *gorm.DB, requestID uint, now time.Time) (bool, error) {
	var n int64
	if err := db.Model(&model.AccessRequest{}).
		Where("id = ? AND status = ? AND pending_expires_at > ?", requestID, model.AccessRequestPending, now).
		Where(anyPendingItemCondition()).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢申請狀態失敗: %w", err)
	}
	return n > 0, nil
}

// breakGlassNeedsReviewer 這張破窗單是否需要這位使用者補審。全部成立才是：有效審核者；
// 通過他的待補審過濾加單號（破窗單、補審狀態待補審、不是破窗人、範圍命中）；human、啟用、未刪除。
// 不看項目是否待審、票證是否到期：破窗單建立即自動核准，只有補審狀態留待人工。
func (s *AccessRequestService) breakGlassNeedsReviewer(db *gorm.DB, requestID, userID uint) (bool, error) {
	if ok, err := liveHumanUser(db, userID); err != nil || !ok {
		return false, err
	}
	if ok, err := effectiveApprover(db, userID); err != nil || !ok {
		return false, err
	}
	var n int64
	if err := pendingReviewFilterOn(db, userID, false).Where("id = ?", requestID).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢待補審過濾失敗: %w", err)
	}
	return n > 0, nil
}

// TargetedBreakGlassRecipients 需要補審這張破窗單的審核者（遞增排序）。
func (s *AccessRequestService) TargetedBreakGlassRecipients(db *gorm.DB, requestID uint) ([]uint, error) {
	candidates, err := approverCandidates(db)
	if err != nil {
		return nil, err
	}
	out := make([]uint, 0, len(candidates))
	for _, id := range candidates {
		ok, err := s.breakGlassNeedsReviewer(db, requestID, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, id)
		}
	}
	return out, nil
}

// TargetedBreakGlassVerdict 送出前重驗：這位收件人是否仍需要補審這張破窗單。
func (s *AccessRequestService) TargetedBreakGlassVerdict(db *gorm.DB, requestID, userID uint) (RecipientVerdict, error) {
	needed, err := s.breakGlassNeedsReviewer(db, requestID, userID)
	if err != nil {
		return RecipientIneligible, err
	}
	if needed {
		return RecipientNeeded, nil
	}
	eligible, err := s.recipientStillEligible(db, requestID, userID)
	if err != nil {
		return RecipientIneligible, err
	}
	if eligible {
		return RecipientResolved, nil
	}
	return RecipientIneligible, nil
}

// TargetedBreakGlassAwaiting 這張破窗單是否仍待補審（不含收件人條件）。
func TargetedBreakGlassAwaiting(db *gorm.DB, requestID uint) (bool, error) {
	var n int64
	if err := db.Model(&model.AccessRequest{}).Where("id = ? AND kind = ? AND review_status = ?",
		requestID, model.AccessRequestKindBreakGlass, model.BreakGlassReviewPending).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢破窗單狀態失敗: %w", err)
	}
	return n > 0, nil
}
