package authz

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 授權列表的列級可操作旗標（非超級管理者）。
//
// 旗標只決定畫面，端點仍各自裁決。計算與寫入端點共用同一組判定：本人範圍判定
// （ruleSubjectsInSelfScope）、建立者判定（ruleCreatedBy）、臨時授權帳號範圍與裸刪的鎖定判定
// （ticketRuleAccountScopeLocked、ticketRuleDeleteLocked）、以及撤銷資格（itemRevokeEligible、
// revokeQualifiedByScope）。列表本身已依檢視者的授權規則管理範圍投影，所以「缺該動作的能力」
// 不會出現，不設對應原因。唯讀，不取鎖。

// 列級旗標的原因碼（不含名稱）與限制值。
const (
	RuleActionReasonSelfSubject       = "self_subject"
	RuleActionReasonTicketBound       = "ticket_bound"
	RuleActionReasonNotRevocable      = "not_revocable"
	RuleActionReasonRevokeNotEligible = "revoke_not_eligible"
	// RuleActionLimitNarrowOnly 可操作，但只能縮小帳號範圍（操作者不是建立者）。
	RuleActionLimitNarrowOnly = "narrow_only"
)

// RuleAction 一個動作的可操作結果；原因只在不可操作時有值，限制只在可操作時有值。
type RuleAction struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	Limit   string `json:"limit,omitempty"`
}

// RuleRowActions 一筆授權規則的動作；Revoke 只在臨時授權列出現。
type RuleRowActions struct {
	UpdateAccounts RuleAction  `json:"update_accounts"`
	Delete         RuleAction  `json:"delete"`
	Revoke         *RuleAction `json:"revoke,omitempty"`
}

// AuthorizationRowActions 授權列表列級旗標的計算者；requests 為撤銷資格的來源。
type AuthorizationRowActions struct {
	db       *gorm.DB
	requests *AccessRequestService
}

// NewAuthorizationRowActions 以讀取連線與申請單服務建立。
func NewAuthorizationRowActions(db *gorm.DB, requests *AccessRequestService) *AuthorizationRowActions {
	return &AuthorizationRowActions{db: db, requests: requests}
}

var errRowActionsUnwired = errors.New("authz: authorization row actions without database or request service")

// For 計算各列的旗標，鍵為授權編號。超級管理者不帶旗標（回 nil）。
// auths 須已回填 RequestID（授權服務的列表查詢已回填）。
func (r *AuthorizationRowActions) For(ctx context.Context, auths []*model.AssetAuthorization, now time.Time) (map[uint]RuleRowActions, error) {
	if r == nil || r.db == nil || r.requests == nil {
		return nil, errRowActionsUnwired
	}
	p := PrincipalFromContext(ctx)
	if p == nil {
		return nil, ErrOperatorUnknown
	}
	if p.IsSuperAdmin() {
		return nil, nil
	}
	self, err := SelfSubjectsOf(r.db, p.UserID)
	if err != nil {
		return nil, err
	}
	type revokeVerdict struct{ eligible, revocable bool }
	verdicts := map[uint]revokeVerdict{}
	out := make(map[uint]RuleRowActions, len(auths))
	for _, a := range auths {
		linked := a.RequestID != nil
		row := RuleRowActions{
			UpdateAccounts: RuleAction{Allowed: true},
			Delete:         RuleAction{Allowed: true},
		}
		var users, groups []uint
		if a.UserID != nil {
			users = []uint{*a.UserID}
		}
		if a.UserGroupID != nil {
			groups = []uint{*a.UserGroupID}
		}
		switch {
		case ticketRuleAccountScopeLocked(a.Source):
			row.UpdateAccounts = RuleAction{Reason: RuleActionReasonTicketBound}
		case ruleSubjectsInSelfScope(self, users, groups):
			row.UpdateAccounts = RuleAction{Reason: RuleActionReasonSelfSubject}
		case !ruleCreatedBy(p, a.GrantedBy):
			row.UpdateAccounts = RuleAction{Allowed: true, Limit: RuleActionLimitNarrowOnly}
		}
		if ticketRuleDeleteLocked(a.Source, linked) {
			row.Delete = RuleAction{Reason: RuleActionReasonTicketBound}
		}
		if a.Source == model.AuthorizationSourceTicket {
			revoke := RuleAction{Allowed: true}
			switch {
			case !linked || !a.ActiveWithin(now):
				revoke = RuleAction{Reason: RuleActionReasonNotRevocable}
			default:
				v, ok := verdicts[*a.RequestID]
				if !ok {
					v.eligible, v.revocable, err = r.requests.revokeEligibleFor(r.db, p.UserID, *a.RequestID, now)
					if err != nil {
						return nil, err
					}
					verdicts[*a.RequestID] = v
				}
				switch {
				case !v.eligible:
					revoke = RuleAction{Reason: RuleActionReasonRevokeNotEligible}
				case !v.revocable:
					revoke = RuleAction{Reason: RuleActionReasonNotRevocable}
				}
			}
			row.Revoke = &revoke
		}
		out[a.ID] = row
	}
	return out, nil
}
