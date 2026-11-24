package authz

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 定向通知的收件人判定登錄：把連線申請與破窗的判定包成投遞程序的對外埠形狀（audit.TargetedJudge），
// 由組裝根以 UseTargetedJudge 登錄。判定本身在 targeted_recipients.go，分派前的求得與送出前的重驗呼叫同一個函式。

// verdictOf 授權模組的結論轉成投遞程序的結論。
func verdictOf(v RecipientVerdict) audit.TargetedVerdict {
	switch v {
	case RecipientNeeded:
		return audit.TargetedNeeded
	case RecipientResolved:
		return audit.TargetedResolved
	default:
		return audit.TargetedIneligible
	}
}

// TargetedAccessRequestJudge 連線申請建立（access_request.created）的收件人判定。
func (s *AccessRequestService) TargetedAccessRequestJudge() audit.TargetedJudge {
	return audit.TargetedJudge{
		Recipients: func(db *gorm.DB, sub audit.TargetedSubject) ([]uint, error) {
			return s.TargetedAccessRequestRecipients(db, sub.RequestID, sub.Now)
		},
		Verdict: func(db *gorm.DB, sub audit.TargetedSubject, userID uint) (audit.TargetedVerdict, error) {
			v, err := s.TargetedAccessRequestVerdict(db, sub.RequestID, userID, sub.Now)
			return verdictOf(v), err
		},
		Awaiting: func(db *gorm.DB, sub audit.TargetedSubject) (bool, error) {
			return TargetedAccessRequestAwaiting(db, sub.RequestID, sub.Now)
		},
	}
}

// TargetedBreakGlassJudge 破窗使用與補審逾期（break_glass_used、break_glass_review_overdue）的收件人判定。
func (s *AccessRequestService) TargetedBreakGlassJudge() audit.TargetedJudge {
	return audit.TargetedJudge{
		Recipients: func(db *gorm.DB, sub audit.TargetedSubject) ([]uint, error) {
			return s.TargetedBreakGlassRecipients(db, sub.RequestID)
		},
		Verdict: func(db *gorm.DB, sub audit.TargetedSubject, userID uint) (audit.TargetedVerdict, error) {
			v, err := s.TargetedBreakGlassVerdict(db, sub.RequestID, userID)
			return verdictOf(v), err
		},
		Awaiting: func(db *gorm.DB, sub audit.TargetedSubject) (bool, error) {
			return TargetedBreakGlassAwaiting(db, sub.RequestID)
		},
	}
}

// TargetedJudges 授權模組負責的三個事件與其判定（組裝根逐一登錄）。
func (s *AccessRequestService) TargetedJudges() map[notifycat.Event]audit.TargetedJudge {
	bg := s.TargetedBreakGlassJudge()
	return map[notifycat.Event]audit.TargetedJudge{
		notifycat.EventAccessRequestCreated:    s.TargetedAccessRequestJudge(),
		notifycat.EventBreakGlassUsed:          bg,
		notifycat.EventBreakGlassReviewOverdue: bg,
	}
}
