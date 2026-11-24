package audit

import (
	"fmt"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 每日審閱逾期提醒的定向收件人：能簽核且能進入簽核頁的人，在功能啟用、提醒所列的日子至少一天仍未簽時。
//
// 授權面（候選人上界與「簽核端點與待簽清單端點都放行」）由授權模組的實作在組裝根登錄，本模組不依賴它；
// 功能開關與已簽日在本模組。分派前的求得與送出前的重驗都在交易之外，傳的是一般連線。
// 只看「這則提醒所列的日子」：所列日子都簽了就不再需要，之後新出現的未簽日由下一則提醒負責。

// DailyReviewSignerAccess 授權面的兩個判定。Candidates 回傳保證不漏的候選人上界；Allowed 以路由守門的同一個
// 解析與判定確認簽核與待簽清單兩個端點都放行（並確認帳號為啟用、未刪除的 human）。
type DailyReviewSignerAccess struct {
	Candidates func(db *gorm.DB) ([]uint, error)
	Allowed    func(db *gorm.DB, userID uint) (bool, error)
}

// SetSignerAccess 登錄授權面的判定（組裝根呼叫）。
func (s *DailyReviewService) SetSignerAccess(a DailyReviewSignerAccess) { s.signerAccess = a }

// reminderDates 提醒所列的未簽日（事件參數 pending_dates，逗號串接；至多 31 個，見 OverdueParams）。
func reminderDates(params map[string]string) []string {
	var out []string
	for _, d := range strings.Split(params["pending_dates"], ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// dailyReviewReminderAwaiting 這則提醒是否仍需要處理（不含收件人條件）：功能啟用，且所列的日子至少一天仍未簽。
func (s *DailyReviewService) dailyReviewReminderAwaiting(db *gorm.DB, params map[string]string) (bool, error) {
	if !s.Enabled() {
		return false, nil
	}
	dates := reminderDates(params)
	if len(dates) == 0 {
		return false, nil
	}
	var signed int64
	if err := db.Model(&model.DailyReviewLog{}).Where("review_date IN ?", dates).Distinct("review_date").Count(&signed).Error; err != nil {
		return false, fmt.Errorf("查詢已簽日失敗: %w", err)
	}
	return int(signed) < len(dates), nil
}

// dailyReviewSignerAllowed 授權面判定；未登錄時一律不成立。
func (s *DailyReviewService) dailyReviewSignerAllowed(db *gorm.DB, userID uint) (bool, error) {
	if s.signerAccess.Allowed == nil {
		return false, nil
	}
	return s.signerAccess.Allowed(db, userID)
}

// dailyReviewNeedsSigner 這則逾期提醒是否需要這位使用者處理：功能啟用、所列的日子至少一天仍未簽、
// 他能簽核且能進入簽核頁（啟用、未刪除的 human）。
func (s *DailyReviewService) dailyReviewNeedsSigner(db *gorm.DB, params map[string]string, userID uint) (bool, error) {
	awaiting, err := s.dailyReviewReminderAwaiting(db, params)
	if err != nil || !awaiting {
		return false, err
	}
	return s.dailyReviewSignerAllowed(db, userID)
}

// TargetedDailyReviewRecipients 需要處理這則逾期提醒的使用者（遞增排序）。
func (s *DailyReviewService) TargetedDailyReviewRecipients(db *gorm.DB, params map[string]string) ([]uint, error) {
	awaiting, err := s.dailyReviewReminderAwaiting(db, params)
	if err != nil || !awaiting || s.signerAccess.Candidates == nil {
		return nil, err
	}
	candidates, err := s.signerAccess.Candidates(db)
	if err != nil {
		return nil, err
	}
	out := make([]uint, 0, len(candidates))
	for _, id := range candidates {
		ok, err := s.dailyReviewNeedsSigner(db, params, id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, id)
		}
	}
	return out, nil
}

// TargetedDailyReviewVerdict 送出前重驗。needed 為真時照送；否則 eligible 表示收件人的權限是否還在
// （在：所列日子都已簽或功能已關閉；不在：收件人已不具資格）。
func (s *DailyReviewService) TargetedDailyReviewVerdict(db *gorm.DB, params map[string]string, userID uint) (needed, eligible bool, err error) {
	eligible, err = s.dailyReviewSignerAllowed(db, userID)
	if err != nil || !eligible {
		return false, false, err
	}
	awaiting, err := s.dailyReviewReminderAwaiting(db, params)
	if err != nil {
		return false, true, err
	}
	return awaiting, true, nil
}

// TargetedDailyReviewAwaiting 這則提醒是否仍需要處理（不含收件人條件）。
func (s *DailyReviewService) TargetedDailyReviewAwaiting(db *gorm.DB, params map[string]string) (bool, error) {
	return s.dailyReviewReminderAwaiting(db, params)
}

// TargetedJudge 每日審閱逾期提醒（daily_review_overdue）的收件人判定，給投遞程序登錄。
func (s *DailyReviewService) TargetedJudge() TargetedJudge {
	return TargetedJudge{
		Recipients: func(db *gorm.DB, sub TargetedSubject) ([]uint, error) {
			return s.TargetedDailyReviewRecipients(db, sub.Params)
		},
		Verdict: func(db *gorm.DB, sub TargetedSubject, userID uint) (TargetedVerdict, error) {
			needed, eligible, err := s.TargetedDailyReviewVerdict(db, sub.Params, userID)
			switch {
			case err != nil:
				return TargetedIneligible, err
			case needed:
				return TargetedNeeded, nil
			case eligible:
				return TargetedResolved, nil
			}
			return TargetedIneligible, nil
		},
		Awaiting: func(db *gorm.DB, sub TargetedSubject) (bool, error) {
			return s.TargetedDailyReviewAwaiting(db, sub.Params)
		},
	}
}
