package audit

import (
	"log"
	"strconv"
	"time"

	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/reviewcal"
)

// DailyReviewReminderHour 逾期提醒的送出時刻（業務時區當地時間）
const DailyReviewReminderHour = 9

// CheckOverdue 逾期提醒檢查（排程每 15 分鐘呼叫）；回傳本次是否送出（供測試斷言）。
//
// 「當地時間」與「今天」都以目前生效的業務時區判定（行事曆的解析器），不讀政策列的
// 設定值。過了 09:00 且今天尚未送過，有任何一天已逾準時期限才送，內容列出全部未簽日；
// 只有昨天未簽時不送（昨天仍在準時期限內）。全部補齊或功能關閉時不送，也不另發補齊通知。
// 「今天已送過」記在記憶體：程序重啟後當日可能再送一次——重複一則的代價低於漏送。
func (s *DailyReviewService) CheckOverdue(now time.Time) bool {
	if !s.Enabled() {
		return false
	}
	cal, err := s.Calendar(now)
	if err != nil {
		log.Printf("[DailyReview] 逾期檢查讀取行事曆失敗: %v", err)
		return false
	}
	today := cal.Today()
	loc, ok := reviewcal.LoadTimezone(today.TZ)
	if !ok {
		loc = time.UTC
	}
	date, _ := reviewcal.ParseDate(today.Date)
	sendAt := time.Date(date.Year(), date.Month(), date.Day(), DailyReviewReminderHour, 0, 0, 0, loc)
	if sendAt.Before(today.Start) {
		sendAt = today.Start
	}
	if now.Before(sendAt) {
		return false
	}

	s.reminderMu.Lock()
	defer s.reminderMu.Unlock()
	if s.reminderSent == today.Date {
		return false
	}
	days, err := s.pendingDays(cal, now)
	if err != nil {
		log.Printf("[DailyReview] 逾期檢查查詢失敗: %v", err)
		return false
	}
	overdue := 0
	dates := make([]string, 0, len(days))
	for _, d := range days {
		dates = append(dates, d.Date)
		if d.Overdue(now) {
			overdue++
		}
	}
	if overdue == 0 {
		return false
	}
	s.sendOverdue(OverdueParams(dates, overdue, today.TZ))
	s.reminderSent = today.Date
	log.Printf("[DailyReview] %d 天未簽核（%d 天逾期，最早 %s），已發送逾期提醒", len(dates), overdue, dates[0])
	return true
}

// sendOverdue 經通知通道送出；測試以 overdueSink 攔截參數
func (s *DailyReviewService) sendOverdue(params map[string]string) {
	if s.overdueSink != nil {
		s.overdueSink(params)
		return
	}
	if notifier := GetAlertNotifier(); notifier != nil {
		notifier.NotifyEvent(notifycat.EventDailyReviewOverdue, params)
	}
}

// OverdueParams 逾期提醒的事件參數：date 保留為最早未簽日，日期清單只帶最早的 31 個，
// pending_count 為真實總數
func OverdueParams(dates []string, overdue int, timezone string) map[string]string {
	return map[string]string{
		"date":                  dates[0],
		"pending_dates":         notifycat.DateList(dates),
		"pending_count":         strconv.Itoa(len(dates)),
		"overdue_count":         strconv.Itoa(overdue),
		"earliest_pending_date": dates[0],
		"timezone":              timezone,
	}
}
