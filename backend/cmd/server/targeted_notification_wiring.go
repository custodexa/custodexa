package main

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/notifycat"
)

// registerTargetedJudges 定向通知的收件人判定經投遞程序的對外埠登錄（audit 不依賴授權模組）：
// 連線申請建立、破窗使用與補審逾期由授權模組判定；每日審閱逾期由每日審閱服務判定，其授權面
// （候選人上界與兩個路由的放行判定）由授權模組以 SetSignerAccess 注入。
func registerTargetedJudges(w *audit.SystemAlertOutboxWorker, requests *authz.AccessRequestService, reviews *audit.DailyReviewService) error {
	reviews.SetSignerAccess(audit.DailyReviewSignerAccess{
		Candidates: authz.DailyReviewSignerCandidates,
		Allowed:    authz.DailyReviewSignerAllowed,
	})
	for event, judge := range requests.TargetedJudges() {
		if err := w.UseTargetedJudge(event, judge); err != nil {
			return err
		}
	}
	return w.UseTargetedJudge(notifycat.EventDailyReviewOverdue, reviews.TargetedJudge())
}
