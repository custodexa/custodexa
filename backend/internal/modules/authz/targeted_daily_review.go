package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 每日簽核提醒的收件人在授權面的兩件事：候選人上界與「能簽核且能進入簽核頁」。
// 功能是否啟用、提醒所列的日子是否仍未簽屬於 audit 模組（每日簽核的資料在那裡），由 audit 的判定組合。

// dailyReviewSignRoute、dailyReviewPendingRoute 簽核與待簽清單的路由（與路由登錄同一組鍵）。
const (
	dailyReviewSignMethod    = "POST"
	dailyReviewSignPath      = "/api/v1/daily-reviews"
	dailyReviewPendingMethod = "GET"
	dailyReviewPendingPath   = "/api/v1/daily-reviews/pending"
)

// dailyReviewCandidatesSQL 啟用、未刪除的 human 使用者中有任何角色指派者（直接指派，或屬於仍存在且有角色指派的群組）。
// 這只是上界：沒有任何指派的帳號套一般使用者範本，沒有簽核與檢視操作日誌的能力；超級管理者本身就是一筆角色指派。
const dailyReviewCandidatesSQL = `SELECT u.id FROM users u
WHERE u.deleted_at IS NULL AND u.active = ? AND u.kind <> ?
  AND (EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id)
    OR EXISTS (SELECT 1 FROM user_group_members gm
      JOIN user_groups g ON g.id = gm.user_group_id AND g.deleted_at IS NULL
      JOIN user_group_roles gr ON gr.user_group_id = gm.user_group_id
      WHERE gm.user_id = u.id))
ORDER BY u.id`

// DailyReviewSignerCandidates 每日簽核提醒的候選人（遞增排序）。
func DailyReviewSignerCandidates(db *gorm.DB) ([]uint, error) {
	var ids []uint
	if err := db.Raw(dailyReviewCandidatesSQL, true, model.KindAgent).Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("查詢每日簽核候選人失敗: %w", err)
	}
	return ids, nil
}

// DailyReviewSignerAllowed 這位使用者能否簽核且能進入簽核頁：以路由守門用的同一個解析與判定，
// 簽核端點與待簽清單端點都放行才成立（只有簽核權、沒有檢視權的人點進操作日誌頁會被導回儀表板）。
// 帳號須為啟用、未刪除的 human。
func DailyReviewSignerAllowed(db *gorm.DB, userID uint) (bool, error) {
	if ok, err := liveHumanUser(db, userID); err != nil || !ok {
		return false, err
	}
	p, err := ResolveUserOn(db, userID, TokenFacts{SubjectKind: model.KindHuman})
	if err != nil {
		return false, err
	}
	if !DecideRoute(dailyReviewSignMethod, dailyReviewSignPath, p).Allowed {
		return false, nil
	}
	return DecideRoute(dailyReviewPendingMethod, dailyReviewPendingPath, p).Allowed, nil
}
