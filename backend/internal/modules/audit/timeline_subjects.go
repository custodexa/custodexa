package audit

import (
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// TimelineSubjectRef 稽核專用的最小主體條目（D7）。
//
// **欄位刻意極少**：本端點存在的理由是 `/users` 全組 admin-only，auditor 挑不了人；
// 而放寬 `/users` 會把 email、角色、外部身分、鎖定狀態一併交出去。
// 加任何一個欄位進來，都等於用另一條路重新開放那些資料，
// 故此結構的欄位集合由 handler 側的白名單測試釘住
type TimelineSubjectRef struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	Deleted     bool   `json:"deleted"`
}

const timelineSubjectMaxLimit = 50

// ListSubjects 主體目錄查詢。
//
// **已停用與已軟刪的主體一律回得到並標記**：調查對象常已離職或資產已下架，
// 把他們濾掉會讓工作台在最需要用的場合查不到人——而那不是「查無此人」，
// 是工具把證據藏起來了
func (s *TimelineService) ListSubjects(kind TimelineSubject, q string, limit int) ([]TimelineSubjectRef, error) {
	if limit <= 0 || limit > timelineSubjectMaxLimit {
		limit = timelineSubjectMaxLimit
	}
	like := "%" + strings.ToLower(strings.TrimSpace(q)) + "%"

	out := make([]TimelineSubjectRef, 0, limit)
	if kind == SubjectAsset {
		// assets 的啟用旗標是 `active`（布林），**不是 `status`**——
		// 寫成 status 會在 SQL 層直接炸（42703），而不是靜默回錯資料
		var rows []struct {
			ID        uint
			Name      string
			Host      string
			Active    bool
			DeletedAt *string
		}
		tx := s.db.Unscoped().Model(&model.Asset{}).
			Select("id, name, host, active, deleted_at")
		if strings.TrimSpace(q) != "" {
			tx = tx.Where("LOWER(name) LIKE ? OR LOWER(host) LIKE ?", like, like)
		}
		if err := tx.Order("name ASC").Limit(limit).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, TimelineSubjectRef{
				ID:          r.ID,
				Name:        r.Name,
				DisplayName: r.Host,
				Active:      r.Active,
				Deleted:     r.DeletedAt != nil,
			})
		}
		return out, nil
	}

	var rows []struct {
		ID               uint
		Username         string
		FullName         string
		LocalDisplayName *string
		Active           bool
		DeletedAt        *string
	}
	tx := s.db.Unscoped().Model(&model.User{}).
		Select("id, username, full_name, local_display_name, active, deleted_at")
	if strings.TrimSpace(q) != "" {
		tx = tx.Where("LOWER(username) LIKE ? OR LOWER(full_name) LIKE ?", like, like)
	}
	if err := tx.Order("username ASC").Limit(limit).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		display := r.FullName
		if r.LocalDisplayName != nil && *r.LocalDisplayName != "" {
			display = *r.LocalDisplayName
		}
		if display == "" {
			display = r.Username
		}
		out = append(out, TimelineSubjectRef{
			ID:          r.ID,
			Name:        r.Username,
			DisplayName: display,
			Active:      r.Active,
			Deleted:     r.DeletedAt != nil,
		})
	}
	return out, nil
}
