package audit

import (
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// TimelineSubjectRef 稽核專用的最小主體條目。
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

// TimelineIPSubject 位址樞紐的候選條目（自基準表導出）。
//
// 與 TimelineSubjectRef 是**不同形狀**：位址沒有整數 id、沒有啟停與軟刪語義，
// 硬塞進同一結構會逼出一堆恆空欄位。候選只是輸入便利——只含成功登入或建線過
// 的位址；只存在於拒絕列的位址由呼叫端自由輸入，任一合法位址皆可查詢
type TimelineIPSubject struct {
	IP         string    `json:"ip"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// escapeLikePrefix 前綴匹配的字面化：位址字串本不含萬用字元，
// 仍逐字轉義以免查詢參數被當 pattern 解讀
func escapeLikePrefix(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// seenAtLayouts sqlite 對 DATETIME 欄位回傳的字串形式（有無時區、
// 有無小數秒）。順序即嘗試順序
var seenAtLayouts = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
}

// coerceSeenAt 把驅動回傳的時刻值收斂為 time.Time。
//
// **為何需要它**：`MAX(last_seen_at)` 是運算式而非欄位，欄位的宣告型別在聚合
// 之後就沒了——PostgreSQL 仍回 timestamptz（驅動給 time.Time），sqlite 則一律
// 回字串。兩種驅動形狀在此收斂，呼叫端只看得到 time.Time。
//
// 無法辨識的形狀回零值——候選只是輸入便利，一筆時刻讀不出來不該讓
// 整個候選查詢失敗（位址本身仍可用，且任一合法位址皆可自由輸入）
func coerceSeenAt(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case *time.Time:
		if t != nil {
			return *t
		}
	case string:
		return parseSeenAt(t)
	case []byte:
		return parseSeenAt(string(t))
	}
	return time.Time{}
}

func parseSeenAt(s string) time.Time {
	for _, layout := range seenAtLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts
		}
	}
	return time.Time{}
}

// ListIPSubjects 位址候選：基準表 DISTINCT、前綴匹配、最近見到降序。
// 空前綴＝全表聚合（初次聚焦的候選），代價隨基準表大小線性——
// 表大小上界＝使用者數 × 相異位址數，plan 驗收見 research/subjects-ip-query-plan.md
func (s *TimelineService) ListIPSubjects(q string, limit int) ([]TimelineIPSubject, error) {
	if limit <= 0 || limit > timelineSubjectMaxLimit {
		limit = timelineSubjectMaxLimit
	}
	tx := s.db.Table("user_source_ips").
		Select("client_ip AS ip, MAX(last_seen_at) AS last_seen_at")
	if p := strings.TrimSpace(q); p != "" {
		tx = tx.Where(`client_ip LIKE ? ESCAPE '\'`, escapeLikePrefix(p)+"%")
	}
	// 逐列自行掃描而非 Scan(&struct)：聚合欄的驅動型別兩庫不同（見
	// coerceSeenAt），而 gorm 的結構掃描要求目的欄位有確定型別
	rows, err := tx.Group("client_ip").
		Order("last_seen_at DESC").
		Limit(limit).
		Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]TimelineIPSubject, 0, limit)
	for rows.Next() {
		var ip string
		var seen any
		if err := rows.Scan(&ip, &seen); err != nil {
			return nil, err
		}
		out = append(out, TimelineIPSubject{IP: ip, LastSeenAt: coerceSeenAt(seen)})
	}
	return out, rows.Err()
}

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
