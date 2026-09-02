package asset

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 輪替證據報告工作單的篩選快照。
//
// 這份 JSON 是**發起與打包之間唯一的傳遞面**：受理時存進工作單，打包時原樣讀回。
// 故它必須自足——排隊期間排程被改名或刪除，都不該影響已受理的那一份報告長什麼樣。

// ReportJobFilter 報告工作單的篩選快照。
type ReportJobFilter struct {
	// ScopeKind／ScopeID 報告範圍，見 model.RotationScope* 常數
	ScopeKind string `json:"scope_kind"`
	ScopeID   uint   `json:"scope_id"`
	// PeriodStart／PeriodEnd 記錄區間 [起, 迄)
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	// Language 報告語言（一份報告一種語言）
	Language string `json:"language"`
	// ScheduleID／ScheduleName 排程產出時的來源排程；手動產出時為零值
	ScheduleID   uint   `json:"schedule_id,omitempty"`
	ScheduleName string `json:"schedule_name,omitempty"`
	// GeneratedBy 發起者的人可讀識別（使用者名或排程名），印在封面與清單檔。
	// **不進去重鍵**（見 DedupeKey）：它不影響產物內容
	GeneratedBy string `json:"generated_by,omitempty"`
}

// Marshal 序列化為工作單的篩選快照。
func (f ReportJobFilter) Marshal() (string, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("序列化報告參數失敗: %w", err)
	}
	return string(data), nil
}

// DedupeKey 去重用的正規化字串：清掉「不影響產物內容」的欄位後再序列化。
//
// 兩個人同時要同一份報告時該拿到同一張工作單，故發起者不進鍵；排程識別留著，
// 因為同參數但來自不同排程的兩份報告，留存期與封面署名都不同。
func (f ReportJobFilter) DedupeKey() (string, error) {
	f.GeneratedBy = ""
	data, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("序列化報告去重鍵失敗: %w", err)
	}
	return string(data), nil
}

// ParseReportJobFilter 讀回篩選快照。
func ParseReportJobFilter(snapshot string) (*ReportJobFilter, error) {
	var f ReportJobFilter
	if err := json.Unmarshal([]byte(snapshot), &f); err != nil {
		return nil, fmt.Errorf("解析報告參數失敗: %w", err)
	}
	return &f, nil
}

// ReportJobDisplay 下載中心列表用的顯示投影。
//
// 解析不出來時回空 map 而不是錯誤：清單的一列少一段摘要，好過整份清單變成錯誤。
func ReportJobDisplay(snapshot string) map[string]string {
	out := map[string]string{}
	f, err := ParseReportJobFilter(snapshot)
	if err != nil {
		return out
	}
	out["scope_kind"] = f.ScopeKind
	if f.ScopeID != 0 {
		out["scope_id"] = fmt.Sprintf("%d", f.ScopeID)
	}
	out["period_start"] = f.PeriodStart.Format(time.RFC3339)
	out["period_end"] = f.PeriodEnd.Format(time.RFC3339)
	out["language"] = f.Language
	if f.ScheduleName != "" {
		out["schedule_name"] = f.ScheduleName
	}
	if f.GeneratedBy != "" {
		out["generated_by"] = f.GeneratedBy
	}
	return out
}

// ValidateReportScope 範圍與語言的值域檢查（發起端與排程 CRUD 共用同一份判準）。
func ValidateReportScope(kind string, id uint) error {
	switch kind {
	case model.RotationScopeAll:
		if id != 0 {
			return ErrReportBadScope
		}
	case model.RotationScopeNode, model.RotationScopePlan:
		if id == 0 {
			return ErrReportBadScope
		}
	default:
		return ErrReportBadScope
	}
	return nil
}
