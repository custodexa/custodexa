package audit

import (
	"archive/zip"
	"fmt"
	"io"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
)

// 證據包的每日簽核紀錄段（daily_reviews.csv）。
//
// **未簽的日子也是一列**：證據只列已簽的日子時，漏簽的那幾天會在證據裡消失，
// 而那正是評鑑者要看的。時間窗內、在啟用範圍內的每一個所屬日一列，含未簽與
// 尚未到期者；有簽核紀錄的日子一律收錄。
//
// 不隨類別篩選、不隨樞紐改變：簽核是平台層的審閱證據，不屬於六類事件來源；
// 每日審閱涵蓋全部安全事件，以使用者、資產或會話為樞紐並不改變那一天是否被審閱。
// 事件報告不收此段。

// maxExportDailyReviews 每日簽核段自己的上限（十年）與自己的截斷標示
const maxExportDailyReviews = 3660

// exportDailyReviewSection manifest 的每日簽核段鍵名（Counts／Totals／Truncated 用）
const exportDailyReviewSection = "daily_reviews"

// DailyReviewSignoffRetention 簽核紀錄本身不在任何自動清除範圍內（保留覆蓋第一層）
const DailyReviewSignoffRetention = "not_retained"

// DailyReviewLedgerSource 證據包取逐日清單的來源（由 DailyReviewService 滿足）
type DailyReviewLedgerSource interface {
	DailyReviewLedger(start, end *time.Time, limit int) ([]policy.SignoffDay, int, bool, error)
}

// ExportDailyReviewStats 清單檔的每日簽核段。
//
// 保留覆蓋分兩層說：簽核紀錄本身不受自動清除（SignoffRetention），但每列計數
// 所依據的操作日誌與告警會被清除——**不得只因簽核紀錄不清除就把整段說成完整**，
// 故另記來源為部分清除與已清除的列數。
type ExportDailyReviewStats struct {
	// Rows 收錄列數（截斷後）；InRange 範圍內真實列數
	Rows      int  `json:"rows"`
	InRange   int  `json:"in_range"`
	Truncated bool `json:"truncated"`
	// NotFilteredByType 此段不隨類別篩選（恆為 true）
	NotFilteredByType bool `json:"not_filtered_by_type"`
	// PivotIndependent 以使用者、資產或會話為樞紐時仍收錄同一時間窗（恆為 true）
	PivotIndependent bool `json:"pivot_independent"`
	// SignoffRetention 簽核紀錄本身的保留狀態
	SignoffRetention string `json:"signoff_retention"`
	// SourcePartialRows／SourcePurgedRows 任一事件來源為部分清除／已清除的列數
	SourcePartialRows int `json:"source_partial_rows"`
	SourcePurgedRows  int `json:"source_purged_rows"`
	// PresumedRows 啟用依據為推定的列數
	PresumedRows int `json:"presumed_rows"`
}

// SetDailyReviewLedger 注入每日簽核的逐日清單來源（組裝根呼叫）。
// 未注入時證據包整包失敗：缺了這一段的包看起來完整，實則少了審閱證據。
func (s *AuditExportService) SetDailyReviewLedger(src DailyReviewLedgerSource) {
	s.dailyReviews = src
}

// writeDailyReviews 寫 daily_reviews.csv 並記清單檔的每日簽核段。
// 來源回錯誤時整包失敗，不輸出一個空白卻成功的段落。
func (s *AuditExportService) writeDailyReviews(zw *zip.Writer, filter *ExportFilter, manifest *ExportManifest) error {
	if s.dailyReviews == nil {
		return fmt.Errorf("每日簽核紀錄來源未注入，拒絕產出缺審閱證據的包")
	}
	days, total, truncated, err := s.dailyReviews.DailyReviewLedger(filter.StartTime, filter.EndTime, maxExportDailyReviews)
	if err != nil {
		return fmt.Errorf("取每日簽核紀錄失敗: %w", err)
	}
	if err := s.writeEntry(zw, policy.DailyReviewsCSVName, manifest, func(out io.Writer) error {
		return policy.WriteDailyReviewsCSV(out, days)
	}); err != nil {
		return err
	}

	stats := &ExportDailyReviewStats{
		Rows: len(days), InRange: total, Truncated: truncated,
		NotFilteredByType: true, PivotIndependent: true, SignoffRetention: DailyReviewSignoffRetention,
	}
	for _, d := range days {
		switch {
		case d.AuditLogSource == model.DailyReviewSourcePurged || d.CommandAlertSource == model.DailyReviewSourcePurged:
			stats.SourcePurgedRows++
		case d.AuditLogSource == model.DailyReviewSourcePartial || d.CommandAlertSource == model.DailyReviewSourcePartial:
			stats.SourcePartialRows++
		}
		if reviewcal.IsPresumedBasis(d.EnabledBasis) {
			stats.PresumedRows++
		}
	}
	manifest.Counts[exportDailyReviewSection] = len(days)
	manifest.Truncated[exportDailyReviewSection] = truncated
	if manifest.Totals == nil {
		manifest.Totals = map[string]int64{}
	}
	manifest.Totals[exportDailyReviewSection] = int64(total)
	manifest.DailyReviews = stats
	return nil
}
