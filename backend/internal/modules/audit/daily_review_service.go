package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
	"gorm.io/gorm"
)

// 每日審閱簽核（PCI 10.4.1/10.4.1.1）。
//
// 審閱單位是業務時區下已經結束的一天（所屬日），快照涵蓋該日 00:00 至 24:00 整天；
// 日終後另有 30 分鐘落庫寬限。所屬日與簽核時刻分欄，簽核時刻只由伺服器寫入。
// 「哪些日子要簽、各用哪個時區切」由政策變更歷史推得（reviewcal），讀取時計算、
// 不物化。規則全部在伺服器端執行，繞過介面呼叫 API 也不能倒填、跳過延遲原因、
// 或在告警未處置時簽核。

// ErrAlreadySigned 該所屬日已有簽核記錄
var ErrAlreadySigned = errors.New("該日已完成簽核")

// 簽核與查詢的規則錯誤（handler 依此轉為錯誤碼）
var (
	ErrDailyReviewDateInvalid         = errors.New("所屬日不是 YYYY-MM-DD")
	ErrDailyReviewDayNotEnded         = errors.New("該日尚未結束")
	ErrDailyReviewOutOfScope          = errors.New("該日不在啟用範圍內")
	ErrDailyReviewDelayReasonRequired = errors.New("遲簽須填寫延遲原因")
	ErrDailyReviewPeriodInvalid       = errors.New("統計期間不合法")
)

// DailyReviewTextMaxRunes 備註與延遲原因的長度上限（Unicode code point）
const DailyReviewTextMaxRunes = 500

// AlreadySignedError 該日已由他人簽核，附既有紀錄的所屬日、簽核者、完整簽核時刻與時區。
//
// 「誰、在什麼時刻簽的」是使用者判斷「不是我漏簽、無須再追」的必需資訊；handler
// 無法從 sentinel 反推，故以具名欄位帶出。errors.Is(err, ErrAlreadySigned) 續可比對。
type AlreadySignedError struct {
	Date     string
	Signer   string
	SignedAt time.Time
	Timezone string
}

func (e *AlreadySignedError) Error() string {
	return fmt.Sprintf("%s（%s 由 %s 於 %s 簽核）", ErrAlreadySigned.Error(), e.Date, e.Signer, e.SignedAt.Format(time.RFC3339))
}

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *AlreadySignedError) Unwrap() error { return ErrAlreadySigned }

// DailyReviewSettlingError 該日已結束但仍在落庫寬限內，附可簽時刻
type DailyReviewSettlingError struct{ SignableAt time.Time }

func (e *DailyReviewSettlingError) Error() string {
	return "該日仍在落庫寬限內，" + e.SignableAt.Format(time.RFC3339) + " 起可簽"
}

// DailyReviewAlertsPendingError 該日仍有未審閱告警
type DailyReviewAlertsPendingError struct{ Count int64 }

func (e *DailyReviewAlertsPendingError) Error() string {
	return fmt.Sprintf("該日仍有 %d 筆未審閱告警", e.Count)
}

// DailyReviewTextTooLongError 備註或延遲原因超過上限；Field 為 note 或 delay_reason
type DailyReviewTextTooLongError struct{ Field string }

func (e *DailyReviewTextTooLongError) Error() string {
	return e.Field + " 超過 500 字"
}

// DailyReviewService 每日審閱簽核
type DailyReviewService struct {
	db     *gorm.DB
	policy *policy.SecurityPolicyService
	audit  auditLogger
	now    func() time.Time

	// reminderSent 逾期提醒當日已送的業務時區日期（記憶體；重啟後當日可能再送一次）
	reminderMu   sync.Mutex
	reminderSent string
	// overdueSink 非 nil 時逾期提醒改交給它（僅測試設定；正式路徑走通知單例）
	overdueSink func(params map[string]string)
}

// NewDailyReviewService 建立每日審閱服務
func NewDailyReviewService(db *gorm.DB, policy *policy.SecurityPolicyService, audit auditLogger) *DailyReviewService {
	return &DailyReviewService{db: db, policy: policy, audit: audit, now: time.Now}
}

// SetClock 替換時鐘（測試以固定時刻驗證日界、寬限與準時期限）
func (s *DailyReviewService) SetClock(now func() time.Time) { s.now = now }

// Now 服務目前的時刻
func (s *DailyReviewService) Now() time.Time { return s.now() }

// Enabled 每日審閱功能是否啟用（政策 daily_review_enabled）
func (s *DailyReviewService) Enabled() bool {
	return s.policy.GetBool(policy.PolicyDailyReviewEnabled)
}

// Calendar 由政策變更歷史算出行事曆（行事曆、提醒排程與統計共用同一個解析器）
func (s *DailyReviewService) Calendar(now time.Time) (*reviewcal.Calendar, error) {
	rows, err := s.policy.History(policy.PolicyDailyReviewEnabled, policy.PolicyDailyReviewTimezone)
	if err != nil {
		return nil, err
	}
	in := reviewcal.Inputs{CurrentTZ: s.policy.Get(policy.PolicyDailyReviewTimezone)}
	for _, r := range rows {
		ch := reviewcal.Change{At: r.ChangedAt, Old: r.OldValue, New: r.NewValue, Source: r.Source}
		switch r.PolicyKey {
		case policy.PolicyDailyReviewEnabled:
			in.Enabled = append(in.Enabled, ch)
		case policy.PolicyDailyReviewTimezone:
			in.TZ = append(in.TZ, ch)
		}
	}
	return reviewcal.Build(in, now), nil
}

// SignRequest 簽核請求。簽核時刻不在其中：一律由伺服器於受理時取當下時間
type SignRequest struct {
	ReviewDate   string
	Note         string
	DelayReason  string
	ReviewerID   uint
	ReviewerName string
}

// Sign 簽核指定所屬日。
//
// 檢查順序：日期格式 → 文字長度 → 已結束 → 寬限 → 已簽（409）→ 啟用範圍 → 延遲原因
// → 交易內（未審閱告警、快照、寫入）。唯一索引衝突（兩個交易同時通過「查無」）
// 同樣轉為 AlreadySignedError，取回的是贏家的紀錄。
func (s *DailyReviewService) Sign(req SignRequest) (*model.DailyReviewLog, error) {
	if _, ok := reviewcal.ParseDate(req.ReviewDate); !ok {
		return nil, ErrDailyReviewDateInvalid
	}
	if utf8.RuneCountInString(req.Note) > DailyReviewTextMaxRunes {
		return nil, &DailyReviewTextTooLongError{Field: "note"}
	}
	reason := strings.TrimSpace(req.DelayReason)
	if utf8.RuneCountInString(reason) > DailyReviewTextMaxRunes {
		return nil, &DailyReviewTextTooLongError{Field: "delay_reason"}
	}

	now := s.now()
	cal, err := s.Calendar(now)
	if err != nil {
		return nil, err
	}
	if beyondTomorrow(cal, req.ReviewDate) {
		return nil, ErrDailyReviewDayNotEnded
	}
	day, ok := cal.Lookup(req.ReviewDate)
	if !ok {
		return nil, ErrDailyReviewOutOfScope
	}
	if !day.Ended(now) {
		return nil, ErrDailyReviewDayNotEnded
	}
	if !day.Signable(now) {
		return nil, &DailyReviewSettlingError{SignableAt: day.SignableAt}
	}
	if existing, err := s.findSigned(s.db, req.ReviewDate); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, alreadySigned(existing)
	}
	if !day.InScope {
		return nil, ErrDailyReviewOutOfScope
	}
	late := !now.Before(day.DueAt)
	var delayReason *string
	if late {
		if reason == "" {
			return nil, ErrDailyReviewDelayReasonRequired
		}
		delayReason = &reason
	}

	watermarks, err := NewRetentionWatermarkService(s.db).Load()
	if err != nil {
		return nil, fmt.Errorf("讀取保留水位: %w", err)
	}

	var row *model.DailyReviewLog
	var snap *DailyReviewSnapshot
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var pending int64
		if err := alertScope(tx, day.Start, day.End).Where("reviewed_at IS NULL").Count(&pending).Error; err != nil {
			return fmt.Errorf("統計未審閱告警數: %w", err)
		}
		if pending > 0 {
			return &DailyReviewAlertsPendingError{Count: pending}
		}
		var err error
		snap, err = computeSnapshot(tx, req.ReviewDate, day.Start, day.End, watermarks)
		if err != nil {
			return err
		}
		snapJSON, err := json.Marshal(snap)
		if err != nil {
			return fmt.Errorf("快照序列化: %w", err)
		}
		if existing, err := s.findSigned(tx, req.ReviewDate); err != nil {
			return err
		} else if existing != nil {
			return alreadySigned(existing)
		}
		row = &model.DailyReviewLog{
			ReviewDate:       req.ReviewDate,
			ReviewerID:       req.ReviewerID,
			ReviewerName:     req.ReviewerName,
			SnapshotJSON:     string(snapJSON),
			Note:             req.Note,
			SignedAt:         now,
			Timezone:         day.TZ,
			TimezoneInferred: day.TZInferred,
			WindowStart:      day.Start,
			WindowEnd:        day.End,
			DueAt:            day.DueAt,
			Late:             late,
			DelayReason:      delayReason,
			Coverage:         model.DailyReviewCoverageFullDay,
			SourceStatus:     snap.worstSource(),
			EnabledBasis:     day.Basis,
		}
		if hook := dailyReviewSignHooks.beforeInsert; hook != nil {
			hook()
		}
		return tx.Create(row).Error
	})
	if err != nil {
		if dberr.IsUniqueViolation(err) {
			existing, findErr := s.findSigned(s.db, req.ReviewDate)
			if findErr == nil && existing != nil {
				return nil, alreadySigned(existing)
			}
			return nil, &AlreadySignedError{Date: req.ReviewDate}
		}
		return nil, err
	}

	if s.audit != nil {
		details, _ := json.Marshal(map[string]any{
			"review_date": row.ReviewDate,
			"timezone":    row.Timezone,
			"signed_at":   row.SignedAt.Format(time.RFC3339Nano),
			"late":        row.Late,
			"late_days":   lateDaysOf(row),
			"snapshot":    snap,
		})
		s.audit.Log(&AuditLogEntry{
			UserID: req.ReviewerID, Username: req.ReviewerName,
			Action: model.ActionCreate, Resource: model.ResourceDailyReview,
			ResourceID: &row.ID, Status: model.StatusSuccess,
			Details: string(details),
		})
	}
	return row, nil
}

// dailyReviewSignHooks 測試同步點（生產為 nil）：搶簽測試在兩個交易都通過「查無」後才放行寫入
var dailyReviewSignHooks struct {
	beforeInsert func()
}

func (s *DailyReviewService) findSigned(db *gorm.DB, date string) (*model.DailyReviewLog, error) {
	var existing model.DailyReviewLog
	switch err := db.Where("review_date = ?", date).First(&existing).Error; {
	case err == nil:
		return &existing, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("查詢既有簽核: %w", err)
	}
}

func alreadySigned(row *model.DailyReviewLog) *AlreadySignedError {
	return &AlreadySignedError{Date: row.ReviewDate, Signer: row.ReviewerName, SignedAt: row.SignedAt, Timezone: row.Timezone}
}

// lateDaysOf 遲簽晚幾天（準時為 0）
func lateDaysOf(row *model.DailyReviewLog) int {
	if !row.Late {
		return 0
	}
	return reviewcal.LateDays(row.ReviewDate, row.Timezone, row.SignedAt)
}

// DailyReviewRecord 已簽紀錄的對外形狀：簽核列加上晚幾天
type DailyReviewRecord struct {
	model.DailyReviewLog
	LateDays int `json:"late_days"`
}

func toRecord(row model.DailyReviewLog) DailyReviewRecord {
	return DailyReviewRecord{DailyReviewLog: row, LateDays: lateDaysOf(&row)}
}

// List 簽核歷史（新到舊）；lateOnly 只列遲簽者
func (s *DailyReviewService) List(page, pageSize int, lateOnly bool) ([]DailyReviewRecord, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	q := s.db.Model(&model.DailyReviewLog{})
	if lateOnly {
		q = q.Where("late = ?", true)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.DailyReviewLog
	if err := q.Order("review_date DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]DailyReviewRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, toRecord(r))
	}
	return out, total, nil
}

// signedRows 指定日期集合中已簽的列（依所屬日）
func (s *DailyReviewService) signedRows(dates []string) (map[string]model.DailyReviewLog, error) {
	out := map[string]model.DailyReviewLog{}
	if len(dates) == 0 {
		return out, nil
	}
	var rows []model.DailyReviewLog
	for start := 0; start < len(dates); start += 500 {
		end := start + 500
		if end > len(dates) {
			end = len(dates)
		}
		var chunk []model.DailyReviewLog
		if err := s.db.Where("review_date IN ?", dates[start:end]).Find(&chunk).Error; err != nil {
			return nil, fmt.Errorf("查詢已簽日: %w", err)
		}
		rows = append(rows, chunk...)
	}
	for _, r := range rows {
		out[r.ReviewDate] = r
	}
	return out, nil
}

// beyondTomorrow 日期晚於明天（業務時區）：入口直接回「尚未結束」，
// 不讓請求帶來的遠未來日期進到行事曆計算
func beyondTomorrow(cal *reviewcal.Calendar, date string) bool {
	return date > reviewcal.AddDays(cal.Today().Date, 1)
}
