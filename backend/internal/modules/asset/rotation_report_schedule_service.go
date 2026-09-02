package asset

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 輪替證據報告的排程與工作單發起。
//
// 排程只做一件事：到點時把「這一期」的參數凍結成一張下載中心工作單。打包、簽章、
// 離機、到期清理全部沿既有工作單機制，這裡不重做一份。

// 排程與發起的哨兵錯誤（handler 據此收斂機器碼）。
var (
	ErrReportScheduleNotFound    = errors.New("報告排程不存在")
	ErrReportScheduleNameExists  = errors.New("報告排程名稱已存在")
	ErrReportScheduleNameEmpty   = errors.New("報告排程名稱不可為空")
	ErrReportScheduleNameTooLong = errors.New("報告排程名稱長度超過上限")
	ErrReportBadCron             = errors.New("排程格式錯誤（標準 5 欄 cron）")
	ErrReportBadScope            = errors.New("報告範圍不合法")
	ErrReportBadLanguage         = errors.New("報告語言不在支援清單內")
	ErrReportBadRetention        = errors.New("留存天數須介於 1 與 3650 之間")
	ErrReportBadPeriod           = errors.New("記錄區間的起點須早於迄點")
	// ErrReportScheduleInflight 同一排程已有一張進行中的工作單。
	// 排程的節流就是這一條——沒有它，排程改成每分鐘就會把打包佇列塞滿
	ErrReportScheduleInflight = errors.New("該排程已有一張進行中的報告工作單")
)

// 留存天數值域（與憑證最長使用天數同值域，理由相同：十年是任何稽核週期的上界）。
const (
	reportRetentionMinDays = 1
	reportRetentionMaxDays = 3650
)

// reportScheduleNameMaxLen 排程名長度上限（字），與該欄的儲存寬度同值。
// 在此驗而不交給資料庫報錯：後者只會落成一則無從辨識的內部錯誤。
const reportScheduleNameMaxLen = 128

// systemRequesterName 排程發起者的顯示名。RequesterID 0＋此名＝系統發起，
// 打包 worker 據前者免申請者重驗。
const systemRequesterName = "system"

// scheduleReloader 排程表變動後重建 cron 註冊（scheduler 側實作）。
type scheduleReloader interface {
	Reload()
}

// RotationReportScheduleService 排程 CRUD 與工作單發起。
type RotationReportScheduleService struct {
	db      *gorm.DB
	jobs    *audit.AuditExportJobService
	builder *RotationReportBuilder
	// reloader 排程表變動後的 cron 重載鉤子；nil＝未接（單元測試）
	reloader scheduleReloader
}

// NewRotationReportScheduleService 建立服務。
func NewRotationReportScheduleService(db *gorm.DB, jobs *audit.AuditExportJobService,
	builder *RotationReportBuilder) *RotationReportScheduleService {
	return &RotationReportScheduleService{db: db, jobs: jobs, builder: builder}
}

// SetReloader 接上 cron 重載鉤子（組裝根）。
func (s *RotationReportScheduleService) SetReloader(r scheduleReloader) { s.reloader = r }

func (s *RotationReportScheduleService) reload() {
	if s.reloader != nil {
		s.reloader.Reload()
	}
}

// List 全部排程（id 升冪）。
func (s *RotationReportScheduleService) List() ([]model.RotationReportSchedule, error) {
	var out []model.RotationReportSchedule
	if err := s.db.Order("id ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("查詢報告排程失敗: %w", err)
	}
	return out, nil
}

// Get 單筆排程。
func (s *RotationReportScheduleService) Get(id uint) (*model.RotationReportSchedule, error) {
	var row model.RotationReportSchedule
	if err := s.db.First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrReportScheduleNotFound
		}
		return nil, fmt.Errorf("查詢報告排程失敗: %w", err)
	}
	return &row, nil
}

// Create 建立排程：區間錨點設為建立時刻——第一份報告涵蓋的是「排程存在之後」
// 發生的事，把錨點往前推等於憑空宣稱涵蓋了沒有排程的那段期間。
func (s *RotationReportScheduleService) Create(in *model.RotationReportSchedule) (*model.RotationReportSchedule, error) {
	if err := s.validate(in); err != nil {
		return nil, err
	}
	if err := s.ensureNameFree(in.Name, 0); err != nil {
		return nil, err
	}
	in.PeriodAnchor = time.Now()
	// `Enabled` 欄帶 DB 預設值 true，而 GORM 對帶 default 的欄位遇零值會改用預設值
	// ——直接 Create 會讓「建立時就停用」靜默變成啟用。故意圖先記下來，落庫後補寫。
	// 兩步同一交易：中間失敗不留一列與請求不符的排程
	enabled := in.Enabled
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(in).Error; err != nil {
			return err
		}
		if enabled {
			return nil
		}
		in.Enabled = false
		return tx.Model(&model.RotationReportSchedule{}).Where("id = ?", in.ID).
			Update("enabled", false).Error
	}); err != nil {
		return nil, fmt.Errorf("建立報告排程失敗: %w", err)
	}
	s.reload()
	return in, nil
}

// Update 修改排程。
//
// **cron 被改動時錨點重設為修改時刻**：週期換了以後，舊週期剩下的那一段對讀
// 報告的人已經沒有意義，讓它併進下一份只會產出一個長度說不出理由的區間。
// 其餘欄位的修改不動錨點。
func (s *RotationReportScheduleService) Update(id uint, in *model.RotationReportSchedule) (*model.RotationReportSchedule, error) {
	current, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if err := s.validate(in); err != nil {
		return nil, err
	}
	if err := s.ensureNameFree(in.Name, id); err != nil {
		return nil, err
	}
	updates := map[string]any{
		"name":           in.Name,
		"cron":           in.Cron,
		"enabled":        in.Enabled,
		"scope_kind":     in.ScopeKind,
		"scope_id":       in.ScopeID,
		"retention_days": in.RetentionDays,
		"language":       in.Language,
	}
	if in.Cron != current.Cron {
		updates["period_anchor"] = time.Now()
	}
	if err := s.db.Model(&model.RotationReportSchedule{}).Where("id = ?", id).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新報告排程失敗: %w", err)
	}
	s.reload()
	return s.Get(id)
}

// Delete 刪除排程。已受理的工作單不受影響——它的參數在受理時就凍結了。
func (s *RotationReportScheduleService) Delete(id uint) error {
	res := s.db.Delete(&model.RotationReportSchedule{}, id)
	if res.Error != nil {
		return fmt.Errorf("刪除報告排程失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrReportScheduleNotFound
	}
	s.reload()
	return nil
}

// validate 欄位值域（建立與修改共用）。
func (s *RotationReportScheduleService) validate(in *model.RotationReportSchedule) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return ErrReportScheduleNameEmpty
	}
	if utf8.RuneCountInString(in.Name) > reportScheduleNameMaxLen {
		return ErrReportScheduleNameTooLong
	}
	if _, err := cronParser.Parse(in.Cron); err != nil {
		return ErrReportBadCron
	}
	if err := s.ValidateScopeExists(in.ScopeKind, in.ScopeID); err != nil {
		return err
	}
	if in.RetentionDays < reportRetentionMinDays || in.RetentionDays > reportRetentionMaxDays {
		return ErrReportBadRetention
	}
	if !model.ValidNotificationChannelLanguage(in.Language) {
		return ErrReportBadLanguage
	}
	return nil
}

// ValidateScopeExists 範圍值域＋存在性。
//
// 存在性在**受理時**驗，而不是等到打包才發現——一張註定失敗的工作單會安靜地
// 重試三次然後以打包失敗告終，發起者看不出真正的原因是節點被刪了。
func (s *RotationReportScheduleService) ValidateScopeExists(kind string, id uint) error {
	if err := ValidateReportScope(kind, id); err != nil {
		return err
	}
	switch kind {
	case model.RotationScopeNode:
		var count int64
		if err := s.db.Model(&model.AssetGroup{}).Where("id = ?", id).Count(&count).Error; err != nil {
			return fmt.Errorf("查詢節點失敗: %w", err)
		}
		if count == 0 {
			return ErrReportBadScope
		}
	case model.RotationScopePlan:
		var count int64
		if err := s.db.Model(&model.ChangeSecretPlan{}).Where("id = ?", id).Count(&count).Error; err != nil {
			return fmt.Errorf("查詢改密計劃失敗: %w", err)
		}
		if count == 0 {
			return ErrReportBadScope
		}
	}
	return nil
}

func (s *RotationReportScheduleService) ensureNameFree(name string, excludeID uint) error {
	q := s.db.Model(&model.RotationReportSchedule{}).Where("name = ?", name)
	if excludeID != 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return fmt.Errorf("查詢報告排程名稱失敗: %w", err)
	}
	if count > 0 {
		return ErrReportScheduleNameExists
	}
	return nil
}

// Trigger 依排程規則建立一張工作單，並把區間錨點推進到本次觸發時刻。
//
// 區間＝[錨點, 觸發時刻)，右開，故連續兩期首尾相接、同一筆記錄不會被兩份報告
// 各算一次。**建單成功才推進錨點**：失敗時錨點留在原處，下一次觸發自然把這一
// 段補回來，不會在區間上留下一個看不出來的空白。
//
// 「立即產出」走同一條路徑——它就是提前的一期。
func (s *RotationReportScheduleService) Trigger(id uint, now time.Time) (*model.AuditExportJob, error) {
	sched, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	filter := ReportJobFilter{
		ScopeKind:    sched.ScopeKind,
		ScopeID:      sched.ScopeID,
		PeriodStart:  sched.PeriodAnchor,
		PeriodEnd:    now,
		Language:     sched.Language,
		ScheduleID:   sched.ID,
		ScheduleName: sched.Name,
		GeneratedBy:  sched.Name,
	}
	expires := now.AddDate(0, 0, sched.RetentionDays)
	job, err := s.createJob(filter, systemRequesterName, 0, &expires, s.inflightGuard(sched.ID))
	if err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.RotationReportSchedule{}).Where("id = ?", sched.ID).
		Update("period_anchor", now).Error; err != nil {
		return nil, fmt.Errorf("推進報告區間錨點失敗: %w", err)
	}
	return job, nil
}

// CreateManualJob 手動產出：發起者是人，區間由發起者指定，保留期沿既有證據包。
// **不碰任何排程的錨點**——手動產出是額外的一份，不是某一期。
func (s *RotationReportScheduleService) CreateManualJob(filter ReportJobFilter,
	requesterName string, requesterID uint) (*model.AuditExportJob, error) {
	if err := s.ValidateScopeExists(filter.ScopeKind, filter.ScopeID); err != nil {
		return nil, err
	}
	if !model.ValidNotificationChannelLanguage(filter.Language) {
		return nil, ErrReportBadLanguage
	}
	if !filter.PeriodStart.Before(filter.PeriodEnd) {
		return nil, ErrReportBadPeriod
	}
	filter.ScheduleID = 0
	filter.ScheduleName = ""
	filter.GeneratedBy = requesterName
	return s.createJob(filter, requesterName, requesterID, nil, nil)
}

func (s *RotationReportScheduleService) createJob(filter ReportJobFilter, requesterName string,
	requesterID uint, expiresAt *time.Time, guard audit.ReportJobGuard) (*model.AuditExportJob, error) {
	filterJSON, err := filter.Marshal()
	if err != nil {
		return nil, err
	}
	dedupe, err := filter.DedupeKey()
	if err != nil {
		return nil, err
	}
	job, _, err := s.jobs.CreateReportJob(model.ExportJobKindRotationReport, filterJSON, dedupe,
		requesterName, requesterID, expiresAt, guard)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// inflightGuard 同一排程至多一張進行中的工作單。
//
// 判準留在這裡而不是工作單服務：排程識別在篩選快照裡，而那是本模組的格式。
func (s *RotationReportScheduleService) inflightGuard(scheduleID uint) audit.ReportJobGuard {
	return func(inflight []model.AuditExportJob) error {
		for i := range inflight {
			f, err := ParseReportJobFilter(inflight[i].FilterJSON)
			if err != nil {
				continue
			}
			if f.ScheduleID == scheduleID {
				return ErrReportScheduleInflight
			}
		}
		return nil
	}
}
