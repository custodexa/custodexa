package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

var (
	// ErrAlertNotFound 告警不存在
	ErrAlertNotFound = errors.New("告警不存在")
	// ErrInvalidDisposition 處置分類不合法
	ErrInvalidDisposition = errors.New("處置分類不合法")
)

// CommandAlertFilter 告警查詢條件（與 SessionCommandFilter 同形：審計查詢一致體驗）
type CommandAlertFilter struct {
	Severity   string     // severity 過濾（high/medium/low）
	UserID     *uint      // 用戶過濾
	AssetID    *uint      // 資產過濾
	StartTime  *time.Time // 觸發時間（起）
	EndTime    *time.Time // 觸發時間（迄）
	Unreviewed bool       // 僅列未審閱（reviewed_at IS NULL），供每日審閱走查（10.4.1）
	Page       int        // 頁碼（從 1 開始）
	PageSize   int        // 每頁大小
}

// CommandAlertView 告警記錄＋關聯名稱（仿 SessionCommandView：列表免前端二次查詢）
type CommandAlertView struct {
	model.CommandAlert
	Username  string `json:"username"`
	AssetName string `json:"asset_name"`
}

// CommandAlertListResponse 告警列表回應（沿用 {data,total,page,page_size} 慣例）
type CommandAlertListResponse struct {
	Data     []CommandAlertView `json:"data"`
	Total    int64              `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
}

// CommandAlertService 告警查詢服務（command-alerts D4）
type CommandAlertService struct {
	db *gorm.DB
}

// NewCommandAlertService 創建告警查詢服務
func NewCommandAlertService(db *gorm.DB) *CommandAlertService {
	return &CommandAlertService{db: db}
}

// CountUnreviewedBySeverity 回傳依嚴重度分的未審閱告警數（供指標曝光）。
//
// **未審閱的定義取 `reviewed_at IS NULL`**，與 `CommandAlertFilter.Unreviewed`
// 同一判準（PCI 10.4.1 的每日審閱走查）。不以 `disposition` 判定——那一欄是
// 處置種類，其可取值日後可能增減，而「有沒有人看過」的語義只由 reviewed_at 承載。
//
// 查詢落在本模組而非組裝根：`command_alerts` 是本模組擁有的表，
// 由外部直接查會撞跨模組資料存取 ratchet，且使邊界只剩人為約定。
func (s *CommandAlertService) CountUnreviewedBySeverity() (map[string]int64, error) {
	var rows []struct {
		Severity string
		N        int64
	}
	if err := s.db.Model(&model.CommandAlert{}).
		Select("severity, count(*) as n").
		Where("reviewed_at IS NULL").
		Group("severity").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Severity] = r.N
	}
	return out, nil
}

// List 告警查詢：rule_name/severity 為觸發快照冗餘欄位，免 JOIN alert_rules
func (s *CommandAlertService) List(filter *CommandAlertFilter) (*CommandAlertListResponse, error) {
	query := s.db.Model(&model.CommandAlert{})

	if filter.Severity != "" {
		query = query.Where("severity = ?", filter.Severity)
	}
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.AssetID != nil {
		query = query.Where("asset_id = ?", *filter.AssetID)
	}
	if filter.StartTime != nil {
		query = query.Where("triggered_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("triggered_at <= ?", *filter.EndTime)
	}
	if filter.Unreviewed {
		query = query.Where("reviewed_at IS NULL")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("查詢告警總數失敗: %w", err)
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}

	var alerts []CommandAlertView
	if err := query.
		Select("command_alerts.*, users.username AS username, assets.name AS asset_name").
		Joins("LEFT JOIN users ON users.id = command_alerts.user_id").
		Joins("LEFT JOIN assets ON assets.id = command_alerts.asset_id").
		Order("triggered_at DESC, id DESC").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&alerts).Error; err != nil {
		return nil, fmt.Errorf("查詢告警列表失敗: %w", err)
	}

	return &CommandAlertListResponse{
		Data:     alerts,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// Review 審閱處置一筆告警（audit-workflows D3，PCI 10.4.1）：記複審者/時間/處置分類/備註。
// disposition 僅接受 benign/escalated（pending 是未審閱狀態，不可主動設回）。
// 冪等：重覆審閱同一告警視為更新處置（可修正誤判），reviewed_at 刷新為最新
func (s *CommandAlertService) Review(alertID, reviewerID uint, disposition, note string) error {
	if disposition != model.AlertDispositionBenign && disposition != model.AlertDispositionEscalated {
		return ErrInvalidDisposition
	}

	res := s.db.Model(&model.CommandAlert{}).
		Where("id = ?", alertID).
		Updates(map[string]interface{}{
			"reviewed_by": reviewerID,
			"reviewed_at": time.Now(),
			"disposition": disposition,
			"note":        note,
		})
	if res.Error != nil {
		return fmt.Errorf("審閱告警失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrAlertNotFound
	}
	return nil
}
