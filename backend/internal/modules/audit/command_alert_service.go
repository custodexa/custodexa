package audit

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

var (
	// ErrAlertNotFound 告警不存在
	ErrAlertNotFound = errors.New("告警不存在")
	// ErrInvalidDisposition 處置分類不合法
	ErrInvalidDisposition = errors.New("處置分類不合法")
	// ErrAlertAlreadyReviewed 批次審閱送出時該告警已有審閱結果（不覆蓋）
	ErrAlertAlreadyReviewed = errors.New("告警已有審閱結果")
	// ErrAlertSelfTriggered 批次審閱不收審閱者自己連線觸發的告警
	ErrAlertSelfTriggered = errors.New("自己觸發的告警須逐筆審閱")
	// ErrAlertBatchNote 批次審閱的理由為空或超過上限
	ErrAlertBatchNote = errors.New("批次審閱理由不合法")
	// ErrAlertNoteTooLong 單筆審閱的理由超過上限
	ErrAlertNoteTooLong = errors.New("審閱理由超過字數上限")
)

// maxAlertBatchNoteRunes 審閱理由的字數上限（與單筆對話框的輸入上限一致）。
// 批次與單筆共用：理由會原樣進入稽核列，兩條路徑都不收超過上限的內容
const maxAlertBatchNoteRunes = 500

// CommandAlertFilter 告警查詢條件（與 SessionCommandFilter 同形：審計查詢一致體驗）
type CommandAlertFilter struct {
	Kind       string     // policy/system signal or rule source
	Severity   string     // severity 過濾（high/medium/low）
	UserID     *uint      // 用戶過濾
	AssetID    *uint      // 資產過濾
	SessionID  *uint      // 會話過濾
	Blocked    *bool      // 阻斷狀態過濾；nil 表示不篩選
	StartTime  *time.Time // 觸發時間（起）
	EndTime    *time.Time // 觸發時間（迄）
	Unreviewed bool       // 僅列未審閱（reviewed_at IS NULL），供每日審閱走查（10.4.1）
	IDs        []uint     // 指定 id 清單（批次中斷後查回每筆實際處置）；空＝不篩選
	Page       int        // 頁碼（從 1 開始）
	PageSize   int        // 每頁大小
}

// CommandAlertView 告警記錄＋關聯名稱（仿 SessionCommandView：列表免前端二次查詢）
type CommandAlertView struct {
	model.CommandAlert
	Username  string `json:"username"`
	AssetName string `json:"asset_name"`
	// ClientIP 該告警所屬會話**建線當下**的來源位址（經 join sessions 帶出，
	// 不冗餘進 command_alerts）。可選欄：會話列缺失時不出現。
	//
	// 加這一欄的理由：新來源位址類的告警，位址就是告警的內容本身——
	// 沒有它，列表上那一列除了「首次自某個位址建線」以外什麼都答不出來
	ClientIP string `json:"client_ip,omitempty"`
}

// CommandAlertListResponse 告警列表回應（沿用 {data,total,page,page_size} 慣例）
type CommandAlertListResponse struct {
	Data     []CommandAlertView `json:"data"`
	Total    int64              `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
}

// CommandAlertService 告警查詢服務
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

	if filter.Kind != "" {
		query = query.Where("command_alerts.kind = ?", filter.Kind)
	}
	if filter.Severity != "" {
		query = query.Where("command_alerts.severity = ?", filter.Severity)
	}
	if filter.UserID != nil {
		query = query.Where("command_alerts.user_id = ?", *filter.UserID)
	}
	if filter.AssetID != nil {
		query = query.Where("command_alerts.asset_id = ?", *filter.AssetID)
	}
	if filter.SessionID != nil {
		query = query.Where("command_alerts.session_id = ?", *filter.SessionID)
	}
	if filter.Blocked != nil {
		query = query.Where("command_alerts.blocked = ?", *filter.Blocked)
	}
	if filter.StartTime != nil {
		query = query.Where("command_alerts.triggered_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("command_alerts.triggered_at <= ?", *filter.EndTime)
	}
	if filter.Unreviewed {
		query = query.Where("command_alerts.reviewed_at IS NULL")
	}
	if len(filter.IDs) > 0 {
		query = query.Where("command_alerts.id IN ?", filter.IDs)
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
		Select("command_alerts.*, users.username AS username, assets.name AS asset_name, " +
			"sessions.client_ip AS client_ip").
		Joins("LEFT JOIN users ON users.id = command_alerts.user_id").
		Joins("LEFT JOIN assets ON assets.id = command_alerts.asset_id").
		// LEFT 而非 INNER：會話列被清除的舊告警仍要列得出來，只是少一個位址
		Joins("LEFT JOIN sessions ON sessions.id = command_alerts.session_id").
		Order("command_alerts.triggered_at DESC, command_alerts.id DESC").
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

// Review 審閱處置一筆告警（PCI 10.4.1）：記複審者/時間/處置分類/備註。
// disposition 僅接受 benign/escalated（pending 是未審閱狀態，不可主動設回）。
// 冪等：重覆審閱同一告警視為更新處置（可修正誤判），reviewed_at 刷新為最新。
// 理由選填，但不超過 maxAlertBatchNoteRunes（與批次同一上限）
func (s *CommandAlertService) Review(alertID, reviewerID uint, disposition, note string) error {
	if disposition != model.AlertDispositionBenign && disposition != model.AlertDispositionEscalated {
		return ErrInvalidDisposition
	}
	if utf8.RuneCountInString(note) > maxAlertBatchNoteRunes {
		return ErrAlertNoteTooLong
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

// ReviewInBatch 批次審閱中的一筆。
//
// 與單筆 Review 的差別只在三個前置條件，其餘（處置分類、寫入欄位）相同：
//   - 理由必填且不超過 maxAlertBatchNoteRunes：同一個理由套到多筆，空白理由答不出每筆依據；
//   - 審閱者自己連線觸發的告警不收：這類告警須逐筆說明；
//   - 只處置送出當下仍未審閱者（`reviewed_at IS NULL` 條件更新）：已被審閱的那筆回
//     ErrAlertAlreadyReviewed，既有處置原樣保留。單筆路徑保留「重新審閱」修正誤判的語義。
func (s *CommandAlertService) ReviewInBatch(alertID, reviewerID uint, disposition, note string) error {
	if disposition != model.AlertDispositionBenign && disposition != model.AlertDispositionEscalated {
		return ErrInvalidDisposition
	}
	if strings.TrimSpace(note) == "" || utf8.RuneCountInString(note) > maxAlertBatchNoteRunes {
		return ErrAlertBatchNote
	}

	res := s.db.Model(&model.CommandAlert{}).
		Where("id = ? AND reviewed_at IS NULL AND user_id <> ?", alertID, reviewerID).
		Updates(map[string]interface{}{
			"reviewed_by": reviewerID,
			"reviewed_at": time.Now(),
			"disposition": disposition,
			"note":        note,
		})
	if res.Error != nil {
		return fmt.Errorf("審閱告警失敗: %w", res.Error)
	}
	if res.RowsAffected == 1 {
		return nil
	}

	// 沒有更新到：判明是哪一個條件不成立，逐筆回報給呼叫端
	var current model.CommandAlert
	if err := s.db.Select("id", "user_id", "reviewed_at").First(&current, alertID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAlertNotFound
		}
		return fmt.Errorf("查詢告警失敗: %w", err)
	}
	if current.UserID == reviewerID {
		return ErrAlertSelfTriggered
	}
	return ErrAlertAlreadyReviewed
}
