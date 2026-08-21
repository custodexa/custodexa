package audit

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// SessionCommandFilter 跨會話指令搜尋條件
type SessionCommandFilter struct {
	Keyword   string     // 指令子字串（ILIKE 模糊比對）
	UserID    *uint      // 用戶過濾
	AssetID   *uint      // 資產過濾
	StartTime *time.Time // 執行時間（起）
	EndTime   *time.Time // 執行時間（迄）
	// Degraded 降級列過濾：nil＝不過濾、true＝只要降級列、false＝只要有文字的列。
	// 指標型而非 bool：值型的零值是 false，會把「沒指定」靜默變成「只要正常列」，
	// 而那正好會把降級列整批藏起來——本 change 要消滅的就是這種靜默。
	Degraded *bool
	Page     int // 頁碼（從 1 開始）
	PageSize int // 每頁大小
}

// SessionCommandListResponse 指令搜尋回應（沿用 {data,total,page,page_size} 慣例）
type SessionCommandListResponse struct {
	Data     []SessionCommandView `json:"data"`
	Total    int64                `json:"total"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
	// DegradedTotal 本次查詢的時間窗／人／資產範圍內，**指令文字無法可信重組的輪數**。
	//
	// **刻意忽略 keyword 與 Degraded 兩個條件**，這是本欄唯一有用的語義：
	// 降級列的 command 恆為空字串，`command ILIKE '%rm -rf%'` **永遠不會命中它們**。
	// 若本欄跟著 keyword 走，稽核員搜 `rm -rf` 得到 0 筆時本欄也是 0，
	// 於是「這區間有 N 輪根本沒有文字可搜」這個事實仍然無從得知——
	// 那正是誠實橫幅要回答的問題。同理不跟著 Degraded 走，否則 `degraded=false`
	// 的查詢會把它歸零。
	DegradedTotal int64 `json:"degraded_total"`
}

// SessionCommandService 指令審計查詢服務
type SessionCommandService struct {
	db *gorm.DB
}

// NewSessionCommandService 創建指令審計服務
func NewSessionCommandService(db *gorm.DB) *SessionCommandService {
	return &SessionCommandService{db: db}
}

// ListBySession 取得單一會話的指令流（按 seq 升冪，重現執行順序）
func (s *SessionCommandService) ListBySession(sessionID uint) ([]model.SessionCommand, error) {
	var commands []model.SessionCommand
	if err := s.db.
		Where("session_id = ?", sessionID).
		Order("seq ASC").
		Find(&commands).Error; err != nil {
		return nil, fmt.Errorf("查詢會話指令失敗: %w", err)
	}
	return commands, nil
}

// Search 跨會話指令搜尋（D4：user_id/asset_id 冗餘欄位免 JOIN）
// SessionCommandView 指令記錄＋關聯名稱（指令審計列表顯示用，2026-06-12 走查債）
type SessionCommandView struct {
	model.SessionCommand
	Username  string `json:"username"`
	AssetName string `json:"asset_name"`
}

// scopedQuery 只套「範圍類」條件（人、資產、時間窗），**不含 keyword 與 degraded**。
//
// 抽出來是為了讓 DegradedTotal 能在同一個範圍上獨立計數——那一筆計數若跟著
// keyword 走就恆為 0（降級列沒有文字可比對），本欄也就失去存在意義。
func (s *SessionCommandService) scopedQuery(filter *SessionCommandFilter) *gorm.DB {
	query := s.db.Model(&model.SessionCommand{})
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.AssetID != nil {
		query = query.Where("asset_id = ?", *filter.AssetID)
	}
	if filter.StartTime != nil {
		query = query.Where("executed_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("executed_at <= ?", *filter.EndTime)
	}
	return query
}

func (s *SessionCommandService) Search(filter *SessionCommandFilter) (*SessionCommandListResponse, error) {
	query := s.scopedQuery(filter)

	// keyword 用 ILIKE 子字串比對：量級內 btree 表掃可接受（design D4）
	if filter.Keyword != "" {
		query = query.Where("command ILIKE ?", "%"+filter.Keyword+"%")
	}
	if filter.Degraded != nil {
		query = query.Where("degraded = ?", *filter.Degraded)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("查詢指令總數失敗: %w", err)
	}

	// 範圍內的降級輪數（見 DegradedTotal 的欄位註解：刻意不套 keyword／degraded）
	var degradedTotal int64
	if err := s.scopedQuery(filter).Where("degraded = ?", true).Count(&degradedTotal).Error; err != nil {
		return nil, fmt.Errorf("查詢降級輪數失敗: %w", err)
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}

	var commands []SessionCommandView
	if err := query.
		Select("session_commands.*, users.username AS username, assets.name AS asset_name").
		Joins("LEFT JOIN users ON users.id = session_commands.user_id").
		Joins("LEFT JOIN assets ON assets.id = session_commands.asset_id").
		Order("executed_at DESC, id DESC").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&commands).Error; err != nil {
		return nil, fmt.Errorf("查詢指令列表失敗: %w", err)
	}

	return &SessionCommandListResponse{
		Data:          commands,
		Total:         total,
		Page:          page,
		PageSize:      pageSize,
		DegradedTotal: degradedTotal,
	}, nil
}
