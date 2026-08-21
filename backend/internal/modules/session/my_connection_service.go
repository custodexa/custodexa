package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ErrConnectionNotActive 自助終止僅允許進行中的連線
var ErrConnectionNotActive = errors.New("連線已結束")

// MyConnectionDTO 自助連線紀錄的精簡投影（my-connections）：
// 獨立 struct、不得回傳 model.Session——完整 Session 夾帶 recording_path、
// client IP、K8s 快照與 Asset 關聯，欄位面即是洩漏面。此 DTO 為固定契約：
// connected_at＝StartTime（非 CreatedAt）、status 為機器值 active/ended、
// id 供自助終止指定目標（owner-scoped 下對擁有者揭露自己的 id 無洩漏面）
type MyConnectionDTO struct {
	ID              uint      `json:"id"`
	AssetName       string    `json:"asset_name"`
	Protocol        string    `json:"protocol"`
	ConnectedAt     time.Time `json:"connected_at"`
	DurationSeconds int64     `json:"duration_seconds"`
	Status          string    `json:"status"`
}

// MyConnectionListResponse 自助連線列表回應
type MyConnectionListResponse struct {
	Data     []MyConnectionDTO `json:"data"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

// myConnectionMaxPageSize 連線歷史會累積，不得一次回全部
const myConnectionMaxPageSize = 100

// ConnectionTerminator 終止委派介面：實斷 WS＋狀態收斂只有一份實作
// （SessionService.Terminate），自助路徑不得分岔重作
type ConnectionTerminator interface {
	Terminate(id uint, reason string) error
}

// MyConnectionService 一般使用者自助連線紀錄查詢與自助終止
type MyConnectionService struct {
	terminator ConnectionTerminator
}

// NewMyConnectionService 創建自助連線服務
func NewMyConnectionService(terminator ConnectionTerminator) *MyConnectionService {
	return &MyConnectionService{terminator: terminator}
}

// ListMyConnections 列出指定使用者自己的連線紀錄。
// owner 條件固定為參數 userID（handler 自 JWT context 取得），任何 client
// 傳入的 user_id 都不進入此方法——先固定 owner 再套分頁，無越權面
func (s *MyConnectionService) ListMyConnections(userID uint, page, pageSize int) (*MyConnectionListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > myConnectionMaxPageSize {
		pageSize = myConnectionMaxPageSize
	}

	query := database.DB.Model(&model.Session{}).Where("user_id = ?", userID)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("查詢連線總數失敗: %w", err)
	}

	// 以「頁數比較」判定是否超界，避免極端 page 的乘法溢位（codex F3）：
	// 先算總頁數（ceil），page 超過末頁一律回空——offset 乘法只在 page 落在
	// 有效範圍時執行，此時 (page-1)*pageSize < total 不可能溢位
	var sessions []model.Session
	pageCount := (total + int64(pageSize) - 1) / int64(pageSize)
	if int64(page) <= pageCount {
		if err := query.
			Preload("Asset").
			Order("start_time DESC, id DESC").
			Limit(pageSize).
			Offset((page - 1) * pageSize).
			Find(&sessions).Error; err != nil {
			return nil, fmt.Errorf("查詢連線紀錄失敗: %w", err)
		}
	}

	data := make([]MyConnectionDTO, 0, len(sessions))
	now := time.Now()
	for i := range sessions {
		data = append(data, projectMyConnection(&sessions[i], now))
	}

	return &MyConnectionListResponse{
		Data:     data,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// TerminateMyConnection owner-scoped 自助終止：owner 條件與 id 同查
// （WHERE id AND user_id），他人的與不存在的一律 ErrSessionNotFound（404 語義，
// 不洩漏他人 session 存在性）；僅 active 可終止。實斷與狀態收斂委派唯一實作，
// end_reason 記 user_terminate 供稽核區分終止來源
func (s *MyConnectionService) TerminateMyConnection(userID, sessionID uint) error {
	var sess model.Session
	if err := database.DB.
		Where("id = ? AND user_id = ?", sessionID, userID).
		First(&sess).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("查詢連線失敗: %w", err)
	}

	if sess.Status != model.SessionStatusActive {
		return ErrConnectionNotActive
	}

	return s.terminator.Terminate(sess.ID, model.EndReasonUserTerminate)
}

// projectMyConnection 單筆投影。時長契約（design D3）：
// ended 用持久化 Duration；active 用 floor(now-StartTime) 且時鐘異常負值夾 0
func projectMyConnection(sess *model.Session, now time.Time) MyConnectionDTO {
	dto := MyConnectionDTO{
		ID:          sess.ID,
		Protocol:    string(sess.Protocol),
		ConnectedAt: sess.StartTime,
	}
	if sess.Asset != nil {
		dto.AssetName = sess.Asset.Name
	}

	if sess.Status == model.SessionStatusActive {
		dto.Status = "active"
		elapsed := int64(now.Sub(sess.StartTime).Seconds())
		if elapsed < 0 {
			elapsed = 0
		}
		dto.DurationSeconds = elapsed
	} else {
		// disconnected 與 closed 皆歸 ended，前端負責顯示文案
		dto.Status = "ended"
		// 持久化 Duration 也夾 0（codex F4）：legacy/損毀列的負值不得違反非負契約
		d := int64(sess.Duration)
		if d < 0 {
			d = 0
		}
		dto.DurationSeconds = d
	}
	return dto
}
