package session

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

var (
	// ErrSessionNotFound Session 不存在
	ErrSessionNotFound = errors.New("Session 不存在")
	// ErrSessionAlreadyClosed Session 已關閉
	ErrSessionAlreadyClosed = errors.New("Session 已關閉")
)

// SessionService Session 管理服務
type SessionService struct {
	registry ConnectionRegistry // WebSocket 連線註冊表介面
}

// ConnectionRegistry WebSocket 連線註冊表介面
type ConnectionRegistry interface {
	Close(sessionID uint) error
}

// NewSessionService 創建 Session 服務
func NewSessionService(registry ConnectionRegistry) *SessionService {
	// typed-nil 防護：傳入 nil 指標轉介面時 `registry != nil` 仍為 true，
	// 後續呼叫 registry.Close() 會 panic，統一在建構時正規化為 interface nil
	if registry != nil {
		v := reflect.ValueOf(registry)
		if v.Kind() == reflect.Ptr && v.IsNil() {
			registry = nil
		}
	}
	return &SessionService{
		registry: registry,
	}
}

// SessionFilter Session 過濾條件
type SessionFilter struct {
	UserID    *uint               // 使用者 ID 過濾
	AssetID   *uint               // 資產 ID 過濾
	Protocol  model.ProtocolType  // 協議過濾
	Status    model.SessionStatus // 狀態過濾
	StartTime *time.Time          // 開始時間過濾（起）
	EndTime   *time.Time          // 結束時間過濾（迄）
	Page      int                 // 頁碼（從 1 開始）
	PageSize  int                 // 每頁大小
}

// SessionListResponse Session 列表回應
type SessionListResponse struct {
	Data     []model.Session `json:"data"`
	Total    int64           `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

// Create 創建 Session
func (s *SessionService) Create(session *model.Session) error {
	// 生成唯一的 Session ID（如果未提供）
	if session.SessionID == "" {
		session.SessionID = fmt.Sprintf("sess_%d_%d", time.Now().UnixNano(), session.UserID)
	}

	// 設定初始狀態
	if session.Status == "" {
		session.Status = model.SessionStatusActive
	}
	if session.StartTime.IsZero() {
		session.StartTime = time.Now()
	}

	// 儲存到資料庫
	if err := database.DB.Create(session).Error; err != nil {
		return fmt.Errorf("創建 Session 失敗: %w", err)
	}

	return nil
}

// GetByID 根據 ID 取得 Session
func (s *SessionService) GetByID(id uint) (*model.Session, error) {
	var session model.Session
	result := database.DB.
		Preload("User").
		Preload("Asset").
		First(&session, id)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, result.Error
	}

	return &session, nil
}

// GetBySessionID 根據 SessionID 取得 Session
func (s *SessionService) GetBySessionID(sessionID string) (*model.Session, error) {
	var session model.Session
	result := database.DB.
		Preload("User").
		Preload("Asset").
		Where("session_id = ?", sessionID).
		First(&session)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, result.Error
	}

	return &session, nil
}

// List 列出 Session（支援分頁與過濾）
func (s *SessionService) List(filter *SessionFilter) (*SessionListResponse, error) {
	query := database.DB.Model(&model.Session{})

	// 使用者過濾
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}

	// 資產過濾
	if filter.AssetID != nil {
		query = query.Where("asset_id = ?", *filter.AssetID)
	}

	// 協議過濾
	if filter.Protocol != "" {
		query = query.Where("protocol = ?", filter.Protocol)
	}

	// 狀態過濾
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}

	// 時間範圍過濾
	if filter.StartTime != nil {
		query = query.Where("start_time >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("start_time <= ?", *filter.EndTime)
	}

	// 計算總數
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("查詢 Session 總數失敗: %w", err)
	}

	// 分頁
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 查詢資料
	var sessions []model.Session
	if err := query.
		Preload("User").
		Preload("Asset").
		Order("start_time DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("查詢 Session 列表失敗: %w", err)
	}

	return &SessionListResponse{
		Data:     sessions,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// GetActiveSessions 取得所有活動 Session
func (s *SessionService) GetActiveSessions() ([]model.Session, error) {
	var sessions []model.Session
	err := database.DB.
		Preload("User").
		Preload("Asset").
		Where("status = ?", model.SessionStatusActive).
		Order("start_time DESC").
		Find(&sessions).Error

	if err != nil {
		return nil, fmt.Errorf("查詢活動 Session 失敗: %w", err)
	}

	return sessions, nil
}

// ListClipboardEvents 按時間序回傳會話剪貼簿記錄（clipboard-audit）。
//
// 收斂自：原本住在
// `api/clipboard_event_handler.go:32`——handler 自持 `*gorm.DB` 直查
// `model.ClipboardEvent`，是 api 層繞過 service 直碰資料層的四處之一。
// 查詢本體（where／order／find）逐字搬入，行為位元相同。
func (s *SessionService) ListClipboardEvents(sessionID uint) ([]model.ClipboardEvent, error) {
	var events []model.ClipboardEvent
	if err := database.DB.Where("session_id = ?", sessionID).Order("id").Find(&events).Error; err != nil {
		return nil, err
	}
	return events, nil
}

// IsActive 回報 session 是否仍為 active：
// 轉發啟動前的最後一道存活閘——收緊「session 建立為 active、registry 登記前」
// 窗口內被撤銷/停用收線（TerminateByUserAsset/Terminate 已 CAS 成 disconnected，
// 但 registry.Close 因尚未登記而撲空）的競態。查無或非 active 皆回 false（fail-safe）
func (s *SessionService) IsActive(id uint) bool {
	var status model.SessionStatus
	err := database.DB.Model(&model.Session{}).
		Select("status").Where("id = ?", id).Scan(&status).Error
	return err == nil && status == model.SessionStatusActive
}

// Close 關閉 Session
func (s *SessionService) Close(id uint) error {
	return s.CloseWithReason(id, "")
}

// CloseWithReason 關閉會話並記錄斷線原因（session-timeout）；reason 空字串維持既有 normal
func (s *SessionService) CloseWithReason(id uint, reason string) error {
	session, err := s.GetByID(id)
	if err != nil {
		return err
	}

	// 更新狀態
	endTime := time.Now()
	duration := int(endTime.Sub(session.StartTime).Seconds())
	// 時鐘異常/損毀列的負值夾 0（與 Terminate 一致）
	if duration < 0 {
		duration = 0
	}

	updates := map[string]interface{}{
		"status":   model.SessionStatusClosed,
		"end_time": endTime,
		"duration": duration,
	}
	// 僅在原因非 normal 時寫入，避免覆蓋既有值（DB 預設已是 normal）
	if reason != "" && reason != "normal" {
		updates["end_reason"] = reason
	}

	// CAS status=active：自然收線只收未終態的
	// 會話。已被 Terminate（撤銷/停用強制斷線 end_reason=revoked/admin_terminate）
	// 或 reconciler 收線者為 disconnected/closed，此處視為冪等成功——不覆寫終態、
	// end_reason 與時間，避免強制終止語義被 bridge/tunnel 結束後的自然清理蓋掉
	res := database.DB.Model(&model.Session{}).
		Where("id = ? AND status = ?", id, model.SessionStatusActive).
		Updates(updates)
	if res.Error != nil {
		return fmt.Errorf("關閉 Session 失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrSessionAlreadyClosed // 已被他路徑收線，呼叫端 log 後略過（冪等）
	}
	return nil
}

// CloseBySessionID 根據 SessionID 關閉 Session
func (s *SessionService) CloseBySessionID(sessionID string) error {
	session, err := s.GetBySessionID(sessionID)
	if err != nil {
		return err
	}

	return s.Close(session.ID)
}

// Terminate 強制終止 Session（管理員或會話擁有者自助），reason 記入 end_reason
// 供稽核區分終止來源（admin_terminate/user_terminate）
func (s *SessionService) Terminate(id uint, reason string) error {
	session, err := s.GetByID(id)
	if err != nil {
		return err
	}

	// 檢查是否已關閉
	if session.Status == model.SessionStatusClosed {
		return ErrSessionAlreadyClosed
	}

	// 更新狀態為 disconnected
	endTime := time.Now()
	duration := int(endTime.Sub(session.StartTime).Seconds())
	// 時鐘異常/損毀列的負值夾 0（與 reconciler closeAsEnded 非負契約一致）
	if duration < 0 {
		duration = 0
	}

	updates := map[string]interface{}{
		"status":     model.SessionStatusDisconnected,
		"end_time":   endTime,
		"duration":   duration,
		"end_reason": reason,
	}

	// CAS 守衛 status=active：GetByID 與 UPDATE 之間有 TOCTOU，
	// 與被動 WS 關閉、reconciler 收斂或並發終止競態時，無條件 WHERE id 會復活
	// 終態或覆寫他者已寫入的 end_reason。改為條件更新讓「先到者贏」，RowsAffected=0
	// 即已被他路徑收線 → 回 ErrSessionAlreadyClosed
	res := database.DB.Model(&model.Session{}).
		Where("id = ? AND status = ?", id, model.SessionStatusActive).
		Updates(updates)
	if res.Error != nil {
		return fmt.Errorf("終止 Session 失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrSessionAlreadyClosed
	}

	// 實際斷開 WebSocket 連線（僅 CAS 成功才關，避免對他路徑已收線的連線重複關閉）
	if s.registry != nil {
		if err := s.registry.Close(id); err != nil {
			// 記錄錯誤但不返回失敗，因為資料庫狀態已更新
			log.Printf("[SessionService] 關閉 WebSocket 失敗 (SessionID=%d): %v", id, err)
		} else {
			log.Printf("[SessionService] WebSocket 已關閉 (SessionID=%d)", id)
		}
	}

	return nil
}

// TerminateAllByUser 強制終斷某使用者全部進行中會話
//（帳號停用的即時撤權收線，沿用 admin_terminate 斷線語義）。
// 個別會話終斷失敗不中斷整批——已停用是主要目標，殘餘會話記日誌人工跟進
func (s *SessionService) TerminateAllByUser(userID uint) (int, error) {
	var sessions []model.Session
	if err := database.DB.Where("user_id = ? AND status = ?", userID, model.SessionStatusActive).
		Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("查詢使用者進行中會話失敗: %w", err)
	}

	terminated := 0
	for _, sess := range sessions {
		if err := s.Terminate(sess.ID, model.EndReasonAdminTerminate); err != nil {
			log.Printf("[SessionService] 停用收線終斷會話失敗 (SessionID=%d, UserID=%d): %v",
				sess.ID, userID, err)
			continue
		}
		terminated++
	}
	return terminated, nil
}

// TerminateByUserAsset 終斷某使用者在某資產上的全部進行中會話
// （撤銷即斷線政策開啟時的收線路徑，沿
// TerminateAllByUser 模式——個別失敗不中斷整批、Terminate CAS 競態安全）
func (s *SessionService) TerminateByUserAsset(userID, assetID uint, reason string) (int, error) {
	var sessions []model.Session
	if err := database.DB.Where("user_id = ? AND asset_id = ? AND status = ?",
		userID, assetID, model.SessionStatusActive).
		Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("查詢使用者資產進行中會話失敗: %w", err)
	}

	terminated := 0
	for _, sess := range sessions {
		if err := s.Terminate(sess.ID, reason); err != nil {
			log.Printf("[SessionService] 撤銷收線終斷會話失敗 (SessionID=%d, UserID=%d, AssetID=%d): %v",
				sess.ID, userID, assetID, err)
			continue
		}
		terminated++
	}
	return terminated, nil
}

// TerminateByAsset 終斷某資產上的全部進行中會話：
// 資產停用時的收線路徑，沿 TerminateByUserAsset 模式——個別失敗不中斷整批、
// Terminate CAS 競態安全
func (s *SessionService) TerminateByAsset(assetID uint, reason string) (int, error) {
	var sessions []model.Session
	if err := database.DB.Where("asset_id = ? AND status = ?",
		assetID, model.SessionStatusActive).
		Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("查詢資產進行中會話失敗: %w", err)
	}

	terminated := 0
	for _, sess := range sessions {
		if err := s.Terminate(sess.ID, reason); err != nil {
			log.Printf("[SessionService] 資產停用收線終斷會話失敗 (SessionID=%d, AssetID=%d): %v",
				sess.ID, assetID, err)
			continue
		}
		terminated++
	}
	return terminated, nil
}

// UpdateRecording 更新錄製資訊
func (s *SessionService) UpdateRecording(id uint, recordingPath string, recordingSize int64) error {
	updates := map[string]interface{}{
		"recording_path": recordingPath,
		"recording_size": recordingSize,
		"has_recording":  true,
	}

	if err := database.DB.Model(&model.Session{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新錄製資訊失敗: %w", err)
	}

	return nil
}

// SetRecordingStartedAt 記錄「錄影的時間原點」。
//
// 於錄製器實際啟動的當下寫入，**不是**會話建檔時刻——回放的 elapsed=0 對應的是
// 前者。深連結（?t=）要落在正確的畫面上，就必須拿這個原點換算，否則偏移量恆存在。
//
// 失敗只回錯誤由呼叫端記 log：這是回放體驗欄位，不參與 fail-close 判定，
// 不得因為它寫不進去而中斷已建立的連線。
func (s *SessionService) SetRecordingStartedAt(id uint, startedAt time.Time) error {
	if err := database.DB.Model(&model.Session{}).Where("id = ?", id).
		Update("recording_started_at", startedAt).Error; err != nil {
		return fmt.Errorf("更新錄影起始時刻失敗: %w", err)
	}
	return nil
}

// GetStatistics 取得統計資訊
func (s *SessionService) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 活動 Session 數
	var activeCount int64
	if err := database.DB.Model(&model.Session{}).
		Where("status = ?", model.SessionStatusActive).
		Count(&activeCount).Error; err != nil {
		return nil, fmt.Errorf("查詢活動 Session 數失敗: %w", err)
	}
	stats["active_sessions"] = activeCount

	// 今日連線數
	today := time.Now().Truncate(24 * time.Hour)
	var todayCount int64
	if err := database.DB.Model(&model.Session{}).
		Where("start_time >= ?", today).
		Count(&todayCount).Error; err != nil {
		return nil, fmt.Errorf("查詢今日連線數失敗: %w", err)
	}
	stats["today_sessions"] = todayCount

	// 總 Session 數
	var totalCount int64
	if err := database.DB.Model(&model.Session{}).Count(&totalCount).Error; err != nil {
		return nil, fmt.Errorf("查詢總 Session 數失敗: %w", err)
	}
	stats["total_sessions"] = totalCount

	return stats, nil
}
