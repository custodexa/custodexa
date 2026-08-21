package recorder

import (
	"time"
)

// RecordingMetadata 錄製元數據
type RecordingMetadata struct {
	SessionID uint              `json:"session_id"`
	Protocol  string            `json:"protocol"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Env       map[string]string `json:"env,omitempty"`
	StartTime time.Time         `json:"start_time"`
}

// Recorder 錄製器接口
// 負責將終端會話錄製為標準格式（如 asciinema v2）
type Recorder interface {
	// Start 開始錄製
	// metadata: 錄製元數據（會話 ID、協議、終端尺寸等）
	Start(metadata RecordingMetadata) error

	// WriteInput 寫入輸入事件（用戶鍵盤輸入）
	// elapsed: 自錄製開始經過的時間
	// data: 輸入資料
	WriteInput(elapsed time.Duration, data []byte) error

	// WriteOutput 寫入輸出事件（終端輸出）
	// elapsed: 自錄製開始經過的時間
	// data: 輸出資料
	WriteOutput(elapsed time.Duration, data []byte) error

	// Stop 停止錄製，關閉檔案
	Stop() error

	// GetFilePath 取得錄製檔案的完整路徑
	GetFilePath() string

	// --- 測試輔助方法 ---

	// GetMetadata 取得錄製元數據（測試用）
	GetMetadata() RecordingMetadata

	// GetEventCount 取得已寫入的事件數量（測試用）
	GetEventCount() int

	// Flush 立即將緩衝區資料寫入檔案（測試用）
	Flush() error
}
