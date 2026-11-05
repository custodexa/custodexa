package model

import "time"

// KeystrokeRecord 一個會話一列：平台已轉送出去的使用者輸入所存成的加密檔案之
// 中繼資料，或「此會話類型不產生鍵盤紀錄」的判定紀錄。
//
// FileKeyEnc 是以欄位信封封存的檔案金鑰，json:"-"：任何 model 直接序列化的路徑
// 都不得帶出。清除後為空字串（不是 NULL）。
type KeystrokeRecord struct {
	ID             uint   `gorm:"primarykey" json:"id"`
	RecordUUID     string `gorm:"size:36;not null;uniqueIndex:idx_keystroke_records_record_uuid" json:"record_uuid"`
	SessionID      uint   `gorm:"not null;uniqueIndex:idx_keystroke_records_session_id" json:"session_id"`
	Protocol       string `gorm:"size:16;not null;default:''" json:"protocol"`
	Status         string `gorm:"size:16;not null;index:idx_keystroke_records_status" json:"status"`
	CoverageReason string `gorm:"size:32;not null;default:''" json:"coverage_reason"`
	// FilePath 相對於鍵盤紀錄根目錄；清除後保留原值供稽核；
	// not_covered 與未開檔的 failed 為空
	FilePath       string     `gorm:"size:255;not null;default:''" json:"file_path"`
	FileKeyEnc     string     `gorm:"type:text;not null;default:''" json:"-"`
	FailureCause   string     `gorm:"size:64;not null;default:''" json:"failure_cause"`
	WriterInstance string     `gorm:"size:64;not null;default:''" json:"writer_instance"`
	EventCount     int64      `gorm:"not null;default:0" json:"event_count"`
	ByteSize       int64      `gorm:"not null;default:0" json:"byte_size"`
	SegmentCount   int64      `gorm:"not null;default:0" json:"segment_count"`
	StartedAt      time.Time  `gorm:"not null" json:"started_at"`
	LastWriteAt    *time.Time `json:"last_write_at"`
	EndedAt        *time.Time `json:"ended_at"`
	PurgedAt       *time.Time `json:"purged_at"`
}

// TableName 顯式表名：file_key_enc 登記於 envelopeMigrationTargets
func (KeystrokeRecord) TableName() string { return "keystroke_records" }

// 鍵盤紀錄列狀態。
const (
	KeystrokeStatusRecording  = "recording"
	KeystrokeStatusComplete   = "complete"
	KeystrokeStatusIncomplete = "incomplete" // 行程異常中止
	KeystrokeStatusFailed     = "failed"
	KeystrokeStatusPurged     = "purged"
	KeystrokeStatusNotCovered = "not_covered"
)
