package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// RetentionClass 保留期水位的資料類別（auditor-workbench）。
// 值長須在 varchar(32) 內
type RetentionClass string

const (
	RetentionClassAuditLog       RetentionClass = "audit_log"
	RetentionClassSessionCommand RetentionClass = "session_command"
	RetentionClassCommandAlert   RetentionClass = "command_alert"
	RetentionClassRecording      RetentionClass = "recording"
	// RetentionClassClipboardEvent 現況**不在任何 retention 目標內**
	//（`modules/audit/retention_service.go` 的登記表只有三類＋錄影），
	// 故此類別恆無水位列，工作台一律回報 not_retained。常數保留是為了
	// 日後剪貼簿控管 change 補上保留政策時有既定鍵名，不是宣稱現在有清除
	RetentionClassClipboardEvent RetentionClass = "clipboard_event"
)

// ErrRetentionWatermarkImmutable 水位列刪除守衛的拒絕原因
var ErrRetentionWatermarkImmutable = errors.New("audit_retention_watermarks 為永久保留表，不得刪除")

// AuditRetentionWatermark 保留期清除水位（auditor-workbench）。
//
// **為什麼需要一張新表**：現行的清除留痕本身是一筆 audit_log
//（`modules/audit/retention_service.go` 於清除成功後寫入 Resource=retention 的列），
// 而那筆留痕**就在 audit_logs 內，下一輪 retention 會把它一併清掉**。拿它當
// 「這段區間已依保留政策清除」的來源，會在最需要它的時候（區間夠舊）消失，
// 於是工作台把「已合法清除」誤呈為「空白」——即自己製造竄改誤報。
//
// 因此水位另立一張**永不清除**的表：每個類別恆定一列，體積不隨資料量成長。
//
// **誠實邊界**（須與 UI 文案一致）：
//   - `PurgedThroughAt` 的語義是「早於此刻者**不完整**」，不是「早於此刻者全部已刪」。
//     分批清除、部分完成、區間化過度保留都會造成殘留。
//   - 本表**無簽章**，具 DB 權限者可改，是**可用性標記而非防篡改證明**。
//     audit_logs 類另有簽章化 tombstone（`audit_checkpoints.PurgedAt/PurgeSignature`），
//     其餘類別沒有——工作台不得據本表作出任何完整性宣稱。
type AuditRetentionWatermark struct {
	ID uint `gorm:"primarykey" json:"id"`

	// Class 資料類別，每類別至多一列
	Class RetentionClass `gorm:"type:varchar(32);not null;uniqueIndex:idx_retention_watermark_class" json:"class"`

	// PurgedThroughAt 已清除資料的時間上界；**單調前進**，只可用 GREATEST 更新。
	// 保留天數自 90 調為 365 時水位若倒退，早先已被清掉的區間會被重新宣稱為
	// present，工作台就會把「已清除」呈現成「本來就沒發生」
	PurgedThroughAt time.Time `gorm:"not null" json:"purged_through_at"`

	// LastPurgeAt 最近一次清除執行時刻（UI 文案的「最後清除於 T」）
	LastPurgeAt time.Time `gorm:"not null" json:"last_purge_at"`

	// PolicyDays 該次清除所用的保留天數（0 代表永久保留；永久時不更新水位）
	PolicyDays int `json:"policy_days"`

	// Partial 上次執行是否因單輪上限而僅部分完成；為真時 UI 另標「清除進行中」
	Partial bool `gorm:"not null;default:false" json:"partial"`

	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AuditRetentionWatermark) TableName() string {
	return "audit_retention_watermarks"
}

// BeforeDelete 永久保留守衛：本表任何刪除一律拒絕。
//
// 這不是防呆而是不變式——水位一旦消失，該類別會回退為冷啟動語義（present），
// 已清除的區間立刻被誤呈為「完整且無紀錄」。GORM 的 Delete 走本 hook，
// 原生 SQL 繞得過，故另有 retention 側的守衛測試釘住「清除迴圈不含本表」
func (w *AuditRetentionWatermark) BeforeDelete(tx *gorm.DB) error {
	return ErrRetentionWatermarkImmutable
}
