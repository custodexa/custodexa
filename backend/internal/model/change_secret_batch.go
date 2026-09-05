package model

import "time"

// 批次改密的密碼模式
const (
	// BatchPasswordPerTarget 每個目標各自隨機產生新密碼（與計劃相同的行為）
	BatchPasswordPerTarget = "per_target"
	// BatchPasswordShared 全部目標使用同一組新密碼。成功提交的帳號歸入同一個
	// 憑證群組，報告與帳號列表據此標示「共用憑證」——同一組密碼在多台生效，
	// 任一台外洩即全部外洩，這個事實必須在報告上看得見
	BatchPasswordShared = "shared"
)

// 批次狀態
const (
	ChangeSecretBatchRunning   = "running"
	ChangeSecretBatchCompleted = "completed"
)

// ChangeSecretBatch 以帳號名為軸的一次性批次改密。
//
// 與計劃並列而非隱藏的計劃：批次是一次處置動作，沒有排程、跑完即結束；
// 記錄與候選以 batch_id 指回本列（plan_id 為 0）。
//
// **不存任何密碼**：整批同一組模式的那組密碼只存在於執行期記憶體與各目標的
// 候選列（信封加密），批次結束後系統內不再有它的第二份副本。
type ChangeSecretBatch struct {
	ID uint `gorm:"primarykey" json:"id"`
	// Username 帳號名：目標集合＝掛在未刪除資產上、名為此值的未刪除帳號
	Username string `gorm:"size:100;not null;index" json:"username"`
	// PasswordMode 見 BatchPassword* 常數
	PasswordMode string `gorm:"size:16;not null" json:"password_mode"`
	// SharedGroup 整批同一組模式下成功帳號歸入的憑證群組識別；每台各自隨機時為空。
	// 群組識別本身不出站（同 AssetAccount.CredentialGroup 的理由）
	SharedGroup string `gorm:"size:36" json:"-"`

	// 密碼策略：語義與計劃相同
	PasswordLength           int  `gorm:"default:16" json:"password_length"`
	PasswordIncludeSymbol    bool `gorm:"default:true" json:"password_include_symbol"`
	PasswordExcludeAmbiguous bool `gorm:"default:true" json:"password_exclude_ambiguous"`

	// TargetCount 建立時解析到的目標數；四種計數於全部目標處理完後一次寫入
	TargetCount     int `gorm:"not null;default:0" json:"target_count"`
	SuccessCount    int `gorm:"not null;default:0" json:"success_count"`
	FailedCount     int `gorm:"not null;default:0" json:"failed_count"`
	UnverifiedCount int `gorm:"not null;default:0" json:"unverified_count"`
	SkippedCount    int `gorm:"not null;default:0" json:"skipped_count"`

	// Status 見 ChangeSecretBatch* 常數
	Status string `gorm:"size:16;not null" json:"status"`

	// RequestedBy 發起者 id 與名字快照（使用者可能隨後改名或刪除）
	RequestedBy     uint   `json:"requested_by"`
	RequestedByName string `gorm:"size:100" json:"requested_by_name"`

	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (ChangeSecretBatch) TableName() string {
	return "change_secret_batches"
}

// IsBatchPasswordMode 回報字串是否為合法的密碼模式
func IsBatchPasswordMode(mode string) bool {
	return mode == BatchPasswordPerTarget || mode == BatchPasswordShared
}
