package model

import "time"

// SecurityPolicy 安全政策（key-value 儲存）。
// 政策值一律以字串存放，型別語義由 service 層常數表（PolicyDef）定義；
// 無對應列時以常數表出廠預設值生效，故 seed 不需預先物化政策列
type SecurityPolicy struct {
	Key       string    `gorm:"primaryKey;size:64" json:"key"`
	Value     string    `gorm:"type:text;not null" json:"value"`
	UpdatedBy string    `gorm:"size:100" json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (SecurityPolicy) TableName() string {
	return "security_policies"
}

// PasswordHistory 密碼歷史（PCI 8.3.7）。
// 每次設定密碼（建立帳號/seed/自助改密/admin 重設）都寫入一筆，
// 改密時 bcrypt 逐筆比對近 N 筆拒絕重用；初始密碼也入表，
// 否則首次強制改密可設回原密碼
type PasswordHistory struct {
	ID           uint      `gorm:"primarykey" json:"id"`
	UserID       uint      `gorm:"not null;index" json:"user_id"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// TableName 指定表名
func (PasswordHistory) TableName() string {
	return "password_histories"
}

// SecurityPolicyHistory 政策變更歷史。
//
// 只記錄標了「保留歷史」的鍵（每日簽核的開關與業務時區）：它們決定「哪些日子
// 要簽、各用哪個時區切」，必須能由資料重算。審計日誌受保留政策清除，不能當
// 這件事的來源，故另立一張由 policy 模組在寫入政策的同一交易內維護的表。
//
// 不變式：依鍵重播歷史的末值等於政策現值。升級遷移寫入的列可能 old 等於 new
// ——那是標示區段依據（例如推定區段之後改由審計證明）的分界，不是一次變更。
type SecurityPolicyHistory struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	PolicyKey string    `gorm:"type:varchar(64);not null;index:idx_security_policy_history_key_at,priority:1" json:"policy_key"`
	OldValue  string    `gorm:"type:text;not null" json:"old_value"`
	NewValue  string    `gorm:"type:text;not null" json:"new_value"`
	ChangedAt time.Time `gorm:"not null;index:idx_security_policy_history_key_at,priority:2" json:"changed_at"`
	ChangedBy string    `gorm:"type:varchar(100);not null" json:"changed_by"`
	// Source 這一列的來源（PolicyHistorySource*）
	Source string `gorm:"type:varchar(32);not null" json:"source"`
}

// TableName 指定表名
func (SecurityPolicyHistory) TableName() string {
	return "security_policy_history"
}

// 政策變更歷史的來源（security_policy_history.source）
const (
	// PolicyHistorySourcePolicyUpdate 管理端寫入（政策頁、套用政策組）
	PolicyHistorySourcePolicyUpdate = "policy_update"
	// PolicyHistorySourceSeed 首次啟動的播種
	PolicyHistorySourceSeed = "seed"
	// PolicyHistorySourceMigrationAuditLog 升級時由操作日誌中的政策變更紀錄重建
	PolicyHistorySourceMigrationAuditLog = "migration_audit_log"
	// PolicyHistorySourceMigrationPolicyRow 升級時以政策列的現值與最後更新時刻為界
	PolicyHistorySourceMigrationPolicyRow = "migration_policy_row"
	// PolicyHistorySourceMigrationSignRecord 升級前已有簽核紀錄的日子（簽核本身證明當天開著）
	PolicyHistorySourceMigrationSignRecord = "migration_sign_record"
	// PolicyHistorySourceMigrationPresumedPurged 審計已依保留政策清除，推定為開
	PolicyHistorySourceMigrationPresumedPurged = "migration_presumed_purged"
	// PolicyHistorySourceMigrationPresumedGap 相鄰兩筆變更紀錄銜接不上，推定為開
	PolicyHistorySourceMigrationPresumedGap = "migration_presumed_gap"
	// PolicyHistorySourceMigrationPresumedTail 重建結果與現值不一致，推定為開
	PolicyHistorySourceMigrationPresumedTail = "migration_presumed_tail"
	// PolicyHistorySourceMigrationUpgrade 升級時偵測的業務時區初值
	PolicyHistorySourceMigrationUpgrade = "migration_upgrade"
)
