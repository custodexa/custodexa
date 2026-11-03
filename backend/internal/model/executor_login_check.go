package model

import "time"

// ExecutorLoginCheck 堡壘機專用帳號最近一次測試登入的結果，每個專用帳號掛載一列。
//
// Result 空字串表示成功，否則是登錄在 apierror 的結果碼；Method 只在成功時有值；
// InventoryRead 是盤點讀取提權檢查的值。不存任何秘密、公鑰或遠端輸出。
type ExecutorLoginCheck struct {
	AssetAccountID      uint      `gorm:"primaryKey;autoIncrement:false" json:"asset_account_id"`
	AssetID             uint      `gorm:"not null;index:idx_executor_login_checks_asset" json:"asset_id"`
	CredentialID        uint      `gorm:"not null" json:"credential_id"`
	CredentialVersionID uint      `gorm:"not null" json:"credential_version_id"`
	Result              string    `gorm:"size:64;not null;default:''" json:"result"`
	Method              string    `gorm:"size:32;not null;default:''" json:"method"`
	InventoryRead       string    `gorm:"size:16;not null;default:''" json:"inventory_read"`
	CheckedBy           uint      `gorm:"not null;default:0" json:"checked_by"`
	CheckedByName       string    `gorm:"size:100;not null;default:''" json:"checked_by_name"`
	CheckedAt           time.Time `gorm:"not null" json:"checked_at"`
}

// TableName 指定表名
func (ExecutorLoginCheck) TableName() string { return "executor_login_checks" }

// 測試登入成功的方式。
const (
	ExecutorCheckMethodRoot         = "executor_root"
	ExecutorCheckMethodSudoNopasswd = "executor_sudo_nopasswd"
	ExecutorCheckMethodSudoPassword = "executor_sudo_password"
)

// 盤點讀取提權檢查的值。
const (
	ExecutorCheckInventoryOK         = "ok"
	ExecutorCheckInventoryDenied     = "denied"
	ExecutorCheckInventoryNotNeeded  = "not_needed"
	ExecutorCheckInventoryNotChecked = "not_checked"
)

// 測試登入的結果碼（存於結果表，也是回應的 code；同時登錄在 apierror）。
const (
	ExecCheckConnectionFailed      = "RULE_EXECUTOR_CHECK_CONNECTION_FAILED"
	ExecCheckLoginFailed           = "RULE_EXECUTOR_CHECK_LOGIN_FAILED"
	ExecCheckHostKeyMismatch       = "RULE_EXECUTOR_CHECK_HOST_KEY_MISMATCH"
	ExecCheckHostKeyCheckFailed    = "RULE_EXECUTOR_CHECK_HOST_KEY_CHECK_FAILED"
	ExecCheckEscalationDenied      = "RULE_EXECUTOR_CHECK_ESCALATION_DENIED"
	ExecCheckEscalationNeedsNopass = "RULE_EXECUTOR_CHECK_ESCALATION_NEEDS_NOPASSWD"
	ExecCheckUnavailable           = "RULE_EXECUTOR_CHECK_UNAVAILABLE"
	ExecCheckRotationPending       = "RULE_EXECUTOR_CHECK_ROTATION_PENDING"
	ExecCheckTimeout               = "RULE_EXECUTOR_CHECK_TIMEOUT"
)

// ExecutorCheckResultCodes 結果表 result 欄允許的非空值（依上方宣告順序）。
func ExecutorCheckResultCodes() []string {
	return []string{
		ExecCheckConnectionFailed, ExecCheckLoginFailed, ExecCheckHostKeyMismatch,
		ExecCheckHostKeyCheckFailed, ExecCheckEscalationDenied, ExecCheckEscalationNeedsNopass,
		ExecCheckUnavailable, ExecCheckRotationPending, ExecCheckTimeout,
	}
}

// AuditResourceAssetExecutor 堡壘機專用帳號相關審計的資源。14 字元，varchar(20) 內
const AuditResourceAssetExecutor = "asset_executor"

// 結束審計專用的結果值：不是 apierror 碼，也不進結果表（結果表只存真正的測試結果）。
const (
	ExecutorCheckEndBusy          = "busy"
	ExecutorCheckEndStateChanged  = "state_changed"
	ExecutorCheckEndInterrupted   = "interrupted"
	ExecutorCheckEndPersistFailed = "persist_failed"
)
