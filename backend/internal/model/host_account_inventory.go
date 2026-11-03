package model

import "time"

// 主機帳號盤點：以資產的已納管帳號唯讀列出目標主機上的帳號與特權來源，
// 比對納管狀態後只回報，不建立或修改任何帳號。

// 盤點紀錄狀態。queued／running 為未結束；同一資產至多一筆未結束（部分唯一索引）。
const (
	HostAccountScanQueued      = "queued"
	HostAccountScanRunning     = "running"
	HostAccountScanSucceeded   = "succeeded"
	HostAccountScanPartial     = "partial"
	HostAccountScanFailed      = "failed"
	HostAccountScanInterrupted = "interrupted"
)

// 盤點平台。
const (
	HostAccountPlatformPOSIX   = "posix"
	HostAccountPlatformWindows = "windows"
)

// 登入模式：default_account＝以資產預設帳號降級盤點；executor 為預留值域。
const (
	HostAccountIdentityDefault  = "default_account"
	HostAccountIdentityExecutor = "executor"
)

// 盤點結束原因碼（存於盤點紀錄、經 API 回傳；不是 HTTP 錯誤碼）。
const (
	InventoryHostKeyMismatch    = "INVENTORY_HOST_KEY_MISMATCH"
	InventoryHostKeyCheckFailed = "INVENTORY_HOST_KEY_CHECK_FAILED"
	InventoryLoginFailed        = "INVENTORY_LOGIN_FAILED"
	InventoryConnectionFailed   = "INVENTORY_CONNECTION_FAILED"
	InventoryTimeout            = "INVENTORY_TIMEOUT"
	InventoryCommandFailed      = "INVENTORY_COMMAND_FAILED"
	InventoryOutputLimit        = "INVENTORY_OUTPUT_LIMIT"
	InventoryOutputMalformed    = "INVENTORY_OUTPUT_MALFORMED"
	InventoryNoAccount          = "INVENTORY_NO_ACCOUNT"
	InventoryNoSecret           = "INVENTORY_NO_SECRET"
	InventoryAssetChanged       = "INVENTORY_ASSET_CHANGED"
	InventoryPersistFailed      = "INVENTORY_PERSIST_FAILED"
	InventoryInterrupted        = "INVENTORY_INTERRUPTED"
	// 專用帳號身分的結束原因：執行開頭重新判定後不撥號。
	InventoryExecutorChanged     = "INVENTORY_EXECUTOR_CHANGED"
	InventoryExecutorBusy        = "INVENTORY_EXECUTOR_BUSY"
	InventoryExecutorUnavailable = "INVENTORY_EXECUTOR_UNAVAILABLE"
)

// InventoryFailureReasons 全部結束原因碼（依上方宣告順序）。
var InventoryFailureReasons = []string{
	InventoryHostKeyMismatch, InventoryHostKeyCheckFailed, InventoryLoginFailed,
	InventoryConnectionFailed, InventoryTimeout, InventoryCommandFailed,
	InventoryOutputLimit, InventoryOutputMalformed, InventoryNoAccount,
	InventoryNoSecret, InventoryAssetChanged, InventoryPersistFailed, InventoryInterrupted,
	InventoryExecutorChanged, InventoryExecutorBusy, InventoryExecutorUnavailable,
}

// 特權理由碼。帶名稱者以「碼:名稱」存（例如 group:wheel）。
const (
	PrivReasonUID0             = "uid0"
	PrivReasonGroup            = "group"
	PrivReasonGroupPrimary     = "group_primary"
	PrivReasonSudoersUser      = "sudoers_user"
	PrivReasonSudoersGroup     = "sudoers_group"
	PrivReasonSudoersAlias     = "sudoers_alias"
	PrivReasonSudoersAll       = "sudoers_all"
	PrivReasonSudoersAllTarget = "sudoers_all_targetpw"
)

// PrivilegeReasonKinds 全部理由碼種類。
var PrivilegeReasonKinds = []string{
	PrivReasonUID0, PrivReasonGroup, PrivReasonGroupPrimary, PrivReasonSudoersUser,
	PrivReasonSudoersGroup, PrivReasonSudoersAlias, PrivReasonSudoersAll, PrivReasonSudoersAllTarget,
}

// 結果處置狀態。
const (
	HostAccountFindingOpen    = "open"
	HostAccountFindingIgnored = "ignored"
)

// 審計 resource（audit_logs.resource 為 varchar(20)，不得再加長）。
const (
	AuditResourceHostAccountScan    = "host_account_scan"
	AuditResourceHostAccountFinding = "host_account_finding"
)

// HostAccountScan 一次盤點的紀錄。
//
// 未結束（queued／running）的部分唯一索引只存在於 migration DDL，無法以 tag 表達。
type HostAccountScan struct {
	ID                uint   `gorm:"primarykey" json:"id"`
	AssetID           uint   `gorm:"not null;index:idx_host_account_scans_asset" json:"asset_id"`
	Platform          string `gorm:"size:16;not null" json:"platform"`
	IdentityMode      string `gorm:"size:20;not null" json:"identity_mode"`
	IdentityAccountID uint   `gorm:"not null" json:"identity_account_id"`
	InitiatedBy       uint   `gorm:"not null" json:"initiated_by"`
	InitiatedByName   string `gorm:"size:100;not null;default:''" json:"initiated_by_name"`
	Status            string `gorm:"size:16;not null" json:"status"`
	FailureReason     string `gorm:"size:48;not null;default:''" json:"failure_reason"`
	// PrivilegedGroups 開始時的特權群組政策快照（逗號分隔）
	PrivilegedGroups string `gorm:"type:text;not null" json:"privileged_groups"`
	// Coverage 檢查範圍 JSON 陣列
	Coverage                 string     `gorm:"type:text;not null;default:'[]'" json:"-"`
	AccountsTotal            int        `gorm:"not null;default:0" json:"accounts_total"`
	PrivilegedTotal          int        `gorm:"not null;default:0" json:"privileged_total"`
	UnmanagedPrivilegedTotal int        `gorm:"not null;default:0" json:"unmanaged_privileged_total"`
	ReopenedTotal            int        `gorm:"not null;default:0" json:"reopened_total"`
	StartedAt                *time.Time `json:"started_at"`
	FinishedAt               *time.Time `json:"finished_at"`
	CreatedAt                time.Time  `json:"created_at"`
}

// TableName 指定表名
func (HostAccountScan) TableName() string { return "host_account_scans" }

// HostAccountFinding 一個資產上一個主機帳號的最新盤點結果。
//
// 全域清單的部分索引只存在於 migration DDL。
type HostAccountFinding struct {
	ID       uint   `gorm:"primarykey" json:"id"`
	AssetID  uint   `gorm:"not null;uniqueIndex:idx_host_account_findings_asset_user,priority:1" json:"asset_id"`
	Username string `gorm:"size:256;not null;uniqueIndex:idx_host_account_findings_asset_user,priority:2" json:"username"`
	UID      string `gorm:"column:uid;size:32;not null;default:''" json:"uid"`
	// UIDConflict 同名多列的 uid 不全相同
	UIDConflict  bool `gorm:"column:uid_conflict;not null;default:false" json:"uid_conflict"`
	LoginCapable bool `gorm:"not null;default:false" json:"login_capable"`
	Privileged   bool `gorm:"not null;default:false" json:"privileged"`
	Incomplete   bool `gorm:"not null;default:false" json:"incomplete"`
	Present      bool `gorm:"not null;default:true" json:"present"`
	// PrivilegedReasons 理由碼 JSON 陣列（排序去重）
	PrivilegedReasons string     `gorm:"type:text;not null;default:'[]'" json:"-"`
	Status            string     `gorm:"size:12;not null" json:"status"`
	IgnoreReason      string     `gorm:"size:500;not null;default:''" json:"ignore_reason"`
	IgnoredBy         uint       `gorm:"not null;default:0" json:"ignored_by"`
	IgnoredByName     string     `gorm:"size:100;not null;default:''" json:"ignored_by_name"`
	IgnoredAt         *time.Time `json:"ignored_at"`
	// IgnoredReasons 忽略當下的特權理由快照（JSON 陣列）
	IgnoredReasons  string    `gorm:"type:text;not null;default:'[]'" json:"-"`
	Alerted         bool      `gorm:"not null;default:false" json:"-"`
	FirstSeenScanID uint      `gorm:"not null" json:"first_seen_scan_id"`
	LastSeenScanID  uint      `gorm:"not null" json:"last_seen_scan_id"`
	FirstSeenAt     time.Time `gorm:"not null" json:"first_seen_at"`
	LastSeenAt      time.Time `gorm:"not null" json:"last_seen_at"`
}

// TableName 指定表名
func (HostAccountFinding) TableName() string { return "host_account_findings" }
