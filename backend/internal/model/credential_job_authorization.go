package model

import "time"

// 工作授權來源種類。
const (
	JobAuthSourcePlan     = "plan"
	JobAuthSourceBatch    = "batch"
	JobAuthSourceRotation = "rotation"
)

// 工作授權的取得方式（不是授權依據本身：執行時一律以發起者當下的能力重驗）。
const (
	// JobAuthViaRequest 建立或修改當下的伺服器端主體。
	JobAuthViaRequest = "request"
	// JobAuthViaAuditBackfill 升級時由既有審計列指認的建立者或最後修改者。
	JobAuthViaAuditBackfill = "audit_backfill"
	// JobAuthViaReauthorized 超管對無從歸屬的舊計畫明示重新授權。
	JobAuthViaReauthorized = "reauthorized"
	// JobAuthViaManualCandidate 具權者手動重試升級前的舊候選，該次授權記在點擊者名下。
	JobAuthViaManualCandidate = "manual_candidate"
	// JobAuthViaManualRun 具權者手動執行計畫，該次執行的授權記在點擊者名下（不改變計畫該版的脈絡）。
	JobAuthViaManualRun = "manual_run"
)

// 計畫的授權狀態。空值＝有可指認的發起者。
const (
	PlanAuthNeedsReauthorization = "needs_reauthorization"
	// PlanAuthNeedsReconfirmation 範圍化發起者的憑證目標計畫，當下掛載的範圍外部分超出該版掛載上界：
	// 排程不再觸發，範圍化使用者須重新確認並儲存新版；經全系統來源持有憑證改密者可承接或手動執行一次
	PlanAuthNeedsReconfirmation = "needs_reconfirmation"
)

// CredentialJobAuthorization 背景工作的授權脈絡（不可變列）。
//
// 只保存「誰發起、當時的權限世代、能力清單、確認時間與目標上界」。它不是一張票：
// 執行時仍以發起者當下的能力重驗，列內的世代與能力僅供稽核與漂移判斷。
// 修改計畫時新增一列（Revision 遞增），舊列不被覆寫。
type CredentialJobAuthorization struct {
	ID            uint   `gorm:"primarykey" json:"id"`
	SchemaVersion int    `gorm:"not null;default:1" json:"schema_version"`
	SourceKind    string `gorm:"size:16;not null;index:idx_credential_job_authorizations_source,priority:1" json:"source_kind"`
	SourceID      uint   `gorm:"not null;index:idx_credential_job_authorizations_source,priority:2" json:"source_id"`
	Revision      int    `gorm:"not null;default:1" json:"revision"`
	ActorID       uint   `gorm:"not null" json:"actor_id"`
	ActorKind     string `gorm:"size:16;not null;default:human" json:"actor_kind"`
	ActorName     string `gorm:"size:100;not null;default:''" json:"actor_name"`
	AuthSource    string `gorm:"size:24;not null" json:"auth_source"`
	AuthzVersion  int64  `gorm:"not null;default:0" json:"authz_version"`
	// PermissionSources 判定當下主體權限的來源種類（JSON 陣列，元素為 direct／group／mapped／both）
	PermissionSources string `gorm:"type:text;not null;default:'[]'" json:"permission_sources"`
	// Capabilities 建立當下確認的能力鍵（JSON 陣列）
	Capabilities string `gorm:"type:text;not null;default:'[]'" json:"capabilities"`
	// TargetBound 建立當下的目標上界（資產 ID 的 JSON 陣列；空陣列＝以來源設定展開）
	TargetBound string `gorm:"type:text;not null;default:'[]'" json:"target_bound"`
	// TargetMountBound 範圍化發起者儲存憑證目標計畫時，該憑證當下全部掛載的上界
	// （資產帳號列識別的升冪 JSON 陣列）；全域發起者與既有列為空字串。不序列化
	TargetMountBound string `gorm:"type:text;not null;default:''" json:"-"`
	// RestoreGeneration 建立當下的持久還原世代；空＝建立於 legacy 世代。執行前與目前世代比對，
	// 不符＝這份意圖留自一次還原之前，背景派送停止（見 asset 模組的還原世代比對）。
	RestoreGeneration string    `gorm:"size:64;not null;default:''" json:"-"`
	ConfirmedAt       time.Time `gorm:"not null" json:"confirmed_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// TableName 指定表名
func (CredentialJobAuthorization) TableName() string { return "credential_job_authorizations" }
