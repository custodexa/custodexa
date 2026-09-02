package model

import "time"

// 證據包非同步匯出 job 的狀態。
//
// 值域即 spec「證據包的非同步交付」明列的五態。無獨立的「取消」態：
// 失權取消落 failed 並以 ErrorSummary 機器碼標明原因——對申請者而言兩者的
// 可行動語義相同（可重新發起），而審計列已完整保存取消事實。
const (
	// ExportJobPending 已受理、尚未開始打包（可被 worker 領件）
	ExportJobPending = "pending"
	// ExportJobRunning 打包進行中
	ExportJobRunning = "running"
	// ExportJobDone 產物已落地，保留期內可下載
	ExportJobDone = "done"
	// ExportJobFailed 打包失敗或失權取消（ErrorSummary 帶機器碼）；不參與去重，
	// 可重新發起
	ExportJobFailed = "failed"
	// ExportJobExpired 產物逾保留期已清除，下載失效
	ExportJobExpired = "expired"
)

// 匯出工作單的種類（閉集）。決定打包者、列表分頁與下載授權判準。
const (
	// ExportJobKindEvidenceBundle 證據包：下載綁申請者本人，內容含錄影與
	// 剪貼簿等秘密材料
	ExportJobKindEvidenceBundle = "evidence_bundle"
	// ExportJobKindRotationReport 輪替證據報告：共用產物，具稽核檢視權限即可
	// 下載。**不綁申請者本人是對證據包規則的顯式例外**，成立的前提是報告不含
	// 錄影、剪貼簿或任何秘密材料——這個前提改變時，例外必須一併撤除
	ExportJobKindRotationReport = "rotation_report"
)

// job 失敗摘要的機器碼（後端零散文出站；細節只進伺服器 log 與審計）。
const (
	// ExportJobErrPackFailed 打包過程失敗（重試達上限）
	ExportJobErrPackFailed = "export_job.pack_failed"
	// ExportJobErrRequesterRevoked 領件／重試時重驗發現申請者已停用、刪除或
	// 失去稽核檢視權限，job 取消並清除產物
	ExportJobErrRequesterRevoked = "export_job.requester_revoked"
)

// AuditExportJob 非同步匯出 job（證據包與輪替證據報告）。
//
// **走 job 的種類見 ExportJobKind* 常數**；事件報告維持同步匯出。下載授權依種類
// 分流：evidence_bundle 綁申請者本人（RequesterID），rotation_report 為共用產物
// （具稽核檢視權限即可列出與下載）。任何回應層投影一律走顯式 DTO，本 model 不直接序列化
// 出站（ArtifactPath 是伺服器內部路徑，FilterJSON 供 worker 重建篩選）。
//
// 欄位刻意不帶 gorm default tag：GORM 對帶 default 的欄位遇零值會交由 DB 填值
// （User.ExternalCredential 實測教訓），本表所有欄位一律由程式碼顯式賦值。
type AuditExportJob struct {
	ID uint `gorm:"primarykey"`
	// RequesterID／RequesterName 申請者主體（下載授權與清單範圍的判準；
	// name 為發起當下快照，供 manifest 的 exported_by 與審計列）。
	// 索引具名且與 migration DDL 逐字一致（index parity 守衛的比對基準）；
	// pending/running 部分唯一索引無法以 tag 表達，僅存在於 migration DDL
	RequesterID   uint   `gorm:"not null;index:idx_audit_export_jobs_requester_status,priority:1"`
	RequesterName string `gorm:"size:50;not null"`
	// Kind 工作單種類（值域見 ExportJobKind* 常數）。決定由哪個打包者產出、
	// 列表落在哪個分頁、以及下載是否綁申請者本人。
	//
	// **這一欄帶 gorm default 是刻意的**（與本表其餘欄位的紀律相反）：本欄晚於
	// 本表出現，存量列的回填語義只有一個——它們全是證據包。DB 層的預設值是那次
	// 回填的載體，也使任何繞過服務層的寫入路徑不會產生種類為空的孤兒列。
	// 產品程式碼仍一律顯式賦值。
	Kind string `gorm:"size:32;not null;default:evidence_bundle;index:idx_audit_export_jobs_kind_status,priority:1"`
	// FilterJSON 完整篩選條件快照（audit.ExportFilter 的 JSON 序列化）；
	// FilterHash 其正規化 SHA-256，pending/running 去重鍵
	FilterJSON string `gorm:"type:text;not null"`
	FilterHash string `gorm:"size:64;not null"`
	Status     string `gorm:"size:16;not null;index:idx_audit_export_jobs_requester_status,priority:2;index:idx_audit_export_jobs_status;index:idx_audit_export_jobs_kind_status,priority:2"`
	// Attempts 打包嘗試次數（含首次）；達上限即轉 failed，防無限重試
	Attempts int `gorm:"not null"`
	// 產物三欄：done 時填實；過期清除後 ArtifactPath 清空、
	// SHA-256 與大小保留供紀錄比對
	ArtifactPath   string `gorm:"size:500;not null"`
	ArtifactSHA256 string `gorm:"size:64;not null"`
	ArtifactSize   int64  `gorm:"not null"`
	// ErrorSummary 失敗摘要機器碼（ExportJobErr*）；成功恆空
	ErrorSummary string `gorm:"size:64;not null"`
	// RequestedAt 發起時刻；PackagedAt 實際打包完成時刻——兩者一併寫入
	// manifest（雙時戳），使收包方能判斷內容對應的資料時點
	RequestedAt time.Time  `gorm:"not null"`
	PackagedAt  *time.Time ``
	// ExpiresAt 產物過期時刻（done 時＝PackagedAt＋保留期）；逾期由 worker
	// 清檔並轉 expired
	ExpiresAt *time.Time ``
	CreatedAt time.Time  ``
	UpdatedAt time.Time  ``

	// 離機儲存（evidence-offsite-storage）：指標＋顯示用快取兩欄，語義與
	// Session 的同名兩欄逐字相同（遠端物件的身分與狀態機在 offsite_objects）。
	// 產物到期（30 天 purge）只清 job 列，**不動遠端物件**——遠端副本的清理
	// 歸部署方的 bucket lifecycle
	OffsiteObjectID *uint  ``
	OffsiteStatus   string `gorm:"size:20;not null;default:''"`
}

// TableName 顯式表名（moduleboundary 掃描要求可靜態解析）
func (AuditExportJob) TableName() string {
	return "audit_export_jobs"
}
