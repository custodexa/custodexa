package offsite

// 帳冊（`offsite_objects`）的值域常數與擁有表快取的額外分類。
//
// **值域跟著擁有者走**：`internal/offsite` 定義帳冊的不變式（狀態機、租約、
// 世代歸屬），故值域常數在此而不在 `internal/model`。`docs/DB_SCHEMA.md` 的狀態機
// 段與前端枚舉皆以本檔為事實源（三方差集為空是文件任務的驗收判準）。

// 上傳目標種類（`offsite_objects.kind`）。
const (
	// KindRecording 會話錄影（擁有者＝sessions.id）
	KindRecording = "recording"
	// KindExport 證據包產物（擁有者＝audit_export_jobs.id）
	KindExport = "export"
)

// 排入來源（`offsite_objects.origin`）——雙佇列配額的判準。
const (
	// OriginLive 會話結束／打包完成當下即排入
	OriginLive = "live"
	// OriginBackfill 回填掃描排入（功能啟用前的歷史證據、關閉期間的積壓）
	OriginBackfill = "backfill"
)

// 帳冊狀態機（`offsite_objects.state`）。
//
//	pending → uploading → uploaded → local_purged
//	         ↘ failed（達重試上限）
//	           integrity_mismatch（取回驗證不符）
//	           foreign（設定世代已變更或已停止離機；只讀）
const (
	// StatePending 待上傳（帳冊即佇列：本態＋next_attempt_at 就是取件查詢面）
	StatePending = "pending"
	// StateUploading 上傳中，持有租約（lease_until 到期即回收回 pending）
	StateUploading = "uploading"
	// StateUploaded 已上傳並記帳（sha256／size／uploaded_at）
	StateUploaded = "uploaded"
	// StateFailed 重試達上限（5 次）；error_code 保留，可經管理介面手動重試
	StateFailed = "failed"
	// StateIntegrityMismatch 取回時 SHA-256 或大小不符，已拒絕交付
	StateIntegrityMismatch = "integrity_mismatch"
	// StateForeign 所屬設定世代已退役（世代切換或停止離機）：**只讀**。
	// 不再上傳、不做本機快取清除（其遠端可達性已不由現行設定保證，
	// 本機副本可能是唯一可讀副本）；取回仍以該世代自己的憑證進行
	StateForeign = "foreign"
	// StateLocalPurged 本機副本已因保留政策到期而清除；**遠端物件未被刪除**
	// （產品不代刪，遠端到期清理歸部署方的 bucket lifecycle）
	StateLocalPurged = "local_purged"
)

// AllStates 帳冊狀態的完整值域（供文件與前端枚舉的三方一致性核對）。
func AllStates() []string {
	return []string{StatePending, StateUploading, StateUploaded, StateFailed,
		StateIntegrityMismatch, StateForeign, StateLocalPurged}
}

// 擁有表快取（`sessions.offsite_status`／`audit_export_jobs.offsite_status`）
// 的**額外**分類——回填掃描的兩種「不建帳冊列」結果。
//
// 它們**不是帳冊態**：帳冊裡沒有對應的列，故不出現在 AllStates()。
// 快取欄的完整值域＝AllStates() ∪ 本兩者 ∪ {""}。
const (
	// CacheSkippedMissing recording_path 非空但本機檔 stat 失敗（還原備份後檔案
	// 回來即可上傳，故下一輪掃描會再看一次）
	CacheSkippedMissing = "skipped_missing"
	// CacheSkippedExpired 已逾錄影保留期：交給保留清理刪本機，不與清理競跑
	CacheSkippedExpired = "skipped_expired"
)

// AllOwnerCacheStatuses 擁有表快取欄的完整值域（含空字串）。
func AllOwnerCacheStatuses() []string {
	return append(AllStates(), CacheSkippedMissing, CacheSkippedExpired, "")
}

// 帳冊 `error_code` 與對外機器碼（`offsite.*`）。
//
// 原始錯誤只進 operational log（沿 audit_export_jobs.error_summary 的既有慣例）：
// 儲存端的錯誤字串可能夾帶端點、bucket 路徑甚至簽章材料。
const (
	// ErrCodeUploadFailed 上傳呼叫失敗（網路、權限、bucket 不存在等的收斂碼）
	ErrCodeUploadFailed = "offsite.upload_failed"
	// ErrCodeFileChangedDuringUpload 上傳後複驗發現本機檔的 size／mtime 已變動
	// （畫格中途收線的長尾）：重試＝重傳同 key
	ErrCodeFileChangedDuringUpload = "offsite.file_changed_during_upload"
	// ErrCodeHeadMismatch 上傳完成後 Head 核對大小不符
	ErrCodeHeadMismatch = "offsite.head_size_mismatch"
	// ErrCodeOpenFailed adapter 開啟本機檔失敗
	ErrCodeOpenFailed = "offsite.local_open_failed"
	// ErrCodeIntegrityMismatch 取回驗證不符，已拒絕交付
	ErrCodeIntegrityMismatch = "offsite.integrity_mismatch"
	// ErrCodeProfileMissing 帳冊列的 storage_generation_id 對不到世代列
	// （部分還原、DB 手術）：fail-close，不退回「用現行設定猜」
	ErrCodeProfileMissing = "offsite.profile_missing"
	// ErrCodeForeignCredentialsMissing 該世代憑證已撤銷或缺席：
	// **絕不 fallback SDK 預設鏈**（零 driver 建構、零預設鏈探測）
	ErrCodeForeignCredentialsMissing = "offsite.foreign_credentials_missing"
	// ErrCodeCredentialsUnavailable 憑證解密失敗（金鑰事故）：三態的 failed，
	// **不得併吞為未設定**
	ErrCodeCredentialsUnavailable = "offsite.credentials_unavailable"
)
