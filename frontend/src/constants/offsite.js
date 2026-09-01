// 離機儲存（evidence-offsite-storage）的值域硬拷。
//
// **事實源＝後端 `internal/offsite/state.go` 與 `internal/offsite/testconnection.go`**
// （前者定義帳冊狀態機與擁有表快取的額外分類，後者定義測試連線的步驟與結果三態）。
// 本檔是那兩份 Go 常數的前端鏡像，由 `__tests__/offsite.spec.js` 直讀 Go 原始碼
// 雙向比對——後端加一態而此處沒補，或此處多寫一個後端沒有的值，兩個方向都紅。
//
// 為什麼要硬拷而不是等後端回傳值域：狀態決定的是 tag 顏色與 tooltip 文案，
// 那是**前端閉集**（未知值不顯示裸機器碼）；把值域交給回應等於讓後端的任何
// 新狀態以機器碼形式直接出現在稽核員眼前。

// 帳冊狀態機（`offsite_objects.state`）——`internal/offsite/state.go` 的 `AllStates()`
export const OFFSITE_STATES = [
  'pending',
  'uploading',
  'uploaded',
  'failed',
  'integrity_mismatch',
  'foreign',
  'local_purged',
]

// 擁有表快取欄（`sessions.offsite_status`／`audit_export_jobs.offsite_status`）的
// **額外**分類：回填掃描的兩種「不建帳冊列」結果。它們不是帳冊態——帳冊裡沒有對應列
export const OFFSITE_CACHE_EXTRA_STATUSES = ['skipped_missing', 'skipped_expired']

// 擁有表快取欄的完整值域＝帳冊七態 ∪ 回填兩分類 ∪ {''}＝**十態**。
// `''` 是正常值（未排入），不是缺欄
export const OFFSITE_STATUS_VALUES = [
  ...OFFSITE_STATES,
  ...OFFSITE_CACHE_EXTRA_STATUSES,
  '',
]

// 狀態 → el-tag type。
//
// 分色的判準是**這個狀態對「證據取得回來」的意義**，不是流程階段：
// 只有 uploaded 是好消息（success）；failed 與 integrity_mismatch 是要人處理的
// 壞消息（danger）；pending／uploading 是進行中（warning）；
// foreign／local_purged／skipped_* 與 `''` 都是中性事實（info）——
// 尤其 `foreign` 不得標成警示：世代退役是管理員自己按的，且物件仍取得回來
export const OFFSITE_STATUS_TAG_TYPES = {
  '': 'info',
  pending: 'warning',
  uploading: 'warning',
  uploaded: 'success',
  failed: 'danger',
  integrity_mismatch: 'danger',
  foreign: 'info',
  local_purged: 'info',
  skipped_missing: 'info',
  skipped_expired: 'info',
}

// 下載中心狀態行只呈現子集（第三列）：
// 逾保留／本機已清／未排入三者對「這個包還下不下得到」沒有增量資訊，不加行
export const OFFSITE_EXPORT_ROW_STATUSES = [
  'uploaded',
  'pending',
  'uploading',
  'failed',
  'integrity_mismatch',
  'foreign',
]

// 儲存後端（`offsite_profiles.provider`）
export const OFFSITE_PROVIDERS = ['s3', 'gcs']

// 憑證模式（`offsite_profiles.credential_mode`）：三值明確分立，
// **`revoked` 絕不 fallback 預設鏈**（後端紅線，前端只負責如實呈現）
export const OFFSITE_CREDENTIAL_MODES = ['stored', 'default_chain', 'revoked']

// 憑證三態（`GET /offsite-storage/status` 的 `credential_state`）：
// `failed`＝解密失敗（金鑰事故），**不得呈現為「未設定」**
export const OFFSITE_CREDENTIAL_STATES = ['unconfigured', 'ok', 'failed']

// 測試連線步驟——`internal/offsite/testconnection.go` 的 `Step*` 常數。
// 兩段分組：第 0 段是治理現況揭露（不判好壞），第 1 段是寫讀刪實測
export const OFFSITE_TEST_STEPS_DISCLOSURE = ['probe_bucket', 'versioning', 'retention']
export const OFFSITE_TEST_STEPS_ROUNDTRIP = ['write', 'read', 'delete']
export const OFFSITE_TEST_STEPS = [
  ...OFFSITE_TEST_STEPS_DISCLOSURE,
  ...OFFSITE_TEST_STEPS_ROUNDTRIP,
]

// 步驟結果三態
export const OFFSITE_TEST_OUTCOMES = ['ok', 'warn', 'fail']

// 步驟層機器碼（`internal/offsite/testconnection.go` 的 `CodeTest*`）：
// 前端以自有 i18n 鍵查譯，未知值退回通用文案而非顯示裸碼
export const OFFSITE_TEST_CODES = [
  'offsite.test_bucket_unreachable',
  'offsite.test_governance_unknown',
  'offsite.test_write_failed',
  'offsite.test_read_failed',
  'offsite.test_read_mismatch',
  'offsite.test_delete_denied',
]

// 帳冊 `error_code`（`internal/offsite/state.go` 的 `ErrCode*`）：
// 失敗清單與會話詳情 tooltip 的原因查譯用
export const OFFSITE_ERROR_CODES = [
  'offsite.upload_failed',
  'offsite.file_changed_during_upload',
  'offsite.head_size_mismatch',
  'offsite.local_open_failed',
  'offsite.integrity_mismatch',
  'offsite.profile_missing',
  'offsite.foreign_credentials_missing',
  'offsite.credentials_unavailable',
]

// 排入來源（`offsite_objects.origin`）：雙車道配額的判準
export const OFFSITE_ORIGINS = ['live', 'backfill']

// bucket 治理揭露（`ProbeBucket` 的資訊性回報）：中性呈現、不判好壞
export const OFFSITE_VERSIONING_STATES = ['enabled', 'disabled', 'unknown']

/** 狀態 → el-tag type；未知值退回 info（不讓陌生狀態染上警示色） */
export const offsiteStatusTagType = (status) =>
  OFFSITE_STATUS_TAG_TYPES[status ?? ''] || 'info'

/** 該狀態是否屬本前端閉集（未知值不顯示裸機器碼） */
export const isKnownOffsiteStatus = (status) =>
  OFFSITE_STATUS_VALUES.includes(status ?? '')
