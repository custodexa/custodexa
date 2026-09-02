// 輪替證據的枚舉顯示中繼資料。
//
// 值域硬拷後端 `backend/internal/modules/asset/rotation_report.go:13-45`
// 與 `backend/internal/model/rotation_report_schedule.go` 的範圍常數；
// 完備性由 `views/__tests__/RotationEvidence.spec.js` 的枚舉案例把關
// ——後端新增一個桶而畫面沒跟上時，那裡會紅，而不是靜默少一格。

// 狀態桶：互斥且**依序判定**（未驗證 → 無政策 → 無記錄 → 逾期 → 即將到期 → 合規）。
// 這裡的排列即判定順序，摘要數字列也照這個順序呈現：讀者由左至右讀下來，
// 就是報告判斷一個帳號的順序
export const ROTATION_BUCKETS = [
  'unverified',
  'no_policy',
  'no_record',
  'overdue',
  'due_soon',
  'compliant',
]

// 桶 → 摘要欄位名。後端摘要用 `due_within_30` 而非 `due_soon`
//（欄名寫死了預警窗天數），桶名與欄名的落差在這裡收口，不散進模板
export const BUCKET_SUMMARY_FIELD = {
  unverified: 'unverified',
  no_policy: 'no_policy',
  no_record: 'no_record',
  overdue: 'overdue',
  due_soon: 'due_within_30',
  compliant: 'compliant',
}

// 標籤色：逾期為 danger、即將到期為 warning、合規為 success，
// 其餘三者是「還說不上合不合規」，一律中性——把無記錄畫成紅色，
// 會讓一台從未納管的機器看起來像違規，那是兩件事
export const BUCKET_TAG_TYPE = {
  unverified: 'warning',
  no_policy: 'info',
  no_record: 'info',
  overdue: 'danger',
  due_soon: 'warning',
  compliant: 'success',
}

/** 報告範圍種類：全系統／節點含子樹／改密計劃 */
export const ROTATION_SCOPE_KINDS = ['all', 'node', 'plan']

/** 產出語言閉集（與介面語言同一組，但兩者各自獨立：報告語言隨報告走） */
export const ROTATION_REPORT_LANGUAGES = ['zh-TW', 'en-US', 'ja-JP']

/** 記錄明細的結果狀態（與改密記錄同一組值域） */
export const ROTATION_RECORD_STATUSES = ['success', 'failed', 'unverified', 'skipped']

export const DEFAULT_RETENTION_DAYS = 400
