/**
 * 操作日誌的「同一請求」篩選：同一次 HTTP 請求寫下的各列共用 request_id。
 * 網址 `?request_id=` 與詳情裡的連結都走這裡。
 */
import { t } from '@/i18n'

// 與後端 audit_logs.request_id 的欄位寬度一致；超過的值不可能命中，直接忽略
export const REQUEST_ID_MAX_LENGTH = 100

/** 網址參數轉篩選值；不是非空字串或過長時回空字串 */
export function requestIdFromQuery(query) {
  const value = query?.request_id
  if (typeof value !== 'string' || value === '' || value.length > REQUEST_ID_MAX_LENGTH) return ''
  return value
}

/** 篩選標籤文字：只顯示前 8 碼 */
export function requestFilterChipText(requestId) {
  return t('auditLogs.requestFilterChip', { id: String(requestId).slice(0, 8) })
}

/** 有篩選值才帶進查詢參數 */
export function withRequestId(params, requestId) {
  if (requestId) params.request_id = requestId
  return params
}
