/**
 * 事件摘要與標籤的碼→文案解析（auditor-workbench D9）。
 *
 * 後端零散文出站：時間軸每一列只回 `summary_code`＋`params`，文案在此組。
 * **未知 code 必須優雅降級**——後端日後新增一個 action 時，工作台要照樣
 * 顯示得出這一列（時間、類別、對象都在），不得漏字、不得吐 raw i18n key、
 * 更不得整頁壞掉。
 */
import { t, te } from '@/i18n'

/** 後端 `type` 值域（六類，字串固定，與 backend TimelineEventType 對齊） */
export const TIMELINE_TYPES = [
  'session',
  'command',
  'audit_log',
  'file_transfer',
  'clipboard',
  'alert',
]

const SUMMARY_PREFIX = 'timeline.'

export function typeLabel(type) {
  const key = `auditorWorkbench.categories.${type}`
  return te(key) ? t(key) : String(type ?? '')
}

/** 既有 enum 命名空間優先（全站同一份資源／狀態譯名），查無則原樣顯示 */
const enumLabel = (namespace, value) => {
  if (!value) return ''
  const key = `enum.${namespace}.${value}`
  return te(key) ? t(key) : String(value)
}

export const resourceLabel = (value) => enumLabel('auditResource', value)
export const statusLabel = (value) => enumLabel('auditStatus', value)
export const severityLabel = (value) => enumLabel('alertLevel', value)
export const sessionStatusLabel = (value) => enumLabel('sessionStatus', value)

/**
 * 事件摘要文案。
 * @param {{summary_code?:string, params?:Object}} event
 * @returns {string} 永遠是可讀文字（未知 code 走 fallback 並附原碼）
 */
export function summaryText(event) {
  const code = event?.summary_code || ''
  const suffix = code.startsWith(SUMMARY_PREFIX)
    ? code.slice(SUMMARY_PREFIX.length)
    : code
  const params = { ...(event?.params || {}) }
  if (params.resource) params.resource = resourceLabel(params.resource)

  const key = `auditorWorkbench.summary.${suffix}`
  if (suffix && te(key)) return t(key, params)
  return t('auditorWorkbench.summary.fallback', { code: code || '-' })
}

/**
 * 事件細節（摘要之外的補充，逐類別不同）。
 * **剪貼簿刻意無內容**：內容不入時間軸是硬性裁決，此處只回方向與會話連結所需，
 * 不得在任何分支嘗試顯示剪貼簿內容。
 * @returns {string} 空字串＝該列無細節
 */
export function detailText(event) {
  const params = event?.params || {}
  switch (event?.type) {
    case 'command':
      return params.command || ''
    case 'alert':
      return params.command || ''
    case 'audit_log':
    case 'file_transfer':
      return params.path || ''
    default:
      return ''
  }
}

/** 事件列的狀態標籤（成功者不標，避免整頁綠標稀釋失敗列） */
export function abnormalStatus(event) {
  const status = event?.params?.status
  if (!status || status === 'success') return ''
  return statusLabel(status)
}
