/**
 * 審計列的可讀原因（每日簽核抽屜、操作日誌詳情共用）。
 *
 * 後端只回 `reason_code`＋`reason_params`（字串對字串），文案在
 * `dailyReview.reason.*`。降級順序：
 *   有碼且查得到譯文 → 套譯文；
 *   有碼但前端不認得（前端版本早於後端）→ `generic` 句型；
 *   沒有碼 → 照舊顯示 `error_msg || path`（鑑識原文，不改寫）；
 *   仍為空 → `generic` 句型。
 * 任何分支都不得回傳空字串或裸鍵。
 */
import { t, te } from '@/i18n'

const REASON_PREFIX = 'dailyReview.reason.'

// 參數值是以半形逗號串接的角色名（後端已把名稱內的逗號換成空白）
const ROLE_CODES = new Set(['role_mapping_applied', 'role_mapping_applied_added', 'role_mapping_applied_removed'])

const lookup = (key, raw) => (te(key) ? t(key) : String(raw))

const enumLabel = (namespace, value) => (value ? lookup(`enum.${namespace}.${value}`, value) : '')

const roleLabel = (name) => lookup(`enum.role.${name}.label`, name)

/** 角色清單：逐一查 enum 譯名，查不到顯示原名，以該語系的列舉分隔接回 */
export const roleListText = (value) =>
  String(value || '')
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean)
    .map(roleLabel)
    .join(t('common.listSeparator'))

// 需要前端二次翻譯的參數；其餘參數原樣代入
const localizeParams = (params) => {
  const out = { ...params }
  if ('action' in out) out.action = enumLabel('auditAction', out.action)
  if ('resource' in out) out.resource = enumLabel('auditResource', out.resource)
  if ('target' in out) out.target = lookup(`dailyReview.reasonTarget.${out.target}`, out.target)
  if ('added' in out) out.added = roleListText(out.added)
  if ('removed' in out) out.removed = roleListText(out.removed)
  return out
}

const knownCode = (code) => Boolean(code) && te(`${REASON_PREFIX}${code}`)

const genericText = (item) => {
  const text = t(`${REASON_PREFIX}generic`, localizeParams({ action: item?.action || '', resource: item?.resource || '' }))
  return text.trim() || '-'
}

/**
 * @param {{reason_code?:string, reason_params?:Object, error_msg?:string, path?:string, action?:string, resource?:string}} item
 * @returns {string} 永遠非空
 */
export function reasonText(item) {
  const code = item?.reason_code || ''
  if (knownCode(code)) {
    return t(`${REASON_PREFIX}${code}`, localizeParams(item.reason_params || {}))
  }
  if (code) return genericText(item)
  return item?.error_msg || item?.path || genericText(item)
}

/**
 * 抽屜用的兩行呈現：角色增減時第一行是主句、第二行列出「加上／移除」；
 * 其餘碼只有一行。
 * @returns {{ main: string, sub: string[] }}
 */
export function reasonLines(item) {
  const code = item?.reason_code || ''
  if (!ROLE_CODES.has(code) || !knownCode(code)) return { main: reasonText(item), sub: [] }
  const params = item.reason_params || {}
  const sub = []
  const added = roleListText(params.added)
  const removed = roleListText(params.removed)
  if (added) sub.push(t('dailyReview.roleDelta.added', { roles: added }))
  if (removed) sub.push(t('dailyReview.roleDelta.removed', { roles: removed }))
  return { main: t('dailyReview.roleDelta.headline'), sub }
}

const parseDetails = (details) => {
  if (!details) return null
  if (typeof details !== 'string') return details
  try {
    return JSON.parse(details)
  } catch {
    return null
  }
}

/**
 * 操作日誌詳情：`details.changes` 非空時照舊列變更；否則改列原因與格式化的 details。
 * @returns {{ changes: Array, showReason: boolean, raw: string }}
 */
export function logDetailBlocks(log) {
  const parsed = parseDetails(log?.details)
  const changes = Array.isArray(parsed?.changes) ? parsed.changes : []
  if (changes.length) return { changes, showReason: false, raw: '' }
  const raw = parsed ? JSON.stringify(parsed, null, 2) : String(log?.details || '')
  return { changes, showReason: Boolean(log?.reason_code || raw), raw }
}
