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
import { roleLabel as builtinRoleLabel } from '@/constants/roles'

const REASON_PREFIX = 'dailyReview.reason.'

// 參數值是以半形逗號串接的角色名（後端已把名稱內的逗號換成空白）
const ROLE_CODES = new Set(['role_mapping_applied', 'role_mapping_applied_added', 'role_mapping_applied_removed'])

const lookup = (key, raw) => (te(key) ? t(key) : String(raw))

const enumLabel = (namespace, value) => (value ? lookup(`enum.${namespace}.${value}`, value) : '')

const roleLabel = builtinRoleLabel

/** 角色清單：逐一查 enum 譯名，查不到顯示原名，以該語系的列舉分隔接回 */
export const roleListText = (value) =>
  String(value || '')
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean)
    .map((name) => roleLabel(name))
    .join(t('common.listSeparator'))

const splitList = (value) =>
  String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)

// 範圍參數：`global` 為全系統，否則是節點清單（附總數；清單因上限被截斷時總數仍正確）
const rangeText = (value, count) => {
  if (!value) return ''
  if (value === 'global') return t('dailyReview.reasonRange.global')
  const items = splitList(value)
  return t('dailyReview.reasonRange.nodes', {
    nodes: items.join(t('common.listSeparator')),
    count: count || String(items.length),
  })
}

// 授權分級標記：逐項翻成譯名
const marksText = (value) =>
  splitList(value)
    .map((mark) => enumLabel('grantMark', mark))
    .join(t('common.listSeparator'))

// 指派對象：群組列的名稱套「使用者群組 {名稱}」；帳號列原樣
const roleTargetText = (out) =>
  out.target_kind === 'user_group' ? t('dailyReview.reasonGroupTarget', { name: out.target }) : out.target

// 需要前端二次翻譯的參數；其餘參數原樣代入
const localizeParams = (params) => {
  const out = { ...params }
  if ('action' in out) out.action = enumLabel('auditAction', out.action)
  if ('resource' in out) out.resource = enumLabel('auditResource', out.resource)
  if ('target_kind' in out) {
    out.target = roleTargetText(out)
  } else if ('target' in out) {
    out.target = lookup(`dailyReview.reasonTarget.${out.target}`, out.target)
  }
  if ('role' in out) out.role = roleLabel(out.role)
  if ('origin' in out) out.origin = enumLabel('roleAssignOrigin', out.origin)
  if ('marks' in out) out.marks = marksText(out.marks)
  if ('before' in out) out.before = rangeText(out.before, out.before_count)
  if ('after' in out) out.after = rangeText(out.after, out.after_count)
  if ('nodes' in out) out.nodes = rangeText(out.nodes, out.nodes_count)
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
