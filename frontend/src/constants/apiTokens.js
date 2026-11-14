/**
 * API token 呈現的單一事實源：狀態值域、彩標、分區與排序。
 *
 * 狀態本身與優先序由後端投影決定（清單回應的 status），這裡只決定「怎麼呈現」，
 * 不以到期時間或角色清單在前端重算狀態。值域硬拷後端回應契約的七個值，
 * 完備性由 constants/__tests__/api-tokens.spec.js 鎖定。
 */
import { t } from '@/i18n'
import { roleLabel, roleTagType } from '@/constants/roles'

export const API_TOKEN_STATUSES = [
  'active',
  'expiring_soon',
  'expired',
  'revoked',
  'invalidated_by_restore',
  'suspended_account_disabled',
  'suspended_roles_revoked',
]

// 不能再使用、也不會恢復的狀態：收進「已失效」區，不提供撤銷
export const INACTIVE_STATUSES = new Set(['expired', 'revoked', 'invalidated_by_restore'])
// 摘要的「可用」：目前能呼叫的兩種
export const USABLE_STATUSES = new Set(['active', 'expiring_soon'])

export const isInactive = (token) => INACTIVE_STATUSES.has(token?.status)
export const isUsable = (token) => USABLE_STATUSES.has(token?.status)

// 彩標：琥珀＝還有事要處理（快到期、角色被收回）；紅＝已到期；
// 其餘終局或暫停狀態用中性色，不佔用品牌青
const TAG_TYPES = {
  active: 'success',
  expiring_soon: 'warning',
  expired: 'danger',
  suspended_roles_revoked: 'warning',
}
export const statusTagType = (status) => TAG_TYPES[status] || 'info'
export const statusTagClass = (status) => (TAG_TYPES[status] ? '' : 'ot-tag-neutral')

const DAY_MS = 24 * 60 * 60 * 1000

// 「N 天後到期」只是把後端判定的 expiring_soon 換成讀者看得懂的天數，不影響狀態
export const daysUntil = (iso, now = Date.now()) => {
  const at = Date.parse(iso)
  if (!Number.isFinite(at)) return null
  const startOfToday = new Date(now)
  startOfToday.setHours(0, 0, 0, 0)
  const target = new Date(at)
  target.setHours(0, 0, 0, 0)
  return Math.round((target.getTime() - startOfToday.getTime()) / DAY_MS)
}

export const statusLabel = (token, now = Date.now()) => {
  const status = token?.status
  if (status === 'expiring_soon') {
    const n = daysUntil(token.expires_at, now)
    if (n === null) return t('apiTokens.status.expiring_soon')
    if (n <= 0) return t('apiTokens.status.expiresToday')
    if (n === 1) return t('apiTokens.status.expiresTomorrow')
    return t('apiTokens.status.expiresInDays', { n })
  }
  return API_TOKEN_STATUSES.includes(status) ? t(`apiTokens.status.${status}`) : String(status ?? '')
}

// 內建範本識別與角色名不一定相同：超級管理者的範本識別是 super_admin，角色名與譯名鍵是 admin。
// 其餘內建範本的識別與角色名相同
const BUILTIN_KEY_ROLE_NAME = { super_admin: 'admin' }
const builtinRoleName = (key) => BUILTIN_KEY_ROLE_NAME[key] || key

// 以內建範本識別或自訂角色名取顯示名（系統告警參數只給這兩種值之一）
export const roleValueLabel = (value) => {
  const v = String(value ?? '').trim()
  if (!v) return ''
  return roleLabel(builtinRoleName(v))
}

// 角色顯示名：內建角色走既有的角色譯名，自訂角色用後端給的名稱
export const grantedRoleLabel = (role) => {
  if (!role) return ''
  const key = role.builtin_key
  if (key) {
    const name = builtinRoleName(key)
    const label = roleLabel(name)
    if (label !== name) return label
  }
  return role.name || key || ''
}

export const grantedRoleTagType = (role) => (role?.builtin_key ? roleTagType(builtinRoleName(role.builtin_key)) : 'info')

// 範圍文字：全系統或節點名稱清單；不生效時為空字串
export const scopeText = (scope) => {
  if (!scope) return ''
  if (scope.kind === 'global') return t('apiTokens.form.scopeAll')
  if (scope.kind === 'nodes') {
    const names = (scope.nodes || []).map((n) => n.name || `#${n.id}`)
    return names.join(t('common.listSeparator'))
  }
  return ''
}

// 「角色（範圍）、角色（範圍）」：摘要、明文顯示與確認框共用
export const rolesWithScopeText = (roles) =>
  (roles || [])
    .map((r) => {
      const scope = scopeText(r.scope)
      return scope ? t('apiTokens.roleWithScope', { role: grantedRoleLabel(r), scope }) : grantedRoleLabel(r)
    })
    .join(t('common.listSeparator'))

export const rolesText = (roles) =>
  (roles || []).map(grantedRoleLabel).join(t('common.listSeparator'))

// 授權角色含超級管理者或系統安全管理員：建立前的提示用（是否發告警由後端決定）
export const SUPER_ROLE_KEY = 'super_admin'
export const SECURITY_ROLE_KEY = 'security_admin'
export const privilegeLevel = (roles) => {
  const keys = new Set((roles || []).map((r) => r.builtin_key))
  if (keys.has(SUPER_ROLE_KEY)) return 'super'
  if (keys.has(SECURITY_ROLE_KEY)) return 'security'
  return ''
}

// 排序：可用區依到期時間由近到遠，永不到期排最後；已失效區由最近失效的排前面。
// 只決定列的順序，不判定狀態
const expiryKey = (token) => {
  const at = Date.parse(token?.expires_at)
  return Number.isFinite(at) ? at : Number.POSITIVE_INFINITY
}
// 失效時刻依狀態取：撤銷看撤銷時刻、過期看到期時刻；還原後失效沒有自己的時刻欄，
// 退回撤銷時刻再退回建立時刻。不可對三欄取最大值——撤銷時尚未到期的 token
// 會被遠在未來的到期日排到最前面
const endedKey = (token) => {
  const chain = {
    revoked: [token?.revoked_at, token?.created_at],
    expired: [token?.expires_at, token?.created_at],
  }[token?.status] || [token?.revoked_at, token?.created_at]
  for (const v of chain) {
    const at = Date.parse(v)
    if (Number.isFinite(at)) return at
  }
  return 0
}

export const splitTokens = (tokens) => {
  const list = Array.isArray(tokens) ? tokens : []
  const current = list
    .filter((tk) => !isInactive(tk))
    .sort((a, b) => expiryKey(a) - expiryKey(b) || (a.id ?? 0) - (b.id ?? 0))
  const inactive = list
    .filter((tk) => isInactive(tk))
    .sort((a, b) => endedKey(b) - endedKey(a) || (b.id ?? 0) - (a.id ?? 0))
  return { current, inactive }
}

export const summarize = (tokens) => {
  const list = Array.isArray(tokens) ? tokens : []
  return {
    usable: list.filter(isUsable).length,
    expiringSoon: list.filter((tk) => tk.status === 'expiring_soon').length,
    inactive: list.filter(isInactive).length,
    // 「撤銷全部」作用的範圍：尚未失效的（含暫停中的）
    revocable: list.filter((tk) => !isInactive(tk)).length,
  }
}

// 到期選項：沒有預選，使用者必須明確選一個。預設期限由前端換算成當天 23:59:59（本地時間），
// 後端只收時刻
export const EXPIRY_OPTIONS = ['never', 'd7', 'd30', 'd90', 'y1', 'custom']

export const endOfDay = (date) => {
  const d = new Date(date)
  d.setHours(23, 59, 59, 0)
  return d
}

export const presetExpiry = (option, now = new Date()) => {
  const d = endOfDay(now)
  if (option === 'd7') d.setDate(d.getDate() + 7)
  else if (option === 'd30') d.setDate(d.getDate() + 30)
  else if (option === 'd90') d.setDate(d.getDate() + 90)
  else if (option === 'y1') d.setFullYear(d.getFullYear() + 1)
  else return null
  return d
}

// 「N 天後」或「約 N 年後」：滿一年起改用年數
export const relativeExpiry = (date, now = Date.now()) => {
  const days = daysUntil(date instanceof Date ? date.toISOString() : date, now)
  if (days === null) return ''
  if (days >= 365) return t('apiTokens.form.expiresRel.years', { n: Math.round(days / 365) })
  return t('apiTokens.form.expiresRel.days', { n: Math.max(days, 0) })
}

// 最近一次使用時間（所有 token 中最新的一筆），沒有用過時為 null
export const latestUse = (tokens) => {
  let best = null
  for (const tk of tokens || []) {
    const at = Date.parse(tk?.last_used_at)
    if (Number.isFinite(at) && (best === null || at > best.at)) best = { at, iso: tk.last_used_at }
  }
  return best ? best.iso : null
}
