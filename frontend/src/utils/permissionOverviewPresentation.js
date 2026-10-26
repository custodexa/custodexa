// 權限一覽的呈現工具：把伺服器算好的欄位轉成白話。
//
// 只做呈現，不做授權判斷：不推算權限集合、範圍或交集；範圍種類、來源種類、不生效原因、
// 台數與旗標一律取自回應。第一層文字不放權限鍵、角色內建鍵與數字識別，細分動作名只在第二層用。
import { t, te } from '@/i18n'
import { roleLabel } from '@/constants/roles'
import { SCOPE_CLASS, classifyRole } from './roleScopePresentation'

const NOT_APPLICABLE_CLASSES = [SCOPE_CLASS.NOT_SCOPABLE, SCOPE_CLASS.BUILTIN_GLOBAL_ONLY, SCOPE_CLASS.NO_SCOPED_PERMISSION]

/** 角色顯示名（合成來源沒有角色，回空字串） */
export const roleName = (role) => (role && role.name ? roleLabel(role.name) : '')

/**
 * 全系統範圍的角色是否寫「不適用」：不能限定節點的角色、只在全系統生效的內建角色，
 * 以及沒有角色的合成來源。判斷取自角色列表的 scopable／node_range_no_effect，不依角色名稱；
 * 被檢視者是超級管理者時一律寫全系統。
 * @param {object|null} role 回應中的角色
 * @param {Map<number, object>} defsById 角色列表（可為空 Map，空時一律視為可限定）
 * @param {boolean} superAdmin 回應的 management.identity.super_admin
 */
export function scopeNotApplicable(role, defsById, superAdmin) {
  if (superAdmin) return false
  if (!role) return true
  const def = defsById?.get(role.id)
  return NOT_APPLICABLE_CLASSES.includes(classifyRole(def))
}

/**
 * 一個範圍的白話：全系統（或不適用）、節點路徑，節點全數失效時只寫失效筆數。
 * @returns {{text:string, inactive:string}} inactive 為另行呈現的「節點已不存在」說明（沒有則空字串）
 */
export function scopeParts(scope, { notApplicable = false } = {}) {
  const s = scope || { kind: 'global', nodes: [], inactive_node_count: 0 }
  if (s.kind !== 'nodes') {
    return { text: notApplicable ? t('permissionOverview.card.notApplicable') : t('permissionOverview.card.global'), inactive: '' }
  }
  const nodes = Array.isArray(s.nodes) ? s.nodes : []
  const inactive = s.inactive_node_count > 0 ? t('permissionOverview.card.inactiveNodes', { n: s.inactive_node_count }) : ''
  return { text: nodes.map((n) => n.path).join(t('common.listSeparator')), inactive }
}

/** 一個來源的白話句；管理者指派只寫「管理者指派」，不帶人名、日期或釘住字樣 */
export function sourceSentences(source) {
  const s = source || {}
  switch (s.kind) {
    case 'direct':
      return [t('permissionOverview.source.direct')]
    case 'mapped': {
      const rules = Array.isArray(s.mapping_rules) ? s.mapping_rules : []
      if (!rules.length) return [t('permissionOverview.source.mappedNoRule')]
      return rules.map((r) => t('permissionOverview.source.mapped', { source: r.source_name, group: r.external_group }))
    }
    case 'group': {
      const name = s.group?.name || ''
      const base = t('permissionOverview.source.group', { group: name })
      const viaMapping = s.group?.member_source === 'mapped' || s.group?.member_source === 'both'
      return [viaMapping ? `${base}${t('permissionOverview.source.groupMapped')}` : base]
    }
    case 'compat_default':
      return [t('permissionOverview.source.compatDefault')]
    case 'agent_fixed':
      return [t('permissionOverview.source.agentFixed')]
    default:
      return []
  }
}

const camelOf = (key) =>
  String(key)
    .split(/[:\-_]/)
    .map((p, i) => (i === 0 ? p : p.charAt(0).toUpperCase() + p.slice(1)))
    .join('')

/** 細分動作名（第二層才用）：查不到譯文時退回原鍵 */
export function permissionName(key) {
  const k = String(key || '')
  const detailKey = `roles.editor.detail.${k.replace(/[:]/g, '.')}`
  if (te(detailKey)) return t(detailKey)
  const capKey = `roles.editor.capability.${k.replace(/[:-]/g, '_')}`
  if (te(capKey)) return t(capKey)
  const labelKey = `roles.permissionLabel.${camelOf(k)}`
  if (te(labelKey)) return t(labelKey)
  return k
}

/** 入口名：取自角色編輯器的入口名，查不到才退回識別 */
export const entryName = (id) => (te(`roles.editor.entry.${id}`) ? t(`roles.editor.entry.${id}`) : String(id))

export const ENTRY_GROUPS = Object.freeze(['manage', 'partial', 'read', 'available'])

const INEFFECTIVE_REASONS = ['nodes_all_deleted', 'permission_not_node_scopable', 'builtin_requires_global']
/** 不生效原因的白話；未知原因不顯示原因碼 */
export const ineffectiveReasonText = (reason) =>
  INEFFECTIVE_REASONS.includes(reason) ? t(`permissionOverview.ineffective.reason.${reason}`) : t('permissionOverview.ineffective.reason.unknown')

/** 時效：常設、到期日、起日或區間 */
export function validityText(validity, fmt) {
  const start = validity?.date_start
  const end = validity?.date_expired
  if (start && end) return t('permissionOverview.connect.validity.range', { start: fmt(start), end: fmt(end) })
  if (end) return t('permissionOverview.connect.validity.until', { date: fmt(end) })
  if (start) return t('permissionOverview.connect.validity.from', { date: fmt(start) })
  return t('permissionOverview.connect.validity.permanent')
}

/** 連線政策：open 與缺值不顯示；混合、需事由、需核准各一句 */
export function policyText(policy) {
  if (policy === 'mixed') return t('permissionOverview.connect.policy.mixed')
  if (policy === 'reason') return t('permissionOverview.connect.policy.reason')
  if (policy === 'approval') return t('permissionOverview.connect.policy.approval')
  return ''
}

/** 經由：本人或群組 */
export const viaText = (via) =>
  via?.type === 'group'
    ? t('permissionOverview.connect.via.group', { group: via.group_name || '' })
    : t('permissionOverview.connect.via.self')

/** 帳號範圍：null 為全部帳號 */
export const accountText = (accounts) =>
  Array.isArray(accounts) && accounts.length
    ? t('permissionOverview.connect.account.named', { accounts: accounts.join(t('common.listSeparator')) })
    : t('permissionOverview.connect.account.all')
