// 單元測試用的 `/auth/me` 能力回應夾具。
//
// 內容是後端內建範本目前的有效權限集合（authz/builtin_templates.go）與衍生呈現點規則的**測試側複本**，
// 只供元件／composable 單元測試組出「某種身分的 /auth/me 回應」。生產程式碼不得引用本檔；
// 入口等價基準（authz-baseline-entries）不用本檔，輸入取自後端擷取的投影。
import { setCapabilitiesForTests } from '@/composables/useCapabilities'

export const ADMIN_PERMISSIONS = [
  'accessreview:manage', 'alert:manage', 'alert:view', 'alertrule:manage', 'approverscope:manage',
  'approverscope:manage_applicant',
  'asset:create', 'asset:delete', 'asset:test', 'asset:update', 'asset:view', 'assetgroup:manage',
  'audit:integrity_view', 'audit:view', 'authorization:manage', 'changesecret:manage', 'compliance:view',
  'account:rotate', 'credential:bind', 'credential:convert-scope', 'credential:create', 'credential:delete',
  'credential:detach', 'credential:manage', 'credential:rotate', 'credential:set-secret', 'credential:update',
  'credential:view', 'hostkey:reset', 'identity_source:manage', 'instanceguard:view', 'key:manage',
  'ldap:manage', 'notification_channel:manage', 'offsite:manage', 'oidc:manage', 'policygroup:manage',
  'policygroup:view', 'role:view', 'rotation_schedule:manage', 'schedule:manage', 'securitypolicy:manage',
  'session:terminate', 'session:view', 'syslog:manage', 'transmission:manage', 'user:manage', 'usergroup:manage',
]
export const AUDITOR_PERMISSIONS = [
  'alert:manage', 'alert:view', 'asset:view', 'audit:integrity_view', 'audit:view',
  'compliance:view', 'policygroup:view', 'session:view',
]
export const USER_PERMISSIONS = ['asset:view']

/**
 * 依舊主角色折疊（admin > auditor > user；零角色視同 user；只有 approver 能力為空）與
 * 衍生呈現點規則組出 permissions。roles 是測試的敘述輸入，不是前端的授權來源。
 */
export function permissionsFor(roles = ['user'], { approver, owns = false, create = false } = {}) {
  const has = (r) => roles.includes(r)
  const isApprover = approver ?? has('approver')
  let base = []
  let legacy = 'none'
  if (has('admin')) [base, legacy] = [ADMIN_PERMISSIONS, 'admin']
  else if (has('auditor')) [base, legacy] = [AUDITOR_PERMISSIONS, 'auditor']
  else if (has('user') || roles.length === 0) [base, legacy] = [USER_PERMISSIONS, 'user']
  const out = new Set(base)
  if (isApprover) out.add('ui:approvals')
  if (owns || create) out.add('ui:my-agents')
  if (legacy === 'admin' || legacy === 'auditor') out.add('ui:assets-global')
  if (legacy !== 'admin' && legacy !== 'auditor') out.add('ui:self-service-actions')
  if (legacy === 'admin') out.add('ui:connect-bypass')
  if (legacy === 'admin') out.add('ui:super-admin')
  return [...out].sort()
}

/** 組出一份 GET /auth/me 的成功回應本文（含兩個新增欄位）。 */
export function meBody(roles = ['user'], flags = {}, extra = {}) {
  const permissions = permissionsFor(roles, flags)
  return {
    id: 1,
    username: 'tester',
    roles,
    is_approver: flags.approver ?? roles.includes('approver'),
    owns_agents: Boolean(flags.owns),
    can_self_create_agent: Boolean(flags.create),
    permissions,
    scope_summary: permissions.filter((p) => !p.startsWith('ui:')).map((permission) => ({ permission, binding_scope: 'global' })),
    ...extra,
  }
}

/** 直接把某種身分的能力寫入共用狀態（頁面／元件單元測試用）。 */
export function grantFor(roles = ['user'], flags = {}) {
  setCapabilitiesForTests(permissionsFor(roles, flags))
}
