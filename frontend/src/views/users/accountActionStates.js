/**
 * 帳號動作的可見性與停用條件（列表頁與詳情頁共用的單一來源）。
 *
 * 既有條件（與抽出前的列表頁相同，只依目標列本身）：
 * - 密碼與外部身分動作：agent 不出現；
 * - 設定密碼：外部憑證帳號為停用；
 * - 停用多因素驗證：只有已啟用才出現；
 * - 停用／啟用：依帳號狀態二選一；解鎖：鎖定期間才出現。
 *
 * 在既有條件上疊加伺服器下發的保護分類（`account_ops`，只有單筆讀取才有）：
 * allowed 不改變、notify 維持可按並於執行前提示、super_only 改為停用並附說明。
 * 沒有分類時（列表頁）完全等於既有條件。分類只供呈現，伺服器仍是最終裁決。
 */
export const ACCOUNT_ACTION_KEYS = [
  'set_password',
  'disable_mfa',
  'bind_identity',
  'unbind_identity',
  'unbind_and_disable',
  'disable',
  'enable',
  'delete',
  'unlock',
]

const LIFECYCLE = new Set(['unbind_and_disable', 'disable', 'enable', 'delete'])
const IDENTITY_GROUP = ['set_password', 'disable_mfa', 'bind_identity']

/** 憑證是否由外部提供者管理：external_credential 為權威旗標，缺欄時退回 is_ldap。 */
export const isExternalAccount = (row) =>
  row?.external_credential === true ||
  (row?.external_credential === undefined && row?.is_ldap === true)

/** 鎖定期間：locked_until 未到才算。 */
export const isLocked = (row) =>
  Boolean(row?.locked_until) && new Date(row.locked_until) > new Date()

/** 目標持有的保護身分：'super'、'security' 或 ''（取較嚴者）。由保護分類推得，不讀角色名。 */
export function protectedIdentity(accountOps) {
  if (!accountOps) return ''
  if (IDENTITY_GROUP.some((k) => accountOps[k] === 'super_only')) return 'super'
  if (IDENTITY_GROUP.some((k) => accountOps[k] === 'notify')) return 'security'
  // 設定密碼等皆放行，但生命週期被擋：只可能是持有保護身分的目標
  if (LIFECYCLE.size && [...LIFECYCLE].some((k) => accountOps[k] === 'super_only')) return 'super'
  return ''
}

function baseState(key, row) {
  const agent = row?.kind === 'agent'
  switch (key) {
    case 'set_password':
      return { visible: !agent, disabled: isExternalAccount(row), reason: isExternalAccount(row) ? 'users.externalPasswordShort' : '' }
    case 'disable_mfa':
      return { visible: Boolean(row?.totp_enabled), disabled: false, reason: '' }
    case 'bind_identity':
      return { visible: !agent, disabled: false, reason: '' }
    case 'unbind_identity':
    case 'unbind_and_disable':
      return { visible: !agent, disabled: false, reason: '' }
    case 'disable':
      return { visible: row?.active !== false, disabled: false, reason: '' }
    case 'enable':
      return { visible: row?.active === false, disabled: false, reason: '' }
    case 'delete':
      return { visible: true, disabled: false, reason: '' }
    case 'unlock':
      return { visible: isLocked(row), disabled: false, reason: '' }
    default:
      return { visible: false, disabled: false, reason: '' }
  }
}

/**
 * @returns {Record<string, {visible:boolean, disabled:boolean, reason:string, notify:boolean}>}
 *   reason 為 i18n 鍵（空字串＝無說明）
 */
export function accountActionStates(row, accountOps = null) {
  const out = {}
  const holder = protectedIdentity(accountOps)
  for (const key of ACCOUNT_ACTION_KEYS) {
    const s = { ...baseState(key, row), notify: false }
    const cls = accountOps ? accountOps[key] : undefined
    if (s.visible && cls === 'super_only') {
      if (!s.disabled) {
        s.disabled = true
        s.reason = LIFECYCLE.has(key)
          ? holder === 'security'
            ? 'userDetail.accountOps.blocked.lifecycleSecurity'
            : 'userDetail.accountOps.blocked.lifecycleSuper'
          : 'userDetail.accountOps.blocked.superAccount'
      }
    } else if (s.visible && !s.disabled && cls === 'notify') {
      s.notify = true
    }
    out[key] = s
  }
  return out
}
