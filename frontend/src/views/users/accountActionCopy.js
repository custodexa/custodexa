/**
 * 使用者管理頁「刪除使用者」「停用 MFA」確認框的文案選擇與版面。
 *
 * 同一個動作對不同帳號的後果不同：已綁外部身分的帳號刪除時會一併解除綁定，
 * 之後此人再登入可能被自動重建（角色只依映射回來），也可能被擋在門外；
 * 目錄帳號同樣會被重建；停用 MFA 對只經身分提供者登入的人不是「只需密碼」。
 * 確認框必須依帳號類型講出實際後果，並把「只是想停用 MFA／暫停登入」的人
 * 引導到可逆的操作。
 *
 * 判定依據全部取自列表列，不需額外 API：
 *   - provisioning_origin（權威）／is_ldap（舊後端退回）→ 目錄帳號
 *   - external_credential → 憑證由外部提供者管理（無本地密碼）
 *   - auth_provider_names → 已綁定的身分提供者實例名（只含 OIDC）
 */
import { h } from 'vue'

export const ACCOUNT_KIND = Object.freeze({
  LOCAL: 'local', // 本地帳號，未綁外部身分
  MIXED: 'mixed', // 本地密碼，且已綁外部身分
  EXTERNAL: 'external', // 只經身分提供者登入（無本地密碼、非目錄帳號）
  LDAP: 'ldap', // 目錄帳號
})

const providerNames = (row) =>
  Array.isArray(row?.auth_provider_names) ? row.auth_provider_names.filter(Boolean) : []

const isDirectoryAccount = (row) =>
  row?.provisioning_origin === 'ldap' || (!row?.provisioning_origin && row?.is_ldap === true)

/** 四類帳號判定（停用 MFA 依此選字）。 */
export function accountKind(row) {
  if (isDirectoryAccount(row)) return ACCOUNT_KIND.LDAP
  if (row?.external_credential === true) return ACCOUNT_KIND.EXTERNAL
  if (providerNames(row).length > 0) return ACCOUNT_KIND.MIXED
  return ACCOUNT_KIND.LOCAL
}

// 名稱清單分隔：英文用逗號，中日文用頓號
const joinProviders = (names, locale) =>
  names.join(String(locale || '').startsWith('en') ? ', ' : '、')

/**
 * 刪除確認框的文案結構（只回鍵與參數，不碰 i18n，方便單測）。
 * 已綁外部身分優先於目錄帳號：綁定被解除是兩者共有、但只有前者才有的後果。
 * @returns {{ main: {key, params}, impact: null | {lead?, items: string[]}, tip: string }}
 */
export function deleteConfirmCopy(row, locale) {
  const name = row?.username ?? ''
  const names = providerNames(row)
  if (names.length > 0) {
    return {
      main: {
        key: 'users.deleteConfirmExternal',
        params: { name, providers: joinProviders(names, locale) },
      },
      impact: {
        lead: 'users.deleteImpactExternalLead',
        items: ['users.deleteImpactExternalJit', 'users.deleteImpactExternalPrebound'],
      },
      tip: 'users.deleteTipExternal',
    }
  }
  if (isDirectoryAccount(row)) {
    return {
      main: { key: 'users.deleteConfirmLdap', params: { name } },
      impact: { items: ['users.deleteImpactLdap'] },
      tip: 'users.deleteTipLdap',
    }
  }
  return {
    main: { key: 'users.deleteConfirmLocal', params: { name } },
    impact: null,
    tip: 'users.deleteTipLocal',
  }
}

const MFA_KEYS = {
  [ACCOUNT_KIND.LOCAL]: 'users.disableMFAConfirmLocal',
  [ACCOUNT_KIND.MIXED]: 'users.disableMFAConfirmMixed',
  [ACCOUNT_KIND.EXTERNAL]: 'users.disableMFAConfirmExternal',
  [ACCOUNT_KIND.LDAP]: 'users.disableMFAConfirmLdap',
}

/** 停用 MFA 確認框的文案結構：主句依帳號類型，共同句尾為政策提醒。 */
export function disableMFAConfirmCopy(row) {
  return {
    main: { key: MFA_KEYS[accountKind(row)], params: { name: row?.username ?? '' } },
    note: 'users.disableMFAPolicyNote',
  }
}

// MessageBox 內容掛在 body 下（不受頁面 scoped style 影響），版面以行內樣式表達，
// 色彩一律取設計 token
const STYLE = {
  body: 'display:flex;flex-direction:column;gap:var(--ot-space-sm);line-height:1.6',
  main: 'margin:0',
  secondary:
    'margin:0;color:var(--ot-text-secondary);font-size:var(--ot-font-size-sm)',
  list: 'margin:2px 0 0;padding-left:1.2em',
  tip:
    'margin:0;padding:var(--ot-space-sm) 12px;border-radius:var(--ot-radius-md);' +
    'background:var(--ot-primary-dim);font-size:var(--ot-font-size-sm)',
}

/** 刪除確認框內容（VNode）：主句、後果（次要色小字）、改用可逆操作的提示（淺藍底）。 */
export function renderDeleteConfirm(row, t, locale) {
  const copy = deleteConfirmCopy(row, locale)
  const children = [
    h('p', { class: 'account-action-main', style: STYLE.main }, t(copy.main.key, copy.main.params)),
  ]
  if (copy.impact) {
    const impactChildren = []
    if (copy.impact.lead) impactChildren.push(t(copy.impact.lead))
    if (copy.impact.items.length > 1) {
      impactChildren.push(
        h('ul', { style: STYLE.list }, copy.impact.items.map((k) => h('li', t(k))))
      )
    } else {
      impactChildren.push(t(copy.impact.items[0]))
    }
    children.push(
      h('div', { class: 'account-action-impact', style: STYLE.secondary }, impactChildren)
    )
  }
  children.push(h('p', { class: 'account-action-tip', style: STYLE.tip }, t(copy.tip)))
  return h('div', { class: 'account-action-confirm', style: STYLE.body }, children)
}

/** 停用 MFA 確認框內容（VNode）：主句＋次要色共同句尾。 */
export function renderDisableMFAConfirm(row, t) {
  const copy = disableMFAConfirmCopy(row)
  return h('div', { class: 'account-action-confirm', style: STYLE.body }, [
    h('p', { class: 'account-action-main', style: STYLE.main }, t(copy.main.key, copy.main.params)),
    h('p', { class: 'account-action-note', style: STYLE.secondary }, t(copy.note)),
  ])
}
