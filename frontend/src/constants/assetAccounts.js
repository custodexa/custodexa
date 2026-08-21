/**
 * 資產帳號顯示中繼資料唯一事實源（asset-multi-account D2/D5）。
 *
 * 值域硬拷後端：`@ALL` 對應 `model.AccountScopeAll`；憑證型別為**前端導出枚舉**
 * （後端只回 has_password／has_private_key 兩布林，不回密文），四值窮盡兩布林積。
 * label 譯文住 locale（enum.accountCredential.*），以 getter 回 t()——render 期
 * 取值可被依賴追蹤，切語言自動重繪；tag 色屬非譯 metadata 留此處。
 */
import { t } from '@/i18n'

/** 全帳號別名（後端 model.AccountScopeAll 的前端鏡像；`@` 前綴為授權別名保留命名空間） */
export const ACCOUNT_SCOPE_ALL = '@ALL'

/**
 * 授權帳號範圍是否為「全部帳號」。
 * 空陣列／缺欄同義於 `@ALL`——後端序列化恆顯化為 `["@ALL"]`，此處守住
 * 單測替身等未經序列化的路徑，語義與 `model.AccountScope.IsAll()` 一致。
 * @param {string[]|undefined|null} accounts
 * @returns {boolean}
 */
export const isAllAccountScope = (accounts) =>
  !Array.isArray(accounts) || accounts.length === 0 || accounts.includes(ACCOUNT_SCOPE_ALL)

/** 憑證型別值域（前端導出枚舉，窮盡 has_password × has_private_key） */
export const ACCOUNT_CREDENTIAL_VALUES = ['password', 'private_key', 'both', 'none']

const credentialMeta = (value, tagType) => ({
  tagType,
  get label() {
    return t(`enum.accountCredential.${value}`)
  },
})

export const ACCOUNT_CREDENTIAL_META = {
  password: credentialMeta('password', 'success'),
  private_key: credentialMeta('private_key', 'primary'),
  both: credentialMeta('both', 'success'),
  // none＝零憑證帳號（合法：原本即無憑證的資產），語意上非錯誤故用 info 而非 danger
  none: credentialMeta('none', 'info'),
}

/**
 * 由帳號物件導出憑證型別。
 * @param {{has_password?: boolean, has_private_key?: boolean}} account
 * @returns {'password'|'private_key'|'both'|'none'}
 */
export const accountCredentialType = (account) => {
  const hasPassword = !!account?.has_password
  const hasPrivateKey = !!account?.has_private_key
  if (hasPassword && hasPrivateKey) return 'both'
  if (hasPrivateKey) return 'private_key'
  if (hasPassword) return 'password'
  return 'none'
}

export const accountCredentialLabel = (account) =>
  ACCOUNT_CREDENTIAL_META[accountCredentialType(account)].label

export const accountCredentialTagType = (account) =>
  ACCOUNT_CREDENTIAL_META[accountCredentialType(account)].tagType
