/**
 * OIDC 設定頁的提供者選擇器與收緊開關的純函式。
 *
 * 提供者只是畫面狀態：決定顯示哪一家的取值說明與欄位提示，不持久化、不送進請求。
 */
import { isEntraIssuer } from './entraIssuer'

export const PROVIDER_ENTRA = 'entra'
export const PROVIDER_GOOGLE = 'google'
export const PROVIDER_OTHER = 'other'
export const PROVIDERS = [PROVIDER_ENTRA, PROVIDER_GOOGLE, PROVIDER_OTHER]

export const GOOGLE_ISSUER = 'https://accounts.google.com'

// Google 的 iss 宣告可能不帶 scheme；兩種寫法都是 Google
const GOOGLE_ISSUERS = new Set([GOOGLE_ISSUER, 'accounts.google.com'])

/**
 * 依 issuer 帶出提供者（編輯頁用）。認不出來即「其他 OIDC」。
 * @param {string} issuer
 * @returns {'entra'|'google'|'other'}
 */
export function detectProvider(issuer) {
  const input = String(issuer ?? '').trim().replace(/\/+$/, '').toLowerCase()
  if (!input) return PROVIDER_OTHER
  if (isEntraIssuer(input)) return PROVIDER_ENTRA
  if (GOOGLE_ISSUERS.has(input)) return PROVIDER_GOOGLE
  return PROVIDER_OTHER
}

/**
 * 是否已是 Google 的 issuer（選 Google 時決定要不要覆寫 issuer 欄）。
 * @param {string} issuer
 */
export function isGoogleIssuer(issuer) {
  return detectProvider(issuer) === PROVIDER_GOOGLE
}

/**
 * 以目錄（租用戶）識別碼組成 Entra 的 issuer。空白或含空白、斜線的輸入不組。
 * @param {string} tenantId
 * @returns {string} 組好的網址；無法組成時回空字串
 */
export function composeEntraIssuer(tenantId) {
  const id = String(tenantId ?? '').trim()
  if (!id || /[\s/]/.test(id)) return ''
  return `https://login.microsoftonline.com/${id}/v2.0`
}

const ENTRA_TENANT_ISSUER = /^https:\/\/login\.microsoftonline\.com\/[^/\s]+\/v2\.0\/?$/i

/**
 * 是否符合常見的 Entra issuer 格式。只用來提醒，不擋儲存：
 * 日後格式若有變動，管理者仍可照新網址填。
 * @param {string} issuer
 */
export function looksLikeEntraTenantIssuer(issuer) {
  return ENTRA_TENANT_ISSUER.test(String(issuer ?? '').trim())
}

/**
 * 收緊開關的送出值：只有管理者真的切換過（目前值不同於載入時的基準）才送。
 * 沒動開關時不送，讓伺服端以「不變更」處理；判定為共用的來源因此不必操作開關即可存檔。
 * @param {boolean} initial 載入時的開關狀態（新增頁為 false）
 * @param {boolean} current 送出當下的開關狀態
 * @returns {{force_shared?: boolean}} 要併入請求的片段
 */
export function forceSharedPatch(initial, current) {
  return Boolean(initial) === Boolean(current) ? {} : { force_shared: Boolean(current) }
}
