/**
 * Microsoft Entra ID 的 issuer 辨識（與伺服端同語義）。
 *
 * 只看主機：租戶專屬（/<tenant>/v2.0）與多租戶端點都屬同一家，而建議的正式
 * 設定是租戶專屬 issuer，路徑比對會把它漏掉。解析不出主機即回 false——
 * 認不出來時頁面維持一般提供者的行為。
 */

const ENTRA_ISSUER_HOST = 'login.microsoftonline.com'

/**
 * @param {string} issuer 使用者輸入或伺服端回傳的 issuer
 * @returns {boolean}
 */
export function isEntraIssuer(issuer) {
  const input = String(issuer ?? '').trim()
  if (!input) return false
  try {
    return new URL(input).hostname.toLowerCase() === ENTRA_ISSUER_HOST
  } catch {
    return false
  }
}
