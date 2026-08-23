/**
 * SSO 交棒工具。
 *
 * 兩件事必須在此收口，否則散落各處必有一處寫錯：
 *   1. **瀏覽器綁定**：原值只存 sessionStorage（per-tab，不隨網址流動），
 *      送出去的只有它的 SHA-256。防 login CSRF——攻擊者即使把自己完成授權的
 *      callback 網址交給受害者，受害者分頁內沒有對應原值，兌換必失敗。
 *   2. **fragment 抹除**：ticket 走 fragment 交棒（不進反向代理 access log），
 *      但仍會留在網址列與 history。讀到後 SHALL 立即 replaceState 抹除，
 *      **先於任何其他動作**——否則兌換期間的任何跳轉或錯誤都可能讓它被保存。
 */

/** sessionStorage 鍵名：瀏覽器綁定原值 */
export const SSO_SECRET_KEY = 'ot-sso-binding'

/** 綁定原值位元組數（256 bit，與雜湊等寬） */
const SECRET_BYTES = 32

const toHex = (bytes) =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

/**
 * WebCrypto 是否可用。
 *
 * `crypto.subtle` 僅存在於 secure context（https 或 localhost）——純 http 部署
 * 下它是 undefined。呼叫端據此給出「需 HTTPS」的可行動訊息，而非泛用失敗。
 * @returns {boolean}
 */
export function isSSOCryptoAvailable() {
  return typeof globalThis.crypto?.subtle?.digest === 'function' &&
    typeof globalThis.crypto?.getRandomValues === 'function'
}

/**
 * 產生瀏覽器綁定原值（密碼學隨機，hex 編碼）
 * @returns {string}
 */
export function createBrowserSecret() {
  const bytes = new Uint8Array(SECRET_BYTES)
  globalThis.crypto.getRandomValues(bytes)
  return toHex(bytes)
}

/**
 * 計算 SHA-256 並以 hex 回傳（送往後端的 binding 值）
 * @param {string} value - 綁定原值
 * @returns {Promise<string>}
 */
export async function sha256Hex(value) {
  const data = new TextEncoder().encode(value)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data)
  return toHex(new Uint8Array(digest))
}

/**
 * 產生綁定原值、存入 sessionStorage 並回其雜湊
 * @returns {Promise<string>} binding 雜湊（hex）
 */
export async function prepareBrowserBinding() {
  const secret = createBrowserSecret()
  const hash = await sha256Hex(secret)
  // 先算出雜湊再寫入：digest 失敗時不留下無主的殘值
  sessionStorage.setItem(SSO_SECRET_KEY, secret)
  return hash
}

/**
 * 取出並清除 sessionStorage 的綁定原值（一次性）
 * @returns {string} 取不到時回空字串（多半是使用者在新分頁完成 callback）
 */
export function consumeBrowserSecret() {
  const secret = sessionStorage.getItem(SSO_SECRET_KEY) || ''
  sessionStorage.removeItem(SSO_SECRET_KEY)
  return secret
}

/** 清除殘留的綁定原值（發起失敗或使用者放棄時） */
export function clearBrowserSecret() {
  sessionStorage.removeItem(SSO_SECRET_KEY)
}

/**
 * 讀取並**立即抹除** URL fragment 的 SSO 交棒內容。
 *
 * 呼叫端 SHALL 於進入登入頁的第一時間呼叫（先於其他動作）。
 * @returns {{ ticket: string, error: string }} 兩者皆空即非 SSO 返回
 */
export function consumeSSOHandoff() {
  const raw = (window.location.hash || '').replace(/^#/, '')
  if (!raw) {
    return { ticket: '', error: '' }
  }
  const params = new URLSearchParams(raw)
  const ticket = params.get('sso_ticket') || ''
  const error = params.get('sso_error') || ''
  if (!ticket && !error) {
    return { ticket: '', error: '' }
  }
  // 抹除必須先於回傳：呼叫端拿到值之後才做的任何事都已在乾淨網址下進行
  const clean = window.location.pathname + window.location.search
  window.history.replaceState(window.history.state, '', clean)
  return { ticket, error }
}
