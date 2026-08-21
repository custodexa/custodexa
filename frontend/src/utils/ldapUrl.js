/**
 * LDAP 目錄位址的 canonical origin 比較（前端側，ldap-settings-migration D3）。
 *
 * **後端才是權威**：伺服端以單一嚴格 parser 解析並在「位址變更且既存有密碼」時
 * 回 400 強制重供密碼。此處的唯一用途是**提前提示**——讓管理者在按下儲存之前就
 * 知道要重填密碼，而不是送出後才被拒。
 *
 * 因此本模組刻意採「寧可多提示、不可漏提示」的降級策略：解析不出來時回 null，
 * 由 sameLdapEndpoint 退回字面比較，而不是靜默視為「沒變」。
 */

// 協定預設埠：比較一律補成顯式埠，否則 ldap://h 與 ldap://h:389 會被誤判為不同端點
const DEFAULT_PORTS = { ldap: '389', ldaps: '636' }

// 僅 origin 形狀 `ldap[s]://host[:port]`——與後端文法一致：不接受 userinfo、
// 路徑、查詢字串與片段（`ldap://user:secret@host/...` 形態會使憑證流入 UI 與日誌）
// 大小寫不敏感：伺服端解析時先 ToLower 再比對 scheme，`LDAPS://H` 是合法輸入。
// 這裡若寫成大小寫敏感，改個大小寫就會被誤判成「換了端點」而彈出重供密碼提示
const ORIGIN_RE = /^(ldaps?):\/\/(\[[0-9A-Fa-f:.]+\]|[^/?#@[\]:]+)(?::(\d{1,5}))?$/i

/**
 * 解析為 canonical origin 字串（scheme 與 host 小寫、埠恆顯式、去 FQDN 尾點）。
 * @param {string} raw 使用者輸入的目錄位址
 * @returns {string|null} `ldaps://dir.example.com:636`；不符文法時 null
 */
export function canonicalLdapOrigin(raw) {
  const input = String(raw ?? '').trim()
  if (!input) return null
  const m = ORIGIN_RE.exec(input)
  if (!m) return null

  const scheme = m[1].toLowerCase()
  // 尾點：`host.` 與 `host` 在 DNS 是同一名稱，不去掉會讓純加一點的改動被當成換端點
  const host = m[2].toLowerCase().replace(/\.$/, '')
  if (!host || host === '[]') return null

  const port = m[3] || DEFAULT_PORTS[scheme]
  const portNum = Number(port)
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return null

  return `${scheme}://${host}:${port}`
}

/**
 * 兩個位址是否指向同一端點。
 *
 * 任一方解析失敗即退回去空白後的字面比較：此時「有沒有變」仍能判斷，只是失去
 * 大小寫與預設埠的等價性——對提示而言是安全的方向（多提示一次，不會漏）。
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function sameLdapEndpoint(a, b) {
  const ca = canonicalLdapOrigin(a)
  const cb = canonicalLdapOrigin(b)
  if (ca && cb) return ca === cb
  return String(a ?? '').trim() === String(b ?? '').trim()
}
