/**
 * 資產名稱的顯示截斷（側欄名稱欄放不下時用）。
 *
 * 同一批主機的名稱常常只差尾碼（`-r-01`／`-r-02`），單純從尾端省略會讓
 * 兩列看起來一模一樣，所以截斷規則以「保住能區辨的那一段」為準：
 *
 *   1. 放得下就原樣顯示。
 *   2. 名稱含 `.` 視為「主機名.網域」：主機名（第一個 `.` 前）完整保留，
 *      網域自尾端省略，例如 `mysql-101-r-01.acme…`。
 *   3. 不含 `.`，或主機名本身放不下：捨去網域，對主機名做保留尾段的中段省略，
 *      例如 `acme-db-pro…primary-01`（尾段取較大的一半）。
 *   4. 可用字數小於 3 時退回尾端省略，避免頭尾段為零。
 *
 * 純函式、不碰 DOM；字數由呼叫端依名稱欄實際寬度換算。
 */

export const ELLIPSIS = '…'

/** 保留尾段的中段省略：頭段＋…＋尾段，總長恰為 maxChars */
function middleEllipsis(text, maxChars) {
  const keep = maxChars - 1
  const tail = Math.ceil(keep / 2)
  const head = keep - tail
  return text.slice(0, head) + ELLIPSIS + text.slice(text.length - tail)
}

/**
 * @param {string} name 資產全名
 * @param {number} maxChars 名稱欄放得下的字數
 * @returns {string} 顯示字串（截斷時含單一字元的省略號）
 */
export function formatAssetLabel(name, maxChars) {
  const text = String(name ?? '')
  const max = Math.floor(Number(maxChars))
  // 量不到寬度（尚未量測、非數值）時不截斷，交給 CSS 的單行省略兜底
  if (!Number.isFinite(max) || text.length <= max) return text
  if (max <= 0) return ''
  if (max < 3) return text.slice(0, max - 1) + ELLIPSIS

  const dot = text.indexOf('.')
  if (dot > 0) {
    // 主機名＋「.」＋至少一字網域＋省略號放得下：主機名完整、網域從尾端省略
    if (dot + 3 <= max) return text.slice(0, max - 1) + ELLIPSIS
    const host = text.slice(0, dot)
    // 主機名剛好放得下但網域一字都擠不進：只留完整主機名，省略號標示後面還有
    if (host.length + 1 <= max) return host + ELLIPSIS
    return middleEllipsis(host, max)
  }
  return middleEllipsis(text, max)
}
