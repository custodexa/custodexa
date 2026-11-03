/**
 * 把一段提示拆成粗體首句與其後的說明：以第一個句號（中日文「。」「．」，或英文「. 」）為界。
 * 找不到句號時整段當首句、說明為空。
 * @param {string} text
 * @returns {{ head: string, body: string }}
 */
export function splitLead(text) {
  const s = String(text ?? '')
  const m = /[。．]|\.\s/.exec(s)
  if (!m) return { head: s, body: '' }
  const end = m.index + 1
  return { head: s.slice(0, end), body: s.slice(end).trim() }
}
