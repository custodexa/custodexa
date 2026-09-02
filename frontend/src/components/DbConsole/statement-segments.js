// 編輯器的送出範圍切分。
//
// **切分只決定送出的文字範圍，不解析 SQL**：分號與空行是使用者排版語句的習慣，
// 不是語法。切錯的後果是送出的範圍與使用者預期不同（他看得見送出了什麼、
// 也看得見結果），而不是語義被誤判——伺服端的執行單位語義完全不受此處影響。

/**
 * 以「分號或空行」切出各段的位移區間。空白段落一律略去。
 * @param {string} text 編輯器全文
 * @returns {{start: number, end: number, text: string}[]}
 */
export function splitSegments(text) {
  const source = String(text ?? '')
  const bounds = []
  let start = 0
  let i = 0
  while (i < source.length) {
    if (source[i] === ';') {
      bounds.push({ start, end: i + 1 })
      i += 1
      start = i
      continue
    }
    if (source[i] === '\n') {
      const blank = /^\n[ \t\r]*\n/.exec(source.slice(i))
      if (blank) {
        bounds.push({ start, end: i })
        i += blank[0].length
        start = i
        continue
      }
    }
    i += 1
  }
  if (start < source.length) bounds.push({ start, end: source.length })
  return bounds
    .map((b) => ({ ...b, text: source.slice(b.start, b.end) }))
    .filter((b) => b.text.trim() !== '')
}

/**
 * 游標所在的那一段。
 * 游標落在段與段之間的空白時取前一段——「剛打完分號就按執行」是最常見的動作。
 * @param {string} text 編輯器全文
 * @param {number} cursor `selectionStart`
 * @returns {string} 送出的原文（已去頭尾空白；段末的分號保留）
 */
export function segmentAtCursor(text, cursor) {
  const segments = splitSegments(text)
  if (segments.length === 0) return ''
  const pos = Math.max(0, Math.min(Number(cursor) || 0, String(text ?? '').length))
  const hit = segments.find((s) => pos >= s.start && pos <= s.end)
  if (hit) return hit.text.trim()
  const before = [...segments].reverse().find((s) => s.end <= pos)
  return (before || segments[0]).text.trim()
}
