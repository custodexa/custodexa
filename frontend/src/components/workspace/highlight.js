/**
 * 把文字依關鍵字切段（不分大小寫、所有出現處），供範本以一般文字節點渲染命中片段。
 * 不產生 HTML 字串：呼叫端逐段輸出文字，命中段包一層標記元素。
 *
 * @param {string} text
 * @param {string} term 已去頭尾空白的關鍵字；空字串＝不切
 * @returns {{ text: string, hit: boolean }[]}
 */
export function highlightSegments(text, term) {
  const source = String(text ?? '')
  const needle = String(term ?? '').toLowerCase()
  if (!source) return []
  if (!needle) return [{ text: source, hit: false }]
  const lower = source.toLowerCase()
  const segments = []
  let from = 0
  let at = lower.indexOf(needle, from)
  while (at !== -1) {
    if (at > from) segments.push({ text: source.slice(from, at), hit: false })
    segments.push({ text: source.slice(at, at + needle.length), hit: true })
    from = at + needle.length
    at = lower.indexOf(needle, from)
  }
  if (from < source.length) segments.push({ text: source.slice(from), hit: false })
  return segments
}

/**
 * 「主機位址：<host>」這一行只在 host 段內標命中；標籤文字不參與比對，
 * 避免關鍵字剛好與標籤字樣相同時把標籤也標起來。
 *
 * @param {string} line 已套好語系的整行文字
 * @param {string} host 行內的主機位址字串
 * @param {string} term
 * @returns {{ text: string, hit: boolean }[]}
 */
export function hostLineSegments(line, host, term) {
  const text = String(line ?? '')
  const at = host ? text.indexOf(host) : -1
  if (at === -1) return text ? [{ text, hit: false }] : []
  const plain = (s) => (s ? [{ text: s, hit: false }] : [])
  return [
    ...plain(text.slice(0, at)),
    ...highlightSegments(host, term),
    ...plain(text.slice(at + host.length)),
  ]
}
