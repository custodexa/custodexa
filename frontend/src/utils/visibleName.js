// 主機傳回的名稱（帳號名、群組名、別名）的顯示跳脫。
//
// 主機上的名稱原樣保存，可能夾帶看不見或易混淆的字元（雙向控制、零寬字元、
// 各種空白）。畫面把這些字元改成可見的 <U+XXXX>，避免名稱偽裝成別的字串。
// 回傳片段陣列，由元件以文字節點渲染（不使用 v-html）。

// Unicode 一般類別 Cf（格式字元）、Zl、Zp，以及 U+0020 以外的 Zs；U+FEFF 屬 Cf，已涵蓋。
const ESCAPE_RE = /[\p{Cf}\p{Zl}\p{Zp}\p{Cc}]|(?!\x20)\p{Zs}/u

function codeLabel(ch) {
  const hex = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')
  return `<U+${hex}>`
}

/**
 * @param {string} raw 主機傳回的原始字串
 * @returns {{ segments: Array<{text: string, escaped: boolean}>, hasEscaped: boolean, hasNonAscii: boolean }}
 */
export function visibleName(raw) {
  const str = typeof raw === 'string' ? raw : raw == null ? '' : String(raw)
  const chars = Array.from(str)
  const segments = []
  let hasEscaped = false
  let hasNonAscii = false

  const push = (text, escaped) => {
    const last = segments[segments.length - 1]
    if (last && last.escaped === escaped && !escaped) {
      last.text += text
    } else {
      segments.push({ text, escaped })
    }
  }

  // 首尾連續的 U+0020 以「␠」顯示，避免看起來像沒有空白。
  let lead = 0
  while (lead < chars.length && chars[lead] === ' ') lead++
  let trail = 0
  while (trail < chars.length - lead && chars[chars.length - 1 - trail] === ' ') trail++

  chars.forEach((ch, i) => {
    if (ch.codePointAt(0) > 0x7f) hasNonAscii = true
    const edgeSpace = ch === ' ' && (i < lead || i >= chars.length - trail)
    if (edgeSpace) {
      hasEscaped = true
      push('␠', true)
    } else if (ESCAPE_RE.test(ch)) {
      hasEscaped = true
      push(codeLabel(ch), true)
    } else {
      push(ch, false)
    }
  })

  return { segments, hasEscaped, hasNonAscii }
}

/** 跳脫後的純文字（供 title／aria 使用）。 */
export function visibleText(raw) {
  return visibleName(raw)
    .segments.map((s) => s.text)
    .join('')
}
