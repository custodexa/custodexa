// 鍵盤紀錄的文字事件呈現：位元組 → 可辨識記號，與十六進位原始值。
//
// 內容原樣呈現，不遮罩、不刪除；只把控制字元與不可列印位元組換成可辨識記號。
// 呼叫端只在記憶體持有結果，不得寫入瀏覽器儲存或 console。

const CTRL_NAMES = new Map([
  [0x08, '<BS>'],
  [0x09, '<TAB>'],
  [0x0a, '<LF>'],
  [0x0d, '<CR>'],
  [0x1b, '<ESC>'],
  [0x7f, '<DEL>'],
])

// 常見按鍵序列（CSI／SS3）：非專業人士看 `<ESC>[A` 等於亂碼，所以認得的序列顯示成按鍵記號
const FINAL_KEYS = new Map([
  ['A', '<↑>'], ['B', '<↓>'], ['C', '<→>'], ['D', '<←>'], ['H', '<Home>'], ['F', '<End>'],
])
const TILDE_KEYS = new Map([
  ['1', '<Home>'], ['2', '<Insert>'], ['3', '<Del>'], ['4', '<End>'], ['5', '<PageUp>'], ['6', '<PageDown>'],
])

const hex2 = (b) => b.toString(16).toUpperCase().padStart(2, '0')

/** base64 轉位元組；非法輸入回空陣列。 */
export function base64ToBytes(b64) {
  try {
    const bin = atob(b64 || '')
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return new Uint8Array(0)
  }
}

/** 十六進位原始值：每個位元組兩位、以空白分隔。 */
export function bytesToHex(bytes) {
  return Array.from(bytes, hex2).join(' ')
}

// 嘗試從 i 取一個 UTF-8 字元；回 { len, ch } 或 null（非法序列）
function utf8At(bytes, i) {
  const b = bytes[i]
  let len = 0
  let cp = 0
  if (b >= 0xc2 && b <= 0xdf) { len = 2; cp = b & 0x1f } else if (b >= 0xe0 && b <= 0xef) { len = 3; cp = b & 0x0f } else if (b >= 0xf0 && b <= 0xf4) { len = 4; cp = b & 0x07 } else return null
  if (i + len > bytes.length) return null
  for (let k = 1; k < len; k += 1) {
    const c = bytes[i + k]
    if ((c & 0xc0) !== 0x80) return null
    cp = (cp << 6) | (c & 0x3f)
  }
  const min = [0, 0, 0x80, 0x800, 0x10000][len]
  if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return null
  return { len, ch: String.fromCodePoint(cp) }
}

// 從 ESC 起辨識一段按鍵序列；回 { len, text } 或 null
function escapeSeq(bytes, i) {
  const n = bytes[i + 1]
  if (n === 0x5b || n === 0x4f) { // ESC [ 或 ESC O
    let j = i + 2
    while (j < bytes.length && bytes[j] >= 0x30 && bytes[j] <= 0x3f) j += 1
    const fin = bytes[j]
    if (fin === undefined) return null
    const params = String.fromCharCode(...bytes.slice(i + 2, j))
    const f = String.fromCharCode(fin)
    if (params === '' && FINAL_KEYS.has(f)) return { len: j - i + 1, text: FINAL_KEYS.get(f) }
    if (f === '~' && TILDE_KEYS.has(params)) return { len: j - i + 1, text: TILDE_KEYS.get(params) }
  }
  return null
}

/**
 * bytesToTokens 把位元組轉成顯示片段。
 * @param {Uint8Array} bytes
 * @returns {{ text: string, kind: 'plain'|'ctrl'|'raw' }[]}
 *   plain＝可列印文字，ctrl＝控制字元或按鍵記號，raw＝非法 UTF-8 位元組（`\xNN`）
 */
export function bytesToTokens(bytes) {
  const out = []
  const push = (text, kind) => {
    const last = out[out.length - 1]
    if (last && last.kind === 'plain' && kind === 'plain') last.text += text
    else out.push({ text, kind })
  }
  let i = 0
  while (i < bytes.length) {
    const b = bytes[i]
    if (b === 0x1b) {
      const seq = escapeSeq(bytes, i)
      if (seq) { push(seq.text, 'ctrl'); i += seq.len; continue }
    }
    if (CTRL_NAMES.has(b)) { push(CTRL_NAMES.get(b), 'ctrl'); i += 1; continue }
    if (b < 0x20) { push(`^${String.fromCharCode(b + 0x40)}`, 'ctrl'); i += 1; continue }
    if (b < 0x7f) { push(String.fromCharCode(b), 'plain'); i += 1; continue }
    const u = b >= 0x80 ? utf8At(bytes, i) : null
    if (u) { push(u.ch, 'plain'); i += u.len; continue }
    push(`\\x${hex2(b)}`, 'raw')
    i += 1
  }
  return out
}

/** tokensToText 串成單一字串（測試與複製用）。 */
export function tokensToText(tokens) {
  return tokens.map((t) => t.text).join('')
}

export const MAX_ROW_BYTES = 512

/**
 * mergeEventRows 把事件合併成顯示列（只在呈現層，事件本身與計數不變）。
 * 規則：連續文字事件（kind=1）來源與阻斷旗標相同才併列；含 CR／LF 的事件之後收列；
 * 標記與其他種類事件獨立成列；單列累積超過 maxBytes 另起新列；
 * breakAt 內的事件索引（頁首）一律另起新列。
 * @param {object[]} events 原始事件（kind、source、blocked、data_b64）
 * @param {{ breakAt?: Set<number>, maxBytes?: number }} [opts]
 * @returns {{ first: object, index: number, count: number, bytes: Uint8Array, mergeable: boolean }[]}
 *   index＝首筆事件在 events 的索引；bytes＝該列全部位元組（標記事件為空）
 */
export function mergeEventRows(events, opts = {}) {
  const breakAt = opts.breakAt || new Set()
  const maxBytes = opts.maxBytes || MAX_ROW_BYTES
  const out = []
  let cur = null
  const flush = () => { if (cur) { out.push(cur); cur = null } }
  events.forEach((ev, i) => {
    if (ev.kind !== 0x01) {
      flush()
      out.push({ first: ev, index: i, count: 1, bytes: ev.kind === 0x10 ? new Uint8Array(0) : base64ToBytes(ev.data_b64), mergeable: false })
      return
    }
    const bytes = base64ToBytes(ev.data_b64)
    const source = ev.source === 'platform' ? 'platform' : 'user'
    const blocked = !!ev.blocked
    if (cur && (breakAt.has(i) || cur.source !== source || cur.blocked !== blocked || cur.parts.reduce((n, p) => n + p.length, 0) + bytes.length > maxBytes)) flush()
    if (!cur) cur = { first: ev, index: i, count: 0, parts: [], source, blocked, mergeable: true }
    cur.parts.push(bytes)
    cur.count += 1
    if (bytes.includes(0x0d) || bytes.includes(0x0a)) flush()
  })
  flush()
  return out.map((r) => {
    if (!r.parts) return r
    const total = r.parts.reduce((n, p) => n + p.length, 0)
    const all = new Uint8Array(total)
    let o = 0
    r.parts.forEach((p) => { all.set(p, o); o += p.length })
    return { first: r.first, index: r.index, count: r.count, bytes: all, mergeable: true }
  })
}
