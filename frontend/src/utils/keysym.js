// X11 keysym 名稱表（鍵盤紀錄檢視頁用）。
//
// 只做顯示：把數值轉成可讀名稱、X11 名稱與分類；查無名稱者 name 與 x11 皆為 null，呼叫端只顯示 hex。
// 第一層名稱用慣用英文鍵名（F5、Enter、PageUp），三語畫面共用不翻譯；
// 只有修飾鍵的「左／右」經 keysymLabel 依語系組字（左 Shift、Left Shift）。
// 第二層（顯示按鍵代碼）用 X11 標準名稱（Shift_L、Return、U4E2D）。

/** 十六進位顯示：小寫、至少四位；超過 0xFFFF 者補到八位（0x01004e2d）。 */
const hex = (n) => {
  const s = Number(n).toString(16)
  return `0x${s.padStart(n > 0xffff ? 8 : 4, '0')}`
}

const NAMED = new Map()
// side／mod 只用於修飾鍵：side 為 left|right，mod 為顯示用鍵名
const add = (code, name, x11, group, extra = {}) => NAMED.set(code, { name, x11, group, ...extra })
const mod = (code, key, side, x11) => add(code, key, x11, 'modifier', { side, mod: key })

// 編輯與導覽
add(0xff08, 'BackSpace', 'BackSpace', 'editing')
add(0xff09, 'Tab', 'Tab', 'editing')
add(0xfe20, 'Shift+Tab', 'ISO_Left_Tab', 'editing')
add(0xff0a, 'Linefeed', 'Linefeed', 'editing')
add(0xff0b, 'Clear', 'Clear', 'editing')
add(0xff0d, 'Enter', 'Return', 'editing')
add(0xff13, 'Pause', 'Pause', 'editing')
add(0xff14, 'Scroll Lock', 'Scroll_Lock', 'editing')
add(0xff15, 'SysRq', 'Sys_Req', 'editing')
add(0xff1b, 'Esc', 'Escape', 'editing')
add(0xff61, 'Print', 'Print', 'editing')
add(0xff63, 'Insert', 'Insert', 'editing')
add(0xff67, 'Menu', 'Menu', 'editing')
add(0xff6b, 'Break', 'Break', 'editing')
add(0xffff, 'Delete', 'Delete', 'editing')
add(0x0020, 'Space', 'space', 'editing')

// 方向與頁面
add(0xff50, 'Home', 'Home', 'navigation')
add(0xff51, 'Left', 'Left', 'navigation')
add(0xff52, 'Up', 'Up', 'navigation')
add(0xff53, 'Right', 'Right', 'navigation')
add(0xff54, 'Down', 'Down', 'navigation')
add(0xff55, 'PageUp', 'Page_Up', 'navigation')
add(0xff56, 'PageDown', 'Page_Down', 'navigation')
add(0xff57, 'End', 'End', 'navigation')
add(0xff58, 'Begin', 'Begin', 'navigation')

// 修飾鍵（左右各一）
mod(0xffe1, 'Shift', 'left', 'Shift_L')
mod(0xffe2, 'Shift', 'right', 'Shift_R')
mod(0xffe3, 'Ctrl', 'left', 'Control_L')
mod(0xffe4, 'Ctrl', 'right', 'Control_R')
mod(0xffe7, 'Meta', 'left', 'Meta_L')
mod(0xffe8, 'Meta', 'right', 'Meta_R')
mod(0xffe9, 'Alt', 'left', 'Alt_L')
mod(0xffea, 'Alt', 'right', 'Alt_R')
mod(0xffeb, 'Super', 'left', 'Super_L')
mod(0xffec, 'Super', 'right', 'Super_R')
mod(0xffed, 'Hyper', 'left', 'Hyper_L')
mod(0xffee, 'Hyper', 'right', 'Hyper_R')
add(0xffe5, 'Caps Lock', 'Caps_Lock', 'modifier')
add(0xffe6, 'Shift Lock', 'Shift_Lock', 'modifier')
add(0xff7e, 'Mode switch', 'Mode_switch', 'modifier')
add(0xfe03, 'AltGr', 'ISO_Level3_Shift', 'modifier')

// 功能鍵 F1–F24
for (let i = 1; i <= 24; i += 1) add(0xffbd + i, `F${i}`, `F${i}`, 'function')

// 數字鍵盤
add(0xff7f, 'Num Lock', 'Num_Lock', 'keypad')
add(0xff80, 'KP_Space', 'KP_Space', 'keypad')
add(0xff89, 'KP_Tab', 'KP_Tab', 'keypad')
add(0xff8d, 'KP_Enter', 'KP_Enter', 'keypad')
add(0xffaa, 'KP_Multiply', 'KP_Multiply', 'keypad')
add(0xffab, 'KP_Add', 'KP_Add', 'keypad')
add(0xffac, 'KP_Separator', 'KP_Separator', 'keypad')
add(0xffad, 'KP_Subtract', 'KP_Subtract', 'keypad')
add(0xffae, 'KP_Decimal', 'KP_Decimal', 'keypad')
add(0xffaf, 'KP_Divide', 'KP_Divide', 'keypad')
add(0xffbd, 'KP_Equal', 'KP_Equal', 'keypad')
for (let i = 0; i <= 9; i += 1) add(0xffb0 + i, `KP_${i}`, `KP_${i}`, 'keypad')

// ASCII 標點的 X11 名稱（字母與數字的 X11 名稱即字元本身）
const ASCII_X11 = {
  0x21: 'exclam', 0x22: 'quotedbl', 0x23: 'numbersign', 0x24: 'dollar', 0x25: 'percent', 0x26: 'ampersand',
  0x27: 'apostrophe', 0x28: 'parenleft', 0x29: 'parenright', 0x2a: 'asterisk', 0x2b: 'plus', 0x2c: 'comma',
  0x2d: 'minus', 0x2e: 'period', 0x2f: 'slash', 0x3a: 'colon', 0x3b: 'semicolon', 0x3c: 'less', 0x3d: 'equal',
  0x3e: 'greater', 0x3f: 'question', 0x40: 'at', 0x5b: 'bracketleft', 0x5c: 'backslash', 0x5d: 'bracketright',
  0x5e: 'asciicircum', 0x5f: 'underscore', 0x60: 'grave', 0x7b: 'braceleft', 0x7c: 'bar', 0x7d: 'braceright',
  0x7e: 'asciitilde',
}

const UNICODE_BASE = 0x01000000

function printable(cp) {
  // 控制字元與未配對代理碼位不顯示成字元
  if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0) || (cp >= 0xd800 && cp <= 0xdfff)) return null
  try {
    return String.fromCodePoint(cp)
  } catch {
    return null
  }
}

/**
 * keysymName 把 keysym 數值轉為顯示資訊。
 * @param {number} code keysym 數值（無號整數）
 * @returns {{ code: number, hex: string, name: string|null, x11: string|null, group: string,
 *   char: string|null, side: 'left'|'right'|null, mod: string|null, cp: string|null }}
 *   name 為 null 代表查無名稱，呼叫端顯示「未知按鍵」與 hex。group 為
 *   function／modifier／navigation／editing／keypad／unicode／latin／unknown。
 *   side／mod 只在左右成對的修飾鍵有值；cp 只在 Unicode keysym 有值（U+4E2D）。
 */
export function keysymName(code) {
  const n = Number(code)
  const base = { code: n, hex: '', name: null, x11: null, group: 'unknown', char: null, side: null, mod: null, cp: null }
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return { ...base, hex: String(code) }
  base.hex = hex(n)
  const named = NAMED.get(n)
  if (named) {
    return {
      ...base,
      name: named.name,
      x11: named.x11,
      group: named.group,
      char: n === 0x20 ? ' ' : null,
      side: named.side || null,
      mod: named.mod || null,
    }
  }
  // Unicode keysym：0x01000000 加碼位
  if (n >= UNICODE_BASE + 0x100 && n <= UNICODE_BASE + 0x10ffff) {
    const cpNum = n - UNICODE_BASE
    const cpHex = cpNum.toString(16).toUpperCase().padStart(4, '0')
    return { ...base, name: `U+${cpHex}`, x11: `U${cpHex}`, group: 'unicode', char: printable(cpNum), cp: `U+${cpHex}` }
  }
  // Latin-1 直接對應段
  if ((n >= 0x21 && n <= 0x7e) || (n >= 0xa0 && n <= 0xff)) {
    const ch = printable(n)
    return { ...base, name: ch, x11: ASCII_X11[n] || ch, group: 'latin', char: ch }
  }
  return base
}

/**
 * keysymLabel 第一層顯示名稱（依語系組字）。查無名稱回 null，呼叫端顯示「未知按鍵」。
 * @param {ReturnType<typeof keysymName>} info
 * @param {(key: string, params?: object) => string} t i18n 翻譯函式
 */
export function keysymLabel(info, t) {
  if (!info || info.name === null) return null
  if (info.side) return t(`keystrokeView.viewer.key.${info.side}`, { key: info.mod })
  if (info.group === 'unicode') {
    return info.char ? t('keystrokeView.viewer.key.unicode', { char: info.char, code: info.cp }) : info.cp
  }
  return info.name
}

export const KIND_KEYSYM = 0x02
export const KIND_KEYSYM_RAW = 0x03

// 讀 uvarint；回 { value, len } 或 null（截斷或超過安全整數）
function readUvarint(bytes) {
  let value = 0
  let mul = 1
  for (let i = 0; i < bytes.length && i < 8; i += 1) {
    const b = bytes[i]
    value += (b & 0x7f) * mul
    if ((b & 0x80) === 0) return { value, len: i + 1 }
    mul *= 128
  }
  return null
}

/**
 * decodeKeyEvent 解出圖形按鍵事件的 payload（格式見後端 keystroke/format）。
 * - kind 0x02：uint32 keysym（big-endian）＋1 byte 按放（1 按下、0 放開）
 * - kind 0x03：uvarint 長度＋無法解析的原始參數位元組
 * payload 不合格式時不丟棄，整段當原始位元組交回（raw）。
 * @param {number} kind
 * @param {Uint8Array} bytes payload
 * @returns {{ keysym: number|null, pressed: boolean|null, raw: Uint8Array|null }}
 */
export function decodeKeyEvent(kind, bytes) {
  const b = bytes || new Uint8Array(0)
  if (kind === KIND_KEYSYM && b.length === 5 && b[4] <= 1) {
    const keysym = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
    return { keysym, pressed: b[4] === 1, raw: null }
  }
  if (kind === KIND_KEYSYM_RAW) {
    const v = readUvarint(b)
    if (v && v.len + v.value === b.length) return { keysym: null, pressed: null, raw: b.slice(v.len) }
  }
  return { keysym: null, pressed: null, raw: b }
}
