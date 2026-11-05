import { describe, it, expect } from 'vitest'
import { decodeKeyEvent, keysymLabel, keysymName } from '../keysym'

// 測試用翻譯函式：回傳鍵名與參數，確認 keysymLabel 走對的 i18n 鍵
const fakeT = (key, p = {}) => `${key}|${Object.entries(p).map(([k, v]) => `${k}=${v}`).join(',')}`

describe('keysymName', () => {
  it('功能鍵 F1 到 F24', () => {
    expect(keysymName(0xffbe)).toMatchObject({ name: 'F1', x11: 'F1', group: 'function' })
    expect(keysymName(0xffc2)).toMatchObject({ name: 'F5', x11: 'F5', hex: '0xffc2' })
    expect(keysymName(0xffd5)).toMatchObject({ name: 'F24' })
  })

  it('修飾鍵分左右，X11 名稱為 Shift_L 一類', () => {
    expect(keysymName(0xffe1)).toMatchObject({ mod: 'Shift', side: 'left', x11: 'Shift_L', group: 'modifier', hex: '0xffe1' })
    expect(keysymName(0xffe2)).toMatchObject({ mod: 'Shift', side: 'right', x11: 'Shift_R' })
    expect(keysymName(0xffe3)).toMatchObject({ mod: 'Ctrl', side: 'left', x11: 'Control_L' })
    expect(keysymName(0xffe4)).toMatchObject({ mod: 'Ctrl', side: 'right' })
    expect(keysymName(0xffeb)).toMatchObject({ mod: 'Super', side: 'left', x11: 'Super_L' })
    expect(keysymName(0xffe5)).toMatchObject({ name: 'Caps Lock', side: null, group: 'modifier' })
  })

  it('方向鍵與編輯鍵', () => {
    expect(keysymName(0xff52)).toMatchObject({ name: 'Up', group: 'navigation' })
    expect(keysymName(0xff55)).toMatchObject({ name: 'PageUp', x11: 'Page_Up' })
    expect(keysymName(0xff0d)).toMatchObject({ name: 'Enter', x11: 'Return', group: 'editing' })
    expect(keysymName(0xff1b)).toMatchObject({ name: 'Esc', x11: 'Escape' })
    expect(keysymName(0xffff).name).toBe('Delete')
    expect(keysymName(0xff08).name).toBe('BackSpace')
  })

  it('數字鍵盤', () => {
    expect(keysymName(0xffb7)).toMatchObject({ name: 'KP_7', group: 'keypad' })
    expect(keysymName(0xff8d).name).toBe('KP_Enter')
    expect(keysymName(0xffab).name).toBe('KP_Add')
  })

  it('Unicode keysym（0x01000000 加碼位）：八位十六進位、X11 名稱 U4E2D', () => {
    const r = keysymName(0x01000000 + 0x4e2d)
    expect(r).toMatchObject({ name: 'U+4E2D', x11: 'U4E2D', cp: 'U+4E2D', group: 'unicode', char: '中', hex: '0x01004e2d' })
    expect(keysymName(0x01000000 + 0x1f600).char).toBe('\u{1F600}')
  })

  it('Latin-1 直接對應，標點用 X11 名稱', () => {
    expect(keysymName(0x61)).toMatchObject({ name: 'a', x11: 'a', group: 'latin' })
    expect(keysymName(0x40)).toMatchObject({ name: '@', x11: 'at' })
    expect(keysymName(0xe9).char).toBe('é')
  })

  it('查無名稱回十六進位值', () => {
    const r = keysymName(0x1008ff13)
    expect(r.name).toBeNull()
    expect(r.x11).toBeNull()
    expect(r.hex).toBe('0x1008ff13')
    expect(r.group).toBe('unknown')
    expect(keysymName(0xfd99).hex).toBe('0xfd99')
    expect(keysymName(-1).name).toBeNull()
    expect(keysymName('x').name).toBeNull()
  })
})

describe('keysymLabel', () => {
  it('修飾鍵依語系組字、Unicode 字元附碼位、其他直接用名稱、查無名稱回 null', () => {
    expect(keysymLabel(keysymName(0xffe1), fakeT)).toBe('keystrokeView.viewer.key.left|key=Shift')
    expect(keysymLabel(keysymName(0xffe4), fakeT)).toBe('keystrokeView.viewer.key.right|key=Ctrl')
    expect(keysymLabel(keysymName(0x01004e2d), fakeT)).toBe('keystrokeView.viewer.key.unicode|char=中,code=U+4E2D')
    expect(keysymLabel(keysymName(0xffc2), fakeT)).toBe('F5')
    expect(keysymLabel(keysymName(0x63), fakeT)).toBe('c')
    expect(keysymLabel(keysymName(0x1008ff13), fakeT)).toBeNull()
  })
})

describe('decodeKeyEvent', () => {
  it('kind 0x02：big-endian keysym 與按放', () => {
    expect(decodeKeyEvent(2, new Uint8Array([0, 0, 0xff, 0xc2, 1]))).toEqual({ keysym: 0xffc2, pressed: true, raw: null })
    expect(decodeKeyEvent(2, new Uint8Array([0x10, 0x08, 0xff, 0x13, 0]))).toEqual({ keysym: 0x1008ff13, pressed: false, raw: null })
  })

  it('kind 0x02 格式不合：整段當原始位元組', () => {
    expect(decodeKeyEvent(2, new Uint8Array([0, 0, 0xff, 0xc2, 7])).raw).toEqual(new Uint8Array([0, 0, 0xff, 0xc2, 7]))
    expect(decodeKeyEvent(2, new Uint8Array([1, 2])).keysym).toBeNull()
  })

  it('kind 0x03：去掉 uvarint 長度前綴；長度不符時整段保留', () => {
    expect(decodeKeyEvent(3, new Uint8Array([3, 0x61, 0x2c, 0x62]))).toEqual({ keysym: null, pressed: null, raw: new Uint8Array([0x61, 0x2c, 0x62]) })
    expect(decodeKeyEvent(3, new Uint8Array([9, 0x61])).raw).toEqual(new Uint8Array([9, 0x61]))
  })
})
