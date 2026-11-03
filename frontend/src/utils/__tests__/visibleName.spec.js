import { describe, it, expect } from 'vitest'
import { visibleName, visibleText } from '../visibleName'

// 以碼位組字串，避免原始檔夾帶看不見的字元
const c = (hex) => String.fromCodePoint(parseInt(hex, 16))
const text = (raw) => visibleText(raw)

describe('visibleName 顯示跳脫', () => {
  it('純 ASCII 不變', () => {
    const r = visibleName('deploy-01')
    expect(r.segments).toEqual([{ text: 'deploy-01', escaped: false }])
    expect(r.hasEscaped).toBe(false)
    expect(r.hasNonAscii).toBe(false)
  })

  it('U+200B 零寬空白被跳脫', () => {
    const raw = 'ro' + c('200B') + 'ot'
    const r = visibleName(raw)
    expect(text(raw)).toBe('ro<U+200B>ot')
    expect(r.hasEscaped).toBe(true)
    expect(r.segments.filter((s) => s.escaped)).toEqual([{ text: '<U+200B>', escaped: true }])
  })

  it('U+202E 雙向覆寫被跳脫', () => {
    expect(text('abc' + c('202E') + 'fdp')).toBe('abc<U+202E>fdp')
  })

  it('U+00A0 不斷行空白與 U+3000 全形空白被跳脫', () => {
    expect(text('a' + c('00A0') + 'b')).toBe('a<U+00A0>b')
    expect(text('a' + c('3000') + 'b')).toBe('a<U+3000>b')
  })

  it('U+FEFF 位元組順序記號被跳脫', () => {
    expect(text(c('FEFF') + 'root')).toBe('<U+FEFF>root')
  })

  it('U+2028 行分隔被跳脫', () => {
    expect(text('a' + c('2028') + 'b')).toBe('a<U+2028>b')
  })

  it('首尾空白以符號顯示，中間空白不動', () => {
    expect(text(' a b ')).toBe(c('2420') + 'a b' + c('2420'))
    expect(visibleName(' a b ').hasEscaped).toBe(true)
    expect(visibleName('a b').hasEscaped).toBe(false)
  })

  it('控制字元防禦性跳脫', () => {
    expect(text('a' + c('0007') + 'b')).toBe('a<U+0007>b')
  })

  it('組合字元與西里爾字母只標非 ASCII，不跳脫', () => {
    const r1 = visibleName('e' + c('0301'))
    expect(r1.hasEscaped).toBe(false)
    expect(r1.hasNonAscii).toBe(true)
    const raw = 'r' + c('043E') + 'ot'
    const r2 = visibleName(raw)
    expect(r2.hasEscaped).toBe(false)
    expect(r2.hasNonAscii).toBe(true)
    expect(text(raw)).toBe(raw)
  })

  it('非字串輸入不丟錯', () => {
    expect(visibleName(null).segments).toEqual([])
    expect(visibleName(undefined).hasEscaped).toBe(false)
  })

  it('補充平面字元以完整碼位顯示', () => {
    expect(text('a' + c('E0001') + 'b')).toBe('a<U+E0001>b')
  })
})
