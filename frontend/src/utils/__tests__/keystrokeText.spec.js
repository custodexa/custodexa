import { describe, it, expect } from 'vitest'
import { base64ToBytes, bytesToHex, bytesToTokens, mergeEventRows, tokensToText } from '../keystrokeText'

const text = (arr) => tokensToText(bytesToTokens(Uint8Array.from(arr)))

describe('keystrokeText', () => {
  it('控制字元以記號顯示', () => {
    expect(text([0x6c, 0x73, 0x0d])).toBe('ls<CR>')
    expect(text([0x03])).toBe('^C')
    expect(text([0x04])).toBe('^D')
    expect(text([0x1b])).toBe('<ESC>')
    expect(text([0x7f, 0x08, 0x09, 0x0a])).toBe('<DEL><BS><TAB><LF>')
    expect(text([0x00])).toBe('^@')
  })

  it('認得的按鍵序列顯示成按鍵記號，認不得的逐字顯示', () => {
    expect(text([0x1b, 0x5b, 0x41])).toBe('<↑>')
    expect(text([0x1b, 0x4f, 0x44])).toBe('<←>')
    expect(text([0x1b, 0x5b, 0x33, 0x7e])).toBe('<Del>')
    expect(text([0x1b, 0x5b, 0x39, 0x39, 0x7a])).toBe('<ESC>[99z')
    expect(text([0x1b, 0x5b])).toBe('<ESC>[')
  })

  it('UTF-8 多位元組與非法位元組', () => {
    expect(text([0xe4, 0xb8, 0xad])).toBe('中')
    expect(text([0xff, 0x41])).toBe('\\xFFA')
    expect(text([0xe4, 0xb8])).toBe('\\xE4\\xB8')
    expect(text([0xc0, 0x80])).toBe('\\xC0\\x80')
  })

  it('片段分類', () => {
    const t = bytesToTokens(Uint8Array.from([0x61, 0x62, 0x0d, 0xff]))
    expect(t.map((x) => x.kind)).toEqual(['plain', 'ctrl', 'raw'])
    expect(t[0].text).toBe('ab')
  })

  it('十六進位與 base64', () => {
    expect(bytesToHex(Uint8Array.from([0x0d, 0xe4, 0x01]))).toBe('0D E4 01')
    expect(Array.from(base64ToBytes('bHM='))).toEqual([0x6c, 0x73])
    expect(base64ToBytes('%%%').length).toBe(0)
    expect(base64ToBytes('').length).toBe(0)
  })
})

describe('mergeEventRows 呈現層合併', () => {
  const b = (s) => btoa(s)
  const e = (seq, text, over = {}) => ({ seq, kind: 1, source: 'user', blocked: false, data_b64: b(text), ...over })
  const typed = (str, start = 0, over = {}) => Array.from(str, (c, i) => e(start + i, c, over))

  it('逐鍵輸入一行加 CR 併成一列，# 為首筆 seq', () => {
    const rows = mergeEventRows([...typed('sudo ls\r', 5), ...typed('exit\r', 14)])
    expect(rows).toHaveLength(2)
    expect(rows[0].first.seq).toBe(5)
    expect(rows[0].count).toBe(8)
    expect(tokensToText(bytesToTokens(rows[0].bytes))).toBe('sudo ls<CR>')
    expect(rows[1].first.seq).toBe(14)
  })
  it('來源改變斷列', () => {
    const rows = mergeEventRows([e(0, 'a'), e(1, 'b', { source: 'platform' }), e(2, 'c')])
    expect(rows).toHaveLength(3)
  })
  it('阻斷旗標改變斷列', () => {
    const rows = mergeEventRows([e(0, 'a'), e(1, 'b', { blocked: true }), e(2, 'c', { blocked: true })])
    expect(rows.map((r) => r.count)).toEqual([1, 2])
  })
  it('標記事件獨立成列且不併入前後文字', () => {
    const rows = mergeEventRows([e(0, 'a'), { seq: 1, kind: 0x10, marker: 'x' }, e(2, 'b')])
    expect(rows).toHaveLength(3)
    expect(rows[1].first.kind).toBe(0x10)
    expect(rows[1].bytes.length).toBe(0)
  })
  it('超過 512 位元組斷列', () => {
    const rows = mergeEventRows(typed('a'.repeat(1100)))
    expect(rows.map((r) => r.bytes.length)).toEqual([512, 512, 76])
  })
  it('頁首索引另起新列', () => {
    const rows = mergeEventRows(typed('abcd'), { breakAt: new Set([2]) })
    expect(rows.map((r) => r.count)).toEqual([2, 2])
  })
  it('十六進位用同一組合併列，涵蓋整列位元組', () => {
    const rows = mergeEventRows(typed('A\r'))
    expect(bytesToHex(rows[0].bytes)).toBe('41 0D')
  })
})
