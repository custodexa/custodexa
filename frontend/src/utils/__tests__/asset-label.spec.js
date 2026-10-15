import { describe, it, expect } from 'vitest'
import { formatAssetLabel, ELLIPSIS } from '../asset-label'

describe('formatAssetLabel 側欄名稱截斷', () => {
  it('網域式名稱保留完整主機名、網域自尾端省略，只差尾碼的兩台仍可區分', () => {
    const a = formatAssetLabel('mysql-101-r-01.acme.internal.example', 20)
    const b = formatAssetLabel('mysql-101-r-02.acme.internal.example', 20)
    expect(a).toBe('mysql-101-r-01.acme…')
    expect(b).toBe('mysql-101-r-02.acme…')
    expect(a).not.toBe(b)
    expect(a).toHaveLength(20)
  })

  it('無網域長名稱採中段省略、保留尾段', () => {
    const out = formatAssetLabel('acme-db-prod-audit-primary-01', 20)
    expect(out).toContain(ELLIPSIS)
    expect(out.endsWith('primary-01')).toBe(true)
    expect(out.startsWith('acme-db-p')).toBe(true)
    expect(out).toHaveLength(20)
  })

  it('同前綴的無網域名稱截斷後仍可區分', () => {
    const a = formatAssetLabel('acme-db-prod-ledger-primary-01', 18)
    const b = formatAssetLabel('acme-db-prod-ledger-replica-02', 18)
    expect(a).not.toBe(b)
  })

  it('主機名本身過長：捨去網域，主機名中段省略並以主機名尾段結尾', () => {
    const name = 'prod-payment-gateway-core-api-node-01.acme.internal.example'
    const out = formatAssetLabel(name, 20)
    expect(out).toContain(ELLIPSIS)
    expect(out).not.toContain('acme')
    expect(out).not.toContain('.')
    expect(out.endsWith('node-01')).toBe(true)
    expect(out).toHaveLength(20)
  })

  it('主機名剛好放得下但網域擠不進：留完整主機名加省略號', () => {
    // 主機名 14 字；可用 16 字放不下「主機名.＋1 字＋…」（需 17）
    expect(formatAssetLabel('mysql-101-r-01.acme.internal.example', 16)).toBe('mysql-101-r-01…')
  })

  it('短名稱原樣、不含省略號', () => {
    expect(formatAssetLabel('web-01', 20)).toBe('web-01')
    expect(formatAssetLabel('exactly-twenty-chars', 20)).toBe('exactly-twenty-chars')
    expect(formatAssetLabel('web-01', 20)).not.toContain(ELLIPSIS)
  })

  it('可用字數小於 3 不丟例外，退回尾端省略', () => {
    expect(() => formatAssetLabel('abcdef', 2)).not.toThrow()
    expect(formatAssetLabel('abcdef', 2)).toBe('a…')
    expect(formatAssetLabel('abcdef', 1)).toBe(ELLIPSIS)
    expect(formatAssetLabel('abcdef', 0)).toBe('')
    expect(formatAssetLabel('abcdef', -5)).toBe('')
  })

  it('寬度未知或名稱缺值時安全回退', () => {
    expect(formatAssetLabel('abcdef', undefined)).toBe('abcdef')
    expect(formatAssetLabel('abcdef', Number.NaN)).toBe('abcdef')
    expect(formatAssetLabel(null, 10)).toBe('')
    expect(formatAssetLabel(undefined, 10)).toBe('')
  })

  it('開頭為點的名稱不視為主機名.網域', () => {
    const out = formatAssetLabel('.hidden-very-long-name-01', 12)
    expect(out.endsWith('e-01')).toBe(true)
    expect(out).toHaveLength(12)
  })
})
