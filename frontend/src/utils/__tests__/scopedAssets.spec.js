import { describe, it, expect } from 'vitest'
import { ACTION_KEYS, actionAllowed, actionDenial } from '../scopedAssets'

describe('scopedAssets 列級旗標', () => {
  it('旗標鍵含主機帳號盤點', () => {
    expect(ACTION_KEYS).toContain('discover_accounts')
  })

  it('帶旗標的列只看旗標，缺鍵視為不可', () => {
    const row = { actions: { discover_accounts: { allowed: true } } }
    expect(actionAllowed(row, 'discover_accounts', false)).toBe(true)
    expect(actionAllowed({ actions: {} }, 'discover_accounts', true)).toBe(false)
  })

  it('不帶旗標的列回退全域能力', () => {
    expect(actionAllowed({}, 'discover_accounts', true)).toBe(true)
    expect(actionAllowed({}, 'discover_accounts', false)).toBe(false)
  })

  it('不可做時回原因碼', () => {
    const row = { actions: { discover_accounts: { allowed: false, reason: 'out_of_scope' } } }
    expect(actionDenial(row, 'discover_accounts')).toEqual({ reason: 'out_of_scope', count: 0 })
  })
})
