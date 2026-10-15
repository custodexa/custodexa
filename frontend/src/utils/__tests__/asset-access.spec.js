import { describe, it, expect } from 'vitest'
import {
  assetEntryState,
  needsAccessRequest,
  isAccessPending,
  isViewOnly,
  BLOCKED_ENTRY_STATES,
} from '../asset-access'

const user = { isPrivileged: false }
const admin = { isPrivileged: true }

describe('assetEntryState 五態', () => {
  it.each([
    [{ permission: 'view', access_state: '' }, 'view_only'],
    [{ permission: 'connect', access_state: 'pending' }, 'pending'],
    [{ permission: 'connect', access_state: 'approval_required' }, 'approval'],
    [{ permission: 'connect', access_state: 'reason_required' }, 'reason'],
    [{ permission: 'connect', access_state: 'connectable' }, 'open'],
  ])('%o → %s', (asset, expected) => {
    expect(assetEntryState({ id: 1, active: true, ...asset }, user)).toBe(expected)
  })

  it('permission=view 優先於 access_state（即使伺服端帶了申請態）', () => {
    expect(assetEntryState({ permission: 'view', access_state: 'approval_required' }, user)).toBe('view_only')
    expect(assetEntryState({ permission: 'view', access_state: 'pending' }, user)).toBe('view_only')
  })

  it('pending 優先於需申請態', () => {
    expect(assetEntryState({ access_state: 'pending' }, user)).toBe('pending')
  })

  it('特權角色一律 open（不做前端分化）', () => {
    for (const asset of [
      { permission: 'view' },
      { access_state: 'pending' },
      { access_state: 'approval_required' },
      { access_state: 'reason_required' },
    ]) {
      expect(assetEntryState(asset, admin)).toBe('open')
    }
  })

  it('欄位缺席、值域外的新值回退 open', () => {
    expect(assetEntryState({}, user)).toBe('open')
    expect(assetEntryState({ access_state: 'something_new' }, user)).toBe('open')
    expect(assetEntryState(undefined, user)).toBe('open')
    expect(assetEntryState({ permission: 'connect' })).toBe('open')
  })

  it('active:false 不回非 open 態', () => {
    for (const asset of [
      { permission: 'view' },
      { access_state: 'pending' },
      { access_state: 'approval_required' },
      { access_state: 'reason_required' },
    ]) {
      expect(assetEntryState({ ...asset, active: false }, user)).toBe('open')
    }
  })

  it('不發簽發的態恰為僅檢視、審核中、需審核', () => {
    expect([...BLOCKED_ENTRY_STATES].sort()).toEqual(['approval', 'pending', 'view_only'])
    expect(BLOCKED_ENTRY_STATES).not.toContain('reason')
  })
})

describe('既有匯出行為不變（資產頁仍用）', () => {
  it('needsAccessRequest：兩種需申請態為真，其餘為假', () => {
    expect(needsAccessRequest({ access_state: 'reason_required' }, user)).toBe(true)
    expect(needsAccessRequest({ access_state: 'approval_required' }, user)).toBe(true)
    expect(needsAccessRequest({ access_state: 'pending' }, user)).toBe(false)
    expect(needsAccessRequest({ access_state: 'approval_required' }, admin)).toBe(false)
    expect(needsAccessRequest({ access_state: 'approval_required', active: false }, user)).toBe(false)
  })

  it('isAccessPending：只有 pending 為真', () => {
    expect(isAccessPending({ access_state: 'pending' }, user)).toBe(true)
    expect(isAccessPending({ access_state: 'pending' }, admin)).toBe(false)
    expect(isAccessPending({ access_state: 'reason_required' }, user)).toBe(false)
  })

  it('isViewOnly：只看 permission=view，特權與停用不分化', () => {
    expect(isViewOnly({ permission: 'view' }, user)).toBe(true)
    expect(isViewOnly({ permission: 'connect' }, user)).toBe(false)
    expect(isViewOnly({ permission: 'view' }, admin)).toBe(false)
    expect(isViewOnly({ permission: 'view', active: false }, user)).toBe(false)
  })
})
