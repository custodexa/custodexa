import { describe, it, expect } from 'vitest'
import writeKeys from './fixtures/write-keys.json'
import { entryStateOf, protectedKeysOf, distinctDetailCount, sharedKeyDetailOf, applyEntryState } from '../entryState'

// 入口的各態集合照後端描述表；write_keys 取自後端實際輸出（fixtures/write-keys.json）
const st = (name, ...keys) => ({ name, keys })
const hidden = st('hidden')
const CRED_KEYS = [
  'account:rotate', 'credential:bind', 'credential:convert-scope', 'credential:create', 'credential:delete',
  'credential:detach', 'credential:rotate', 'credential:set-secret', 'credential:update',
]
const entries = [
  {
    id: 'assets',
    states: [hidden, st('read', 'asset:view'),
      st('manage', 'asset:view', 'asset:create', 'asset:update', 'asset:delete', 'asset:test', 'assetgroup:manage')],
    details: [
      { id: 'asset.view', key: 'asset:view' }, { id: 'asset.create', key: 'asset:create' }, { id: 'asset.update', key: 'asset:update' },
      { id: 'asset.delete', key: 'asset:delete' }, { id: 'asset.test', key: 'asset:test' },
      { id: 'asset_account.view', key: 'asset:view' }, { id: 'asset_account.update', key: 'asset:update' },
      { id: 'node.manage', key: 'assetgroup:manage' },
    ],
    write_keys: writeKeys.assets,
  },
  {
    id: 'credentials',
    states: [hidden, st('read', 'credential:view', 'asset:view'),
      st('manage', 'credential:manage', 'credential:view', ...CRED_KEYS.filter((k) => k !== 'credential:view'), 'asset:view')],
    details: [],
    write_keys: writeKeys.credentials,
  },
  { id: 'authorizations', states: [hidden, st('manage', 'authorization:manage')], details: [], write_keys: ['authorization:manage'] },
  {
    id: 'approver_scopes',
    states: [hidden, st('manage', 'approverscope:manage', 'approverscope:manage_applicant')],
    details: [],
    write_keys: writeKeys.approver_scopes,
  },
  { id: 'users', states: [hidden, st('manage', 'user:manage')], details: [], write_keys: ['user:manage'] },
  {
    id: 'user_groups',
    states: [hidden, st('manage', 'usergroup:manage', 'user:manage')],
    details: [],
    write_keys: writeKeys.user_groups,
  },
]
const by = (id) => entries.find((e) => e.id === id)
const assetAdmin = new Set([
  'asset:view', 'asset:create', 'asset:update', 'asset:delete', 'asset:test', 'assetgroup:manage', 'credential:view', ...CRED_KEYS,
])
const stateOf = (id, keys) => entryStateOf(by(id), new Set(keys))

describe('entryStateOf（與後端摘要判定一致）', () => {
  it('資產檢視加編輯內容：資產為部分管理', () => {
    expect(stateOf('assets', ['asset:view', 'asset:update'])).toBe('partial')
  })
  it('資產管理員範本：資產為管理、憑證庫為部分管理', () => {
    expect(entryStateOf(by('assets'), assetAdmin)).toBe('manage')
    expect(entryStateOf(by('credentials'), assetAdmin)).toBe('partial')
  })
  it('只持 user:manage：帳號為管理、使用者群組為隱藏', () => {
    expect(stateOf('users', ['user:manage'])).toBe('manage')
    expect(stateOf('user_groups', ['user:manage'])).toBe('hidden')
  })
  it('審核範圍：只持其中一個管理鍵為部分管理，兩鍵皆持為管理', () => {
    expect(stateOf('approver_scopes', ['approverscope:manage'])).toBe('partial')
    expect(stateOf('approver_scopes', ['approverscope:manage_applicant'])).toBe('partial')
    expect(stateOf('approver_scopes', ['approverscope:manage', 'approverscope:manage_applicant'])).toBe('manage')
  })
  it('空集合為隱藏；單一檢視鍵仍是唯讀', () => {
    expect(stateOf('assets', [])).toBe('hidden')
    expect(stateOf('assets', ['asset:view'])).toBe('read')
  })
})

describe('protectedKeysOf', () => {
  it('部分管理回各態鍵聯集與已持有者的交集；完整態回該態集合', () => {
    const perms = new Set(['asset:view', 'asset:update', 'user:manage'])
    expect(protectedKeysOf(by('assets'), perms).sort()).toEqual(['asset:update', 'asset:view'])
    expect(protectedKeysOf(by('users'), perms)).toEqual(['user:manage'])
    expect(protectedKeysOf(by('authorizations'), perms)).toEqual([])
  })
})

describe('distinctDetailCount 與共用鍵', () => {
  it('資產細項 8 個、不重複 6 個；帳號細項指向先出現的同鍵細項', () => {
    const a = by('assets')
    expect(distinctDetailCount(a, new Set())).toEqual({ n: 0, m: 6 })
    expect(distinctDetailCount(a, new Set(['asset:view', 'asset:update']))).toEqual({ n: 2, m: 6 })
    const acct = a.details.find((d) => d.id === 'asset_account.view')
    expect(sharedKeyDetailOf(a, acct).id).toBe('asset.view')
    expect(sharedKeyDetailOf(a, a.details[0])).toBeNull()
  })
})

describe('applyEntryState 與部分管理入口', () => {
  const partialAssets = new Set(['asset:view', 'asset:update'])
  const assetsLeft = (p) => ['asset:view', 'asset:update'].every((k) => p.has(k)) && entryStateOf(by('assets'), p) === 'partial'

  it('資產為部分管理時，對憑證庫依序切為 hidden、read、manage：不拋錯，資產仍為部分管理', () => {
    let p = partialAssets
    for (const name of ['hidden', 'read', 'manage']) {
      p = applyEntryState(entries, p, by('credentials'), name, [])
      expect(assetsLeft(p)).toBe(true)
    }
  })
  it('憑證庫為部分管理時把資產切為隱藏：資產檢視與憑證鍵保留，資產變為唯讀', () => {
    const p = applyEntryState(entries, assetAdmin, by('assets'), 'hidden', [])
    expect(p.has('asset:view')).toBe(true)
    CRED_KEYS.forEach((k) => expect(p.has(k)).toBe(true))
    expect(entryStateOf(by('assets'), p)).toBe('read')
    expect(entryStateOf(by('credentials'), p)).toBe('partial')
  })
  it('審核範圍為部分管理時切換授權規則：不拋錯，審核範圍的鍵保留', () => {
    const p0 = new Set(['approverscope:manage'])
    for (const name of ['manage', 'hidden']) {
      const p = applyEntryState(entries, p0, by('authorizations'), name, [])
      expect(p.has('approverscope:manage')).toBe(true)
      expect(entryStateOf(by('approver_scopes'), p)).toBe('partial')
    }
  })
  it('對部分管理的資產本身點管理得完整管理態，點隱藏移除自有鍵', () => {
    const full = applyEntryState(entries, partialAssets, by('assets'), 'manage', [])
    expect(entryStateOf(by('assets'), full)).toBe('manage')
    const none = applyEntryState(entries, partialAssets, by('assets'), 'hidden', [])
    expect(none.has('asset:update')).toBe(false)
    expect(entryStateOf(by('assets'), none)).toBe('hidden')
  })
})
