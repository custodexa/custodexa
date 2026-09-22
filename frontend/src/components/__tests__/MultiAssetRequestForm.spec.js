import i18n from '@/i18n'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Form from '../access-request/MultiAssetRequestForm.vue'
const api = vi.hoisted(() => ({ assets: vi.fn(), accounts: vi.fn(), agents: vi.fn(), create: vi.fn() }))
vi.mock('@/api/assets', () => ({ getAssetList: api.assets }))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: api.accounts }))
vi.mock('@/api/agents', () => ({ getMyAgents: api.agents }))
vi.mock('@/api/accessRequests', () => ({ createAccessRequest: api.create }))
enableAutoUnmount(afterEach)
beforeEach(() => { vi.clearAllMocks(); api.assets.mockResolvedValue({ data: [{ id: 1, name: 'app' }] }); api.accounts.mockResolvedValue({ data: [{ username: 'ops' }] }); api.agents.mockResolvedValue({ data: [{ id: 7, username: 'worker', active: true, kind: 'agent', owner_user_id: 3 }] }) })
const open = async () => { const w = mount(Form, { global: { plugins: [ElementPlus] } }); await flushPromises(); return w }
describe('多資產申請', () => {
  it('新增與刪除項不開第二層', async () => {
    const w = await open(); await w.get('[data-test="add-item"]').trigger('click')
    expect(w.findAll('[data-test="request-item"]')).toHaveLength(2)
    await w.findAll('[data-test="remove-item"]')[1].trigger('click')
    expect(w.findAll('[data-test="request-item"]')).toHaveLength(1)
    expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0)
  })
  it('帳號清單延遲載入且載入中不可送出', async () => {
    const w = await open(); expect(api.accounts).not.toHaveBeenCalled()
    let resolve; api.accounts.mockReturnValue(new Promise(r => { resolve = r }))
    w.vm.items[0].assetId = 1; w.vm.reason = 'work'
    const pending = w.vm.loadAccounts(w.vm.items[0]); await flushPromises()
    expect(api.accounts).toHaveBeenCalledWith(1, { skipErrorToast: true })
    expect(w.get('[data-test="submit-request"]').attributes('disabled')).toBeDefined()
    expect(w.text()).toContain('正在載入帳號')
    resolve({ data: [{ username: 'ops' }] }); await pending
    w.vm.items[0].accounts = ['ops']; await flushPromises()
    expect(w.get('[data-test="submit-request"]').attributes('disabled')).toBeUndefined()
  })
  it('agent 項無全部帳號選項且帳號必填', async () => {
    const w = await open(); w.vm.executorId = 7; w.vm.reason = 'work'; w.vm.items[0].assetId = 1
    await w.vm.loadAccounts(w.vm.items[0]); await flushPromises()
    expect(w.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).not.toContain('@ALL')
    await w.vm.submit(); expect(api.create).not.toHaveBeenCalled()
    w.vm.items[0].accounts = ['ops']; api.create.mockResolvedValue({ id: 8, items: [{ id: 1 }] })
    await w.vm.submit()
    expect(api.create).toHaveBeenCalledWith({ items: [{ asset_id: 1, accounts: ['ops'] }], executor_user_id: 7, reason: 'work', duration_minutes: 60 }, { skipErrorToast: true })
  })
})

it('達開單上限時表單即時顯示 n/N', async () => {
  const w = await open(); w.vm.executorId = 7; w.vm.reason = 'keep reason'; w.vm.items[0].assetId = 1
  await w.vm.loadAccounts(w.vm.items[0]); w.vm.items[0].accounts = ['ops']
  for (const dimension of ['hour', 'pending']) {
    api.create.mockRejectedValue({ response: { status: 429, data: { code: 'RULE_AGENT_REQUEST_RATE', details: { used: 3, limit: 3, dimension, window_seconds: dimension === 'hour' ? 3600 : 0 } } } })
    await w.vm.submit(); await flushPromises(); expect(w.get('[data-test="request-error"]').text()).toContain('3/3')
    expect(w.get('[data-test="request-error"]').text()).toContain(dimension === 'hour' ? '本小時' : '待處理')
  }
  expect(w.vm.reason).toBe('keep reason'); expect(w.vm.items[0].accounts).toEqual(['ops'])
})
it('帳號不存在錯誤指到該項且保留其他項輸入', async () => {
  const w = await open(); w.vm.reason = 'retain'; w.vm.items[0].assetId = 1; await w.vm.loadAccounts(w.vm.items[0]); w.vm.items[0].accounts = ['ops']
  w.vm.addItem(); w.vm.items[1].assetId = 2; await w.vm.loadAccounts(w.vm.items[1]); w.vm.items[1].accounts = ['ops']
  api.create.mockRejectedValue({ response: { status: 400, data: { code: 'VALIDATION_ACCOUNT_NOT_ON_ASSET', details: { item_index: 1, asset_id: 2 } } } })
  await w.vm.submit(); await flushPromises()
  const rows = w.findAll('[data-test="request-item"]')
  expect(rows[0].find('[data-test="item-error"]').exists()).toBe(false)
  expect(rows[1].find('[data-test="item-error"]').exists()).toBe(true)
  expect(w.vm.items[0].accounts).toEqual(['ops']); expect(w.vm.reason).toBe('retain')
})

it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 2 三語 DOM：整單條件在項目上方 %s', async locale => { i18n.global.locale.value = locale; const w = await open(); w.vm.addItem(); await flushPromises(); expect(w.findAll('[data-test="request-item"]')).toHaveLength(2); expect(w.get('[data-test="multi-request"]').find('textarea').exists()).toBe(true); expect(w.text()).not.toMatch(/multiRequest\.|agentPrincipals\.|common\./); expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0) })

it('polish 2、4、5：姓名、代表關係、理由後果與缺帳號項數', async () => {
  api.agents.mockResolvedValue({ data: [{ id: 7, username: 'worker', kind: 'agent', owner_user_id: 3, owner_username: 'owner', active: true }] })
  const w = await open(); w.vm.executorId = 7; w.vm.reason = 'work'; await flushPromises()
  expect(w.text()).toContain('負責人：owner')
  expect(w.get('[data-test="executor-relationship"]').text()).toContain('申請人是您')
  expect(w.get('[data-test="reason-hint"]').text()).toContain('審核者會看到，事後稽核也看得到')
  expect(w.get('[data-test="missing-accounts"]').text()).toContain('還有 1 項沒選帳號')
  await w.get('[data-test="add-item"]').trigger('click')
  expect(w.get('[data-test="missing-accounts"]').text()).toContain('還有 2 項沒選帳號')
  w.vm.items[0].assetId = 1; await w.vm.loadAccounts(w.vm.items[0]); w.vm.items[0].accounts = ['ops']; await flushPromises()
  expect(w.get('[data-test="missing-accounts"]').text()).toContain('還有 1 項沒選帳號')
  await w.findAll('[data-test="remove-item"]')[1].trigger('click')
  expect(w.find('[data-test="missing-accounts"]').exists()).toBe(false)
  expect(w.get('[data-test="submit-request"]').attributes('disabled')).toBeUndefined()
})
