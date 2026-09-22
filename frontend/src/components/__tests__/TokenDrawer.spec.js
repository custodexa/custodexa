import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import TokenDrawer from '../agent/TokenDrawer.vue'
import Users from '../../views/Users.vue'
import i18n from '@/i18n'
const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), revoke: vi.fn() }))
vi.mock('@/api/agents', () => ({ getAgentTokens: api.list, createAgentToken: api.create, revokeAgentToken: api.revoke, createAgentPrincipal: vi.fn() }))
vi.mock('@/api/user', async original => ({ ...(await original()), getUserList: vi.fn().mockResolvedValue({ data: [], total: 0 }), getUserDetail: vi.fn().mockResolvedValue({ data: {}, role_sets: { manual: [], mapped: [] } }), getRoleList: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/auth', () => ({ getCurrentUser: vi.fn().mockResolvedValue({ data: { id: 1 } }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
afterEach(() => vi.restoreAllMocks())
const principal = { id: 5, kind: 'agent', username: 'worker', owner_user_id: 1, active: true }
const token = { id: 9, name: 'nightly', created_by: 1, created_at: '2026-09-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', last_used_at: null }
const options = { plugins: [ElementPlus], stubs: {
  'el-drawer': { name: 'ElDrawer', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
  'el-dialog': { name: 'ElDialog', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
} }
const open = async (data = principal) => {
  const w = mount(TokenDrawer, { props: { modelValue: true, principal: data }, global: options })
  await flushPromises()
  await vi.waitFor(() => expect(w.find('[data-test="token-panel"]').exists()).toBe(true))
  return w
}
beforeEach(() => { vi.clearAllMocks(); api.list.mockResolvedValue({ data: [token] }); api.create.mockResolvedValue({ ...token, token: 'cxa_reveal_once_fixture' }); api.revoke.mockResolvedValue(undefined) })
describe('TokenDrawer', () => {
  it.each(['zh-TW', 'en-US', 'ja-JP'])('建立遭熔斷拒絕經單一入口翻譯且不顯示明文：%s', async locale => {
    i18n.global.locale.value = locale
    const code = 'RULE_AGENT_BREAKER_PENDING'
    const key = `apiError.${code}`
    expect(i18n.global.te(key, locale)).toBe(true)
    api.create.mockRejectedValue({ response: { status: 409, data: { code, error: 'untranslated backend error' } } })
    const w = await open()
    w.vm.name = 'nightly'
    w.vm.expiresAt = new Date('2099-01-01T00:00:00Z')
    await w.get('[data-test="issue-token"]').trigger('click')
    await flushPromises()
    expect(api.create).toHaveBeenCalledWith(5, { name: 'nightly', expires_at: '2099-01-01T00:00:00.000Z' })
    expect(w.get('[role="alert"]').text()).toContain(i18n.global.t(key))
    expect(w.text()).not.toContain(code)
    expect(w.text()).not.toContain('untranslated backend error')
    expect(w.find('[data-test="token-reveal"]').exists()).toBe(false)
    expect(w.text()).not.toContain('cxa_reveal_once_fixture')
  })
  it('抽屜內不渲染第二層對話框', async () => {
    const w = await open()
    await w.get('[data-test="revoke-start"]').trigger('click')
    expect(w.findAllComponents({ name: 'ElDrawer' })).toHaveLength(1)
    expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0)
    expect(w.get('[data-test="revoke-confirm"]').isVisible()).toBe(true)
  })
  it('開啟抽屜時編輯對話框關閉', async () => {
    const w = mount(Users, { global: options })
    await flushPromises()
    w.vm.handleEdit({ id: 3, username: 'human' })
    await flushPromises()
    expect(w.vm.dialogVisible).toBe(true)
    w.vm.openTokenDrawer(principal)
    await flushPromises()
    expect(w.vm.dialogVisible).toBe(false)
    expect(w.getComponent(TokenDrawer).props('modelValue')).toBe(true)
    w.vm.handleEdit({ id: 3, username: 'human' })
    await flushPromises()
    expect(w.getComponent(TokenDrawer).props('modelValue')).toBe(false)
  })
  it('明文只在建立回應當下呈現', async () => {
    const w = await open()
    expect(w.text()).not.toContain('cxa_reveal_once_fixture')
    w.vm.name = 'nightly'
    w.vm.expiresAt = new Date('2099-01-01T00:00:00Z')
    await w.get('[data-test="issue-token"]').trigger('click'); await flushPromises()
    expect(api.create).toHaveBeenCalledWith(5, { name: 'nightly', expires_at: '2099-01-01T00:00:00.000Z' })
    expect(w.get('[data-test="token-reveal"]').text()).toContain('cxa_reveal_once_fixture')
    expect(w.text()).toContain('離開後無法再次取得')
    const copy = vi.fn().mockResolvedValue(undefined)
    vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(copy)
    await w.get('[data-test="copy-token"]').trigger('click'); await flushPromises()
    expect(copy).toHaveBeenCalledWith('cxa_reveal_once_fixture')
    await w.setProps({ modelValue: false }); await w.setProps({ modelValue: true }); await flushPromises()
    expect(w.find('[data-test="token-reveal"]').exists()).toBe(false)
    expect(w.text()).not.toContain('cxa_reveal_once_fixture')
  })
  it('撤銷確認載明會話立即結束', async () => {
    const w = await open()
    await w.get('[data-test="revoke-start"]').trigger('click')
    expect(w.get('[data-test="revoke-confirm"]').text()).toContain('會話會立即結束')
    expect(api.revoke).not.toHaveBeenCalled()
    api.list.mockResolvedValue({ data: [{ ...token, revoked_at: '2026-09-22T00:00:00Z' }] })
    await w.get('[data-test="revoke-confirm-submit"]').trigger('click'); await flushPromises()
    expect(api.revoke).toHaveBeenCalledWith(5, 9, '')
    expect(w.text()).toContain('已撤銷')
  })
  it('熔斷未處置時建立動作停用', async () => {
    const w = await open({ ...principal, breaker_pending_at: '2026-09-22T00:00:00Z' })
    expect(w.get('[data-test="issue-token"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="breaker-summary"]').text()).toContain('不能發新鑰匙')
    expect(w.get('a').attributes('href')).toBe('/agent-breakers?user_id=5')
    await w.vm.issue(); expect(api.create).not.toHaveBeenCalled()
  })
})

describe('熔斷處置出口', () => {
  it('抽屜熔斷摘要連往處置頁', async () => {
    const w = await open({ ...principal, breaker_pending_at: '2026-09-22T00:00:00Z' })
    expect(w.get('[data-test="breaker-summary"] a').attributes('href')).toBe('/agent-breakers?user_id=5')
    expect(w.find('[data-test="release-submit"]').exists()).toBe(false)
  })
})
