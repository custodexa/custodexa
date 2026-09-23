import i18n from '@/i18n'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MyAgents from '../MyAgents.vue'
import TokenDrawer from '../../components/agent/TokenDrawer.vue'
const api = vi.hoisted(() => ({ list: vi.fn(), tokens: vi.fn(), create: vi.fn() }))
vi.mock('@/api/agents', () => ({ getMyAgents: api.list, createMyAgent: api.create, getAgentTokens: api.tokens, createAgentToken: vi.fn(), revokeAgentToken: vi.fn() }))
enableAutoUnmount(afterEach)
const global = { plugins: [ElementPlus], stubs: {
  'el-drawer': { name: 'ElDrawer', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
  'el-dialog': { name: 'ElDialog', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
} }
beforeEach(() => {
  vi.clearAllMocks()
  api.list.mockResolvedValue({ data: [{ id: 5, username: 'my-worker', owner_user_id: 1, kind: 'agent', active: true, breaker_pending_at: '2026-09-22T00:00:00Z' }], total: 1 })
  api.tokens.mockResolvedValue({ data: [] })
})
describe('我的 agent', () => {
  it('本人清單沿自助端點，沒有負責人下拉與停用主體', async () => {
    const w = mount(MyAgents, { global }); await flushPromises()
    expect(api.list).toHaveBeenCalledWith()
    expect(w.get('[data-test="my-agent-row"]').text()).toContain('my-worker')
    expect(w.findAllComponents({ name: 'ElSelect' })).toHaveLength(0)
    expect(w.findAllComponents({ name: 'ElSwitch' })).toHaveLength(0)
    // 頁首只留一句說明，其餘兩句收進「？」提示（提示內容以 aria-label 呈現）
    expect(w.findAllComponents({ name: 'HelpTip' })[0].get('button').attributes('aria-label')).toContain('負責人固定是您')
    expect(w.get('a').attributes('href')).toBe('/agent-breakers?user_id=5')
    w.vm.openKeys(w.vm.agents[0]); await flushPromises()
    await vi.waitFor(() => expect(w.getComponent(TokenDrawer).find('[data-test="token-panel"]').exists()).toBe(true))
    expect(w.getComponent(TokenDrawer).props('principal').id).toBe(5)
    expect(w.getComponent(TokenDrawer).get('[data-test="issue-token"]').attributes('disabled')).toBeDefined()
  })
  it('清單載入失敗不冒稱名下沒有 agent', async () => {
    api.list.mockRejectedValue({ response: { status: 500, data: { code: 'INTERNAL_USER_QUERY' } } })
    const w = mount(MyAgents, { global }); await flushPromises()
    expect(w.text()).toContain('這不代表您名下沒有 agent')
    expect(w.find('[data-test="my-agents-empty"]').exists()).toBe(false)
  })
})

it('政策開：固定本人建立，無 owner 欄', async () => {
  api.list.mockResolvedValue({ data: [], self_create: { enabled: true, max_per_owner: 5, current: 0 } }); api.create.mockResolvedValue({ data: { id: 9 } })
  const w = mount(MyAgents, { global }); await flushPromises(); await w.get('[data-test="create-my-agent"]').trigger('click')
  w.vm.username = 'worker'; w.vm.purpose = 'daily check'; await w.get('[data-test="save-my-agent"]').trigger('click'); await flushPromises()
  expect(api.create).toHaveBeenCalledWith({ username: 'worker', purpose: 'daily check' }); expect(w.findAllComponents({ name: 'ElSelect' })).toHaveLength(0)
})
it('政策關：403 政策值顯示管理員處理而非載入失敗', async () => {
  api.list.mockRejectedValue({ response: { status: 403, data: { code: 'RULE_AGENT_SELF_CREATE_DISABLED', self_create: { enabled: false, max_per_owner: 5, current: 1 } } } })
  const w = mount(MyAgents, { global }); await flushPromises(); expect(w.get('[data-test="policy-disabled"]').text()).toContain('建立 agent 由管理員處理')
  expect(w.find('[data-test="create-my-agent"]').exists()).toBe(false); expect(w.text()).not.toContain('未能載入清單'); expect(w.find('[data-test="my-agents-empty"]').exists()).toBe(true); expect(api.create).not.toHaveBeenCalled()
})

it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 7 三語 DOM：本人清單與政策建立 %s', async locale => { i18n.global.locale.value = locale; api.list.mockResolvedValue({ data: [{ id: 5, username: 'worker', kind: 'agent', active: true, owner_user_id: 1 }], self_create: { enabled: true, current: 1, max_per_owner: 5 } }); const w = mount(MyAgents, { global }); await flushPromises(); await w.get('[data-test="create-my-agent"]').trigger('click'); expect(w.find('[data-test="create-my-agent-form"]').exists()).toBe(true); expect(w.findAllComponents({ name: 'ElSelect' })).toHaveLength(0); expect(w.text()).not.toMatch(/agentPrincipals\.|agentBreaker\.|common\./) })

it('polish 2：本人負責人顯示您，抽屜沿用本人語義', async () => {
  const w = mount(MyAgents, { global }); await flushPromises()
  expect(w.get('[data-test="my-agent-row"]').text()).toContain('負責人：您')
  expect(w.get('[data-test="my-agent-row"]').text()).not.toContain('#1')
  w.vm.openKeys(w.vm.agents[0]); await flushPromises()
  expect(w.getComponent(TokenDrawer).props('ownerName')).toBe('您')
})
