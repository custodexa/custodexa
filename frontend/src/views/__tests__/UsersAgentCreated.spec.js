import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Users from '../Users.vue'
import AgentPrincipalForm from '../../components/agent/AgentPrincipalForm.vue'
import i18n from '@/i18n'

// 建立 agent 後的下一步：建立成功後對話框不直接關，
// 改在同一個對話框告訴管理者「建好了、負責人是誰、下一步是發鑰匙」，
// 並給「稍後再發」與「現在發鑰匙」兩個出口。起因是管理者建好 agent 後
// 找不到發鑰匙的地方。

const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), tokens: vi.fn() }))
vi.mock('@/api/user', async (original) => ({
  ...(await original()),
  getUserList: api.list,
  getUserDetail: vi.fn().mockResolvedValue({ data: {}, role_sets: { manual: [], mapped: [] } }),
  getRoleList: vi.fn().mockResolvedValue({ data: [{ name: 'admin' }, { name: 'user' }] }),
}))
vi.mock('@/api/agents', () => ({ createAgentPrincipal: api.create, getAgentTokens: api.tokens }))
vi.mock('@/api/auth', () => ({ getCurrentUser: vi.fn().mockResolvedValue({ data: { id: 1 } }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)

const global = {
  plugins: [ElementPlus],
  stubs: {
    'el-drawer': { name: 'ElDrawer', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
    'el-dialog': { name: 'ElDialog', props: ['modelValue', 'title'], template: '<section v-if="modelValue" data-test="user-dialog"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
  },
}

const OWNER = { id: 1, username: 'ops.owner', kind: 'human', active: true, roles: [] }

beforeEach(() => {
  vi.clearAllMocks()
  i18n.global.locale.value = 'zh-TW'
  api.list.mockResolvedValue({ data: [OWNER], total: 1 })
  api.tokens.mockResolvedValue({ data: [] })
  api.create.mockResolvedValue({ data: { id: 7, username: 'aibot1token', kind: 'agent', owner_user_id: 1, active: true, roles: [] } })
})

const createAgent = async () => {
  const w = mount(Users, { global })
  await flushPromises()
  w.vm.handleCreate()
  w.vm.createKind = 'agent'
  await flushPromises()
  const form = w.getComponent(AgentPrincipalForm)
  form.vm.username = 'aibot1token'
  form.vm.ownerId = 1
  await form.get('[data-test="agent-submit"]').trigger('click')
  await flushPromises()
  return w
}

describe('建立 agent 後的下一步', () => {
  it('建立成功後對話框留著，顯示名稱、負責人與下一步說明', async () => {
    const w = await createAgent()
    expect(w.vm.dialogVisible).toBe(true)
    const panel = w.get('[data-test="agent-created"]')
    expect(panel.text()).toContain('已建立 agent「aibot1token」')
    expect(panel.text()).toContain('負責人：ops.owner')
    expect(panel.text()).toContain('下一步：發鑰匙')
    expect(panel.text()).toContain('agent 要有鑰匙才能連線')
    expect(panel.text()).toContain('我的 agent')
    // 表單已退場，不會再按一次確認又建一個
    expect(w.findComponent(AgentPrincipalForm).exists()).toBe(false)
    expect(w.get('[data-test="agent-created-later"]').text()).toBe('稍後再發')
    expect(w.get('[data-test="agent-created-issue"]').text()).toBe('現在發鑰匙')
  })

  it('「稍後再發」關閉對話框，不開鑰匙抽屜', async () => {
    const w = await createAgent()
    await w.get('[data-test="agent-created-later"]').trigger('click')
    await flushPromises()
    expect(w.vm.dialogVisible).toBe(false)
    expect(w.vm.tokenDrawerVisible).toBe(false)
  })

  it('「現在發鑰匙」關閉對話框並打開該 agent 的鑰匙抽屜', async () => {
    const w = await createAgent()
    await w.get('[data-test="agent-created-issue"]').trigger('click')
    await flushPromises()
    expect(w.vm.dialogVisible).toBe(false)
    expect(w.vm.tokenDrawerVisible).toBe(true)
    expect(w.vm.tokenPrincipal.id).toBe(7)
    expect(api.tokens).toHaveBeenCalledWith(7)
    expect(w.getComponent({ name: 'TokenDrawer' }).props('ownerName')).toBe('ops.owner')
  })

  it('再開一次新增對話框時回到表單，不殘留上一次的成功畫面', async () => {
    const w = await createAgent()
    await w.get('[data-test="agent-created-later"]').trigger('click')
    await flushPromises()
    w.vm.handleCreate()
    w.vm.createKind = 'agent'
    await flushPromises()
    expect(w.find('[data-test="agent-created"]').exists()).toBe(false)
    expect(w.findComponent(AgentPrincipalForm).exists()).toBe(true)
  })

  it.each(['en-US', 'ja-JP'])('%s 的成功畫面沒有裸 key', async (locale) => {
    i18n.global.locale.value = locale
    const w = await createAgent()
    const panel = w.get('[data-test="agent-created"]')
    expect(panel.text()).toContain('aibot1token')
    expect(panel.text()).toContain('ops.owner')
    expect(w.text()).not.toMatch(/agentPrincipals\./)
  })
})

describe('AgentPrincipalForm 建立事件帶出新 agent', () => {
  it('created 事件含 id、名稱與負責人帳號', async () => {
    const w = mount(AgentPrincipalForm, { global })
    await flushPromises()
    w.vm.username = ' aibot1token '
    w.vm.ownerId = 1
    await w.get('[data-test="agent-submit"]').trigger('click')
    await flushPromises()
    const [agent] = w.emitted('created')[0]
    expect(agent).toMatchObject({ id: 7, username: 'aibot1token', owner_user_id: 1, owner_username: 'ops.owner', kind: 'agent' })
  })
})
