import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Users from '../Users.vue'
import PrincipalBadge from '../../components/agent/PrincipalBadge.vue'
import AgentPrincipalForm from '../../components/agent/AgentPrincipalForm.vue'
import i18n, { t } from '@/i18n'
const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn() }))
vi.mock('@/api/user', async original => ({ ...(await original()), getUserList: api.list, getUserDetail: vi.fn().mockResolvedValue({ data: {}, role_sets: { manual: [], mapped: [] } }), getRoleList: vi.fn().mockResolvedValue({ data: [{ name: 'admin' }, { name: 'user' }, { name: 'auditor' }, { name: 'approver' }] }) }))
vi.mock('@/api/agents', () => ({ createAgentPrincipal: api.create, getAgentTokens: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/auth', () => ({ getCurrentUser: vi.fn().mockResolvedValue({ data: { id: 1 } }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
const global = { plugins: [ElementPlus], stubs: {
  'el-drawer': { name: 'ElDrawer', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
  'el-dialog': { name: 'ElDialog', props: ['modelValue', 'title'], template: '<section v-if="modelValue"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
} }
beforeEach(() => {
  vi.clearAllMocks()
  api.list.mockResolvedValue({ data: [{ id: 1, username: 'agent-human-name', kind: 'human', active: true, roles: [] }, { id: 5, username: 'carol', kind: 'agent', owner_user_id: 1, active: true, roles: [] }], total: 2 })
})
describe('Users agent principal', () => {
  it('列表標示主體類型與負責人', async () => {
    const w = mount(Users, { global }); await flushPromises()
    const badges = w.findAllComponents(PrincipalBadge)
    expect(badges.map(b => b.props('kind'))).toEqual(['human', 'agent'])
    expect(badges[1].text()).toContain('負責人：未提供')
    expect(api.list).toHaveBeenCalledWith(expect.objectContaining({ include_agents: true }))
  })
  it('agent 建立表單無登入與高權角色欄位', async () => {
    const w = mount(Users, { global }); await flushPromises()
    w.vm.handleCreate(); await flushPromises()
    w.vm.createKind = 'agent'; await flushPromises()
    await vi.waitFor(() => expect(w.findComponent(AgentPrincipalForm).exists()).toBe(true))
    const form = w.getComponent(AgentPrincipalForm)
    expect(form.find('input[type="password"]').exists()).toBe(false)
    expect(w.find('[data-test="user-dialog-submit"]').exists()).toBe(false)
    expect(form.findAllComponents({ name: 'ElCheckbox' })).toHaveLength(0)
    expect(form.findAll('input')).not.toHaveLength(0)
    form.vm.username = 'worker'; form.vm.ownerId = 1
    api.create.mockResolvedValue({ data: { id: 7 } })
    await form.get('[data-test="agent-submit"]').trigger('click'); await flushPromises()
    expect(api.create).toHaveBeenCalledWith({ username: 'worker', owner_user_id: 1, roles: ['user'] })
    expect(w.vm.dialogVisible).toBe(false)
  })
  it('缺負責人時顯示對應錯誤文字', async () => {
    const w = mount(AgentPrincipalForm, { global }); await flushPromises()
    w.vm.username = 'worker'
    i18n.global.locale.value = 'ja-JP'
    await w.get('[data-test="agent-submit"]').trigger('click'); await flushPromises()
    expect(w.text()).toContain(t('apiError.VALIDATION_AGENT_OWNER_REQUIRED'))
    expect(api.create).not.toHaveBeenCalled()
  })
})

it('類型篩選只回該類主體', async () => {
  const w = mount(Users, { global }); await flushPromises()
  api.list.mockResolvedValue({ data: [{ id: 5, kind: 'agent', username: 'worker', owner_user_id: 1, roles: [] }], total: 1 })
  await w.getComponent('[data-test="principal-kind-filter"]').vm.$emit('update:modelValue', 'agent')
  w.vm.handleFilter(); await flushPromises()
  expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ kind: 'agent', include_agents: true, page: 1 }))
  expect(w.findAllComponents(PrincipalBadge).map(b => b.props('kind'))).toEqual(['agent'])
  w.vm.handleResetFilter(); await flushPromises(); expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ kind: undefined }))
})

it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 1 三語 DOM：主副行與同層表單 %s', async locale => { i18n.global.locale.value = locale; const w = mount(Users, { global }); await flushPromises(); expect(w.findAllComponents(PrincipalBadge)).toHaveLength(2); expect(w.find('[data-test="principal-kind-filter"]').exists()).toBe(true); expect(w.text()).not.toMatch(/agentPrincipals\.|users\.|common\./); w.vm.handleCreate(); w.vm.createKind = 'agent'; await flushPromises(); expect(w.findComponent(AgentPrincipalForm).exists()).toBe(true); expect(w.findAll('input[type="password"]')).toHaveLength(0) })

it('polish 1–3：副標、姓名投影與篩選回顯', async () => {
  api.list.mockResolvedValue({ data: [{ id: 5, username: 'worker', kind: 'agent', owner_user_id: 1, owner_username: 'responsible', roles: [] }], total: 1 })
  const w = mount(Users, { global }); await flushPromises()
  expect(w.text()).toContain('每個 AI agent 都必須指定一位人員負責')
  expect(w.getComponent(PrincipalBadge).text()).toContain('負責人：responsible')
  const select = w.getComponent('[data-test="principal-kind-filter"]')
  await select.vm.$emit('update:modelValue', 'agent'); await flushPromises()
  expect(select.props('modelValue')).toBe('agent')
  expect(select.findAll('.el-select__selected-item').some(item => item.isVisible() && item.text() === 'AI agent')).toBe(true)
  expect(select.attributes('style')).toContain('width: 160px')
  w.vm.openTokenDrawer(w.vm.userList[0]); await flushPromises()
  expect(w.getComponent({ name: 'TokenDrawer' }).props('ownerName')).toBe('responsible')
})
