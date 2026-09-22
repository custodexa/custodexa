import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AgentTasks from '../AgentTasks.vue'
import i18n from '@/i18n'
import router, { createAuthGuard } from '@/router'
import { setAccessToken, resetSessionForTests } from '@/utils/session'
const api = vi.hoisted(() => ({ list: vi.fn(), route: { query: {} }, replace: vi.fn() }))
vi.mock('@/api/agentTasks', () => ({ getAgentTasks: api.list }))
vi.mock('vue-router', async original => ({ ...(await original()), useRoute: () => api.route, useRouter: () => ({ replace: api.replace }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
beforeEach(() => { vi.clearAllMocks(); api.route.query = {}; api.list.mockResolvedValue({ data: [{ id: 23, subject: 5, username: 'worker', owner_user_id: 2, status: 'approved', report_status: 'submitted', created_at: '2026-09-22T00:00:00Z' }], total: 1 }) })
const open = async () => { const w = mount(AgentTasks, { global: { plugins: [ElementPlus] } }); await flushPromises(); return w }
describe('任務列表', () => {
  it('四種篩選各自生效', async () => {
    const w = await open()
    w.vm.filters.subject = 5; await w.vm.load(); expect(api.list).toHaveBeenLastCalledWith({ subject: 5, offset: 0, limit: 20 })
    w.vm.filters.owner = 2; await w.vm.load(); expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ owner: 2 }))
    w.vm.range = [new Date('2026-09-01T00:00:00Z'), new Date('2026-09-22T00:00:00Z')]; await w.vm.load(); expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ from: '2026-09-01T00:00:00.000Z', to: '2026-09-22T00:00:00.000Z' }))
    w.vm.filters.report_status = 'missing'; await w.vm.load(); expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ report_status: 'missing' }))
    w.vm.changePage(2); await flushPromises(); expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20, subject: 5 }))
    expect(w.get('a').attributes('href')).toBe('/audit/agent-tasks/23')
  })
  it('無 audit:view 時導覽不顯示入口且直達被守衛擋下', async () => {
    setAccessToken('fixture'); localStorage.setItem('user', JSON.stringify({ roles: ['user'] }))
    const next = vi.fn(); await createAuthGuard()(router.resolve('/audit/agent-tasks'), {}, next); expect(next).toHaveBeenCalledWith('/dashboard')
    next.mockClear(); await createAuthGuard()(router.resolve('/audit/agent-tasks/23'), {}, next); expect(next).toHaveBeenCalledWith('/dashboard')
    resetSessionForTests(); localStorage.clear()
  })
  it.each(['zh-TW', 'en-US', 'ja-JP'])('任務列表三語 DOM 無裸 key：%s', async locale => { i18n.global.locale.value = locale; const w = await open(); expect(w.find('[data-test="task-filters"]').exists()).toBe(true); expect(w.text()).not.toMatch(/agentTasks\.|agentPrincipals\.|multiRequest\./) })
})
