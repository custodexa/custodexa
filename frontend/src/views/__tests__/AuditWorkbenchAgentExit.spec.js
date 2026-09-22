import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuditWorkbench from '../AuditWorkbench.vue'
import router from '@/router'
vi.mock('vue-router', async original => ({ ...(await original()), useRoute: () => ({ path: '/audit/workbench', query: {} }), useRouter: () => ({ replace: vi.fn().mockResolvedValue(), push: vi.fn() }) }))
vi.mock('@/api/auditTimeline', () => ({ getAuditSubjects: vi.fn().mockResolvedValue({ data: [], total: 0 }), getAuditTimeline: vi.fn().mockResolvedValue({ events: [], spans: [], coverage: [], has_more: false }) }))
class Observer { observe() {} unobserve() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer); vi.stubGlobal('ResizeObserver', Observer)
enableAutoUnmount(afterEach)
describe('任務反向出口', () => {
  it('agent 主體出現任務出口', async () => {
    const w = mount(AuditWorkbench, { global: { plugins: [ElementPlus] } }); await flushPromises()
    w.vm.onSubjectValue(5); w.vm.onSubjectPicked({ id: 5, name: 'worker', kind: 'agent', owner_user_id: 2 }); await flushPromises()
    expect(w.get('[data-test="agent-task-exit"]').attributes('href')).toBe('/audit/agent-tasks?subject=5')
    const target = router.resolve('/audit/agent-tasks?subject=5'); expect(target.meta.roles).toEqual(['admin', 'auditor']); expect(target.meta.requiresAuth).toBe(true)
    w.vm.onSubjectValue(6); await flushPromises(); expect(w.find('[data-test="agent-task-exit"]').exists()).toBe(false)
  })
  it('人類主體不出現該出口', async () => {
    const w = mount(AuditWorkbench, { global: { plugins: [ElementPlus] } }); await flushPromises()
    w.vm.onSubjectValue(5); w.vm.onSubjectPicked({ id: 5, name: 'agent-in-name', kind: 'human' }); await flushPromises(); expect(w.find('[data-test="agent-task-exit"]').exists()).toBe(false)
  })
})
