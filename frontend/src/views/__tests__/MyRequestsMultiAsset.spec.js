import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MyRequests from '../MyRequests.vue'
import RequestItems from '@/components/access-request/RequestItems.vue'
const list = vi.hoisted(() => vi.fn())
vi.mock('@/api/accessRequests', async original => ({ ...(await original()), getMyAccessRequests: list, getMyActiveTickets: vi.fn().mockResolvedValue({ data: [] }), cancelAccessRequest: vi.fn() }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
const row = { id: 23, status: 'approved', asset_id: 1, asset: { name: 'app' }, requested_duration_minutes: 60, items: [{ id: 1, asset_id: 1, accounts: ['ops'], status: 'approved' }, { id: 2, asset_id: 2, accounts: ['db'], status: 'rejected' }] }
beforeEach(() => list.mockResolvedValue({ data: [row] }))
async function open() { const w = mount(MyRequests, { global: { plugins: [ElementPlus] } }); await flushPromises(); return w }
describe('多項我的申請', () => {
  it('展開顯示逐項狀態', async () => {
    const w = await open(); await w.get('.el-table__expand-icon').trigger('click'); await flushPromises()
    expect(w.getComponent(RequestItems).findAll('[data-test="request-item-state"]')).toHaveLength(2)
    expect(w.getComponent(RequestItems).text()).toContain('ops'); expect(w.getComponent(RequestItems).text()).toContain('db')
    expect(w.getComponent(RequestItems).text()).toContain('未核准')
    expect(w.text()).toContain('2 項資產')
  })
  it('單項被拒不使整單顯示失效', async () => {
    const w = await open(); expect(w.vm.displayStatusText(row)).toBe('已核准')
    expect(w.vm.displayStatusText({ ...row, revoked_at: '2026-09-22T00:00:00Z' })).toBe('已核准')
  })
  it('已核准單可進入任務視角', async () => {
    const w = await open(); expect(w.get('[data-test="request-task"]').attributes('href')).toBe('/audit/agent-tasks/23')
  })
})
