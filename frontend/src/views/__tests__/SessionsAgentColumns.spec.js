import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Sessions from '../Sessions.vue'
import { formatDateTime } from '@/utils/format'
const api = vi.hoisted(() => ({ active: vi.fn(), list: vi.fn() }))
vi.mock('@/api/sessions', () => ({ getActiveSessions: api.active, getSessionList: api.list, terminateSession: vi.fn() }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
const row = { id: 3, user_id: 5, actor_kind: 'agent', owner_user_id: 2, access_request_id: 23, protocol: 'ssh', status: 'active', user: { username: 'worker', owner_user_id: 999 }, start_time: '2026-09-22T00:00:00Z', revoked_during_session_at: '2026-09-22T01:00:00Z' }
beforeEach(() => { api.active.mockResolvedValue([row]); api.list.mockResolvedValue({ data: [row], total: 1 }) })
describe('會話主體欄', () => {
  it('任務欄連往任務視角', async () => {
    const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
    expect(w.get('[data-test="session-task"]').attributes('href')).toBe('/audit/agent-tasks/23')
    expect(w.text()).toContain('負責人：#2'); expect(w.text()).not.toContain('#999')
  })
  it('撤權後仍活動於列表與詳情皆可見', async () => {
    const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
    expect(w.get('[data-test="session-revocation"]').text()).toContain(formatDateTime(row.revoked_during_session_at))
    expect(w.get('[data-test="session-revocation"]').text()).toContain('會話進行中授權已撤銷')
  })
})

it('主體類型篩選只回該類會話', async () => {
  const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
  w.vm.activeTab = 'history'; w.vm.filterForm.actor_kind = 'agent'; w.vm.handleFilter(); await flushPromises()
  expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ actor_kind: 'agent', page: 1 }))
  expect(w.vm.sessionList).toEqual([row]); w.vm.handleResetFilter(); await flushPromises()
  expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ actor_kind: undefined }))
})

it('polish 7、8：歷史欄位收斂且操作者、狀態、操作可見', async () => {
  const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
  w.vm.activeTab = 'history'; await w.vm.handleFilter(); await flushPromises()
  const table = w.get('[data-test="history-table"]')
  for (const label of ['操作者', '資產', '狀態', '操作']) expect(table.findAll('th').some(th => th.text().includes(label) && th.isVisible())).toBe(true)
  expect(table.text()).toContain('worker')
  expect(table.text()).toContain('進行中')
  const columns = w.getComponent('[data-test="history-table"]').findAllComponents({ name: 'ElTableColumn' })
  expect(columns.reduce((sum, col) => sum + Number(col.props('width') || col.props('minWidth')), 0)).toBeLessThanOrEqual(1080)
})

it('polish2：歷史負責人用該列 owner_username，不取操作者現任負責人', async () => {
  api.list.mockResolvedValue({ data: [{ ...row, owner_username: 'recorded-owner', user: { ...row.user, owner_username: 'new-owner' } }], total: 1 })
  const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
  w.vm.activeTab = 'history'; await w.vm.handleFilter(); await flushPromises()
  const table = w.get('[data-test="history-table"]')
  expect(table.text()).toContain('負責人：recorded-owner')
  expect(table.text()).not.toContain('負責人：#2')
  expect(table.text()).not.toContain('new-owner')
})
