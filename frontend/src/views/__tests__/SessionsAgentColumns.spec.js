import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Sessions from '../Sessions.vue'
import { t } from '@/i18n'
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
    expect(w.text()).toContain('負責人：未提供'); expect(w.text()).not.toContain('#999')
  })
  it('撤權後仍活動於列表與詳情皆可見', async () => {
    const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
    expect(w.get('[data-test="session-revocation"]').text()).toContain(formatDateTime(row.revoked_during_session_at))
    expect(w.get('[data-test="session-revocation"]').text()).toContain(t('enum.endReason.revoked'))
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
  // 負責人收進展開列：仍取該列快照的 owner_username，不取操作者現任負責人
  await table.get('.el-table__expand-icon').trigger('click'); await flushPromises()
  const more = w.get('[data-test="session-more"]')
  expect(more.text()).toContain('recorded-owner')
  expect(more.text()).not.toContain('未提供')
  expect(w.text()).not.toContain('new-owner')
})

it('歷史列的撤權：欄內只留彩標，完整句與時間在 title 與展開列', async () => {
  const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
  w.vm.activeTab = 'history'; await w.vm.handleFilter(); await flushPromises()
  const table = w.get('[data-test="history-table"]')
  const tag = table.get('[data-test="session-revocation"]')
  expect(tag.text()).toBe(t('enum.endReason.revoked'))
  expect(tag.attributes('title')).toContain(formatDateTime(row.revoked_during_session_at))
  await table.get('.el-table__expand-icon').trigger('click'); await flushPromises()
  expect(w.get('[data-test="session-more-revocation"]').text()).toBe(formatDateTime(row.revoked_during_session_at))
})

it.each(['active', 'history'])('%s 身分格完整呈現長名與無代表人，協議分類與碼分行', async tab => {
  const username = 'demo-agent-35f3-with-a-very-long-account-name'
  const longRow = { ...row, protocol: 'postgres', user: { username }, on_behalf_of_user_id: null }
  api.active.mockResolvedValue([longRow]); api.list.mockResolvedValue({ data: [longRow], total: 1 })
  const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
  if (tab === 'history') { w.vm.activeTab = tab; await w.vm.handleFilter(); await flushPromises() }
  const table = tab === 'history' ? w.get('[data-test="history-table"]') : w.get('.el-table')
  const actor = table.get('[data-test="session-actor"]')
  const behalf = table.get('[data-test="session-on-behalf"]')
  expect(actor.text()).toBe(username)
  expect(actor.attributes('title')).toBe(username)
  expect(behalf.text()).toBe(t('agentSession.none'))
  for (const cell of [actor, behalf]) {
    expect(cell.element.closest('td').classList.contains('identity-cell')).toBe(true)
    expect(cell.element.closest('.el-tooltip')).toBeNull()
  }
  const columns = (tab === 'history' ? w.getComponent('[data-test="history-table"]') : w.findAllComponents({ name: 'ElTable' })[0]).findAllComponents({ name: 'ElTableColumn' }).filter(col => col.props('className') === 'identity-cell')
  expect(columns.map(col => Number(col.props('minWidth')))).toEqual([200, 140])
  expect(columns.every(col => !col.props('showOverflowTooltip'))).toBe(true)
  expect(table.get('[data-test="session-protocol-kind"]').text()).toBe('資料庫')
  expect(table.get('[data-test="session-protocol-code"]').text()).toBe('POSTGRES')
})

it('歷史首層仍保留工具呼叫數與連線帳號，IP 留在展開明細', async () => {
  api.list.mockResolvedValue({ data: [{ ...row, account_username: 'recorded-login', client_ip: '192.0.2.10' }], total: 1 })
  const w = mount(Sessions, { global: { plugins: [ElementPlus] } }); await flushPromises()
  w.vm.activeTab = 'history'; await w.vm.handleFilter(); await flushPromises()
  const table = w.get('[data-test="history-table"]')
  expect(table.get('[data-test="session-task-calls"]').find('[data-test="session-calls"]').exists()).toBe(true)
  expect(table.get('.account-cell').text()).toBe('recorded-login')
  await table.get('.el-table__expand-icon').trigger('click'); await flushPromises()
  expect(w.get('[data-test="session-more"]').text()).toContain('192.0.2.10')
})
