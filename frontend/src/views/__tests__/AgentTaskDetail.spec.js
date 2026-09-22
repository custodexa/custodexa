import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AgentTaskDetail from '../AgentTaskDetail.vue'
import i18n from '@/i18n'
import { formatDateTime } from '@/utils/format'
const api = vi.hoisted(() => ({ asset: vi.fn(), detail: vi.fn(), sessions: vi.fn(), ledger: vi.fn() }))
vi.mock('vue-router', () => ({ useRoute: () => ({ params: { requestId: '23' } }) }))
vi.mock('@/api/agentTasks', () => ({ getAgentTask: api.detail, getAgentToolCalls: api.ledger }))
vi.mock('@/api/assets', () => ({ getAsset: api.asset }))
vi.mock('@/api/sessions', () => ({ getSessionList: api.sessions }))
enableAutoUnmount(afterEach)
const payload = () => ({ request: { id: 23, requester_id: 1, executor_user_id: 5, executor: { id: 5, username: 'worker', kind: 'agent', owner_user_id: 99, owner_username: 'current' }, requester: { username: 'human' }, reason: 'check deployment', created_at: '2026-09-22T00:00:00Z', requested_duration_minutes: 60, decision_note: '<b>original note</b>', items: [{ id: 3, asset_id: 2, accounts: ['ops'], status: 'approved', approved_duration_minutes: 30, decided_by: 4, decided_at: '2026-09-22T01:00:00Z' }], approvals: [] }, reports: { total: 2, missing_report_at_close: true, closed_at: '2026-09-22T02:00:00Z', versions: [{ id: 2, version: 2, submitted_at: '2026-09-22T03:00:00Z', body: 'latest self report' }, { id: 1, version: 1, submitted_at: '2026-09-22T02:30:00Z', body: 'first self report' }] } })
beforeEach(() => { vi.clearAllMocks(); api.asset.mockResolvedValue({ name: 'app-host' }); api.detail.mockResolvedValue(payload()); api.sessions.mockResolvedValue({ data: [{ id: 8, owner_user_id: 2, agent_token_name: 'snapshot', has_recording: true, start_time: '2026-09-22T01:00:00Z' }], total: 1 }); api.ledger.mockResolvedValue({ data: [], total: 0 }) })
const open = async () => { const w = mount(AgentTaskDetail, { global: { plugins: [ElementPlus] } }); await flushPromises(); return w }
// textContent includes closed <details>; collect visible DOM text, retaining its summary.
function visibleText(node) {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent
  if (node.nodeType !== Node.ELEMENT_NODE) return ''
  const style = getComputedStyle(node)
  if (node.hidden || style.display === 'none' || ['hidden', 'collapse'].includes(style.visibility)) return ''
  if (node.tagName === 'DETAILS' && !node.open) {
    const summary = Array.from(node.children).find(child => child.tagName === 'SUMMARY')
    return summary ? visibleText(summary) : ''
  }
  return Array.from(node.childNodes, visibleText).join(' ')
}
describe('任務詳情', () => {
  it('行話在第二層：預設不露機器碼與欄位名，展開 details 後才出現', async () => {
    const codes = ['RULE_AGENT_BREAKER_PENDING', 'AUTH_TOKEN_EXPIRED', 'NOTFOUND_ACCESS_REQUEST']
    api.ledger.mockResolvedValue({ data: codes.map((code, index) => ({
      id: index + 1, seq: index + 1, tool: 'list_assets', decision: 'denied', denial_code: code,
      created_at: '2026-09-22T01:00:00Z', duration_ms: 0, masked_count: 0,
      args_redacted: { access_request_id: 23, agent_token_id: 8 },
    })), total: codes.length })
    const w = await open()
    const details = w.findAll('[data-test="ledger-row"] details')
    expect(details).toHaveLength(codes.length)
    expect(details.every(detail => !detail.element.open)).toBe(true)
    expect(visibleText(w.element)).not.toMatch(/RULE_|AUTH_|NOTFOUND_|access_request_id|agent_token_id/)
    for (const [index, detail] of details.entries()) {
      expect(visibleText(w.element)).toContain(detail.get('summary').text())
      // Set the native disclosure state; happy-dom has no browser layout engine.
      detail.element.open = true
      await detail.trigger('toggle')
      const text = visibleText(w.element)
      expect(text).toContain(codes[index])
      expect(text).toContain('access_request_id')
      expect(text).toContain('agent_token_id')
      detail.element.open = false
      await detail.trigger('toggle')
      expect(visibleText(w.element)).not.toMatch(/RULE_|AUTH_|NOTFOUND_|access_request_id|agent_token_id/)
    }
  })
  it('四段依固定順序呈現', async () => { const w = await open(); expect(w.findAll('.task-sections > section').map(n => n.attributes('data-test'))).toEqual(['task-who', 'task-grants', 'task-activity', 'task-reports']); expect(api.detail).toHaveBeenCalledWith(23, { limit: 20, offset: 0 }); expect(api.sessions).toHaveBeenCalledWith({ access_request_id: 23, page: 1, page_size: 20 }); expect(w.get('[data-test="task-session"]').text()).toContain('#2'); expect(api.ledger).toHaveBeenCalledWith({ access_request_id: 23, offset: 0, limit: 20 }) })
  it('核准註記對稽核者以原文呈現', async () => { const w = await open(); expect(w.get('[data-test="approval-note"]').text()).toBe('<b>original note</b>'); expect(w.get('[data-test="approval-note"]').find('b').exists()).toBe(false) })
  it('報告標示為自述且多版可讀', async () => { const w = await open(); expect(w.get('[data-test="report-boundary"]').text()).toContain('agent 自述，非授權證據'); await w.get('[data-test="toggle-reports"]').trigger('click'); expect(w.findAll('[data-test="report-version"]')).toHaveLength(2) })
  it('預設呈現最新版且可展開舊版', async () => { const w = await open(); expect(w.findAll('[data-test="report-version"]')).toHaveLength(1); expect(w.text()).toContain('latest self report'); expect(w.text()).not.toContain('first self report'); await w.get('[data-test="toggle-reports"]').trigger('click'); expect(w.text()).toContain('first self report') })
  it('缺報告呈現事實與關閉時間', async () => { const data = payload(); data.reports.versions = []; data.reports.total = 0; api.detail.mockResolvedValue(data); const w = await open(); expect(w.get('[data-test="missing-report"]').text()).toContain('關閉時缺報告'); expect(w.get('[data-test="missing-report"]').text()).toContain('2026') })
  it('關閉後補交仍標示關閉時缺報告', async () => { const w = await open(); expect(w.find('[data-test="missing-report"]').exists()).toBe(true); expect(w.get('[data-test="report-version"]').text()).toContain('關閉後修訂') })
  it('缺報告文案不推測原因', async () => { const w = await open(); expect(w.get('[data-test="missing-report"]').text()).not.toMatch(/故意|惡意|逃避|失敗/) })
  it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 5 三語 DOM 與四段設計對照：%s', async locale => { i18n.global.locale.value = locale; const w = await open(); expect(w.findAll('.task-sections > section')).toHaveLength(4); expect(w.text()).not.toMatch(/agentTasks\.|agentLedger\.|agentSession\./); expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0) })
})

it('核准票與會話各自分頁，不截掉後頁證據', async () => {
  const data = payload(); data.approval_total = 21; api.detail.mockResolvedValue(data); const w = await open()
  await w.vm.changeApprovals(2); expect(api.detail).toHaveBeenLastCalledWith(23, { limit: 20, approval_offset: 20 })
  w.vm.changeSessions(2); await flushPromises(); expect(api.sessions).toHaveBeenLastCalledWith({ access_request_id: 23, page: 2, page_size: 20 })
})

it('polish 9：核准表列資產、帳號、結果、起訖與決定者', async () => {
  const data = payload(); data.request.items[0].approved_date_start = '2026-09-22T01:00:00Z'; api.detail.mockResolvedValue(data)
  const w = await open(); const table = w.get('[data-test="grants-table"]')
  expect(table.findAll('th').map(th => th.text())).toEqual(['資產', '可以用哪些帳號', '狀態', '核准起訖', '決定者'])
  const cells = table.findAll('tbody td')
  expect(cells[0].text()).toContain('app-host'); expect(cells[1].text()).toContain('ops'); expect(cells[2].text()).toContain('已核准')
  expect(cells[3].text()).toContain(formatDateTime('2026-09-22T01:00:00Z')); expect(cells[3].text()).toContain(formatDateTime('2026-09-22T01:30:00Z')); expect(cells[4].text()).toContain('#4')
})
