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
beforeEach(() => { vi.clearAllMocks(); api.asset.mockResolvedValue({ name: 'app-host' }); api.detail.mockResolvedValue(payload()); api.sessions.mockResolvedValue({ data: [{ id: 8, owner_user_id: 2, owner_username: 'owner-b', agent_token_name: 'snapshot', has_recording: true, start_time: '2026-09-22T01:00:00Z' }], total: 1 }); api.ledger.mockResolvedValue({ data: [], total: 0 }) })
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
  // 契約在「申請人即執行者」時 executor_user_id 回 null，executor.id 仍有值：
  // 只判前者時「看鑰匙」直達永不渲染
  it('executor_user_id 缺席時仍以 executor.id 渲染看鑰匙直達', async () => {
    const data = payload()
    data.request.executor_user_id = null
    api.detail.mockResolvedValue(data)
    const w = await open()
    expect(w.get('[data-test="executor-keys-link"]').attributes('href')).toBe('/users?open=5')
  })

  it('兩個 id 都沒有時不渲染看鑰匙直達', async () => {
    const data = payload()
    data.request.executor_user_id = null
    data.request.executor = { username: 'worker', kind: 'agent' }
    api.detail.mockResolvedValue(data)
    const w = await open()
    expect(w.find('[data-test="executor-keys-link"]').exists()).toBe(false)
  })

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
  it('四段依固定順序呈現', async () => { const w = await open(); expect(w.findAll('.task-sections > section').map(n => n.attributes('data-test'))).toEqual(['task-who', 'task-grants', 'task-activity', 'task-reports']); expect(api.detail).toHaveBeenCalledWith(23, { limit: 20, offset: 0 }); expect(api.sessions).toHaveBeenCalledWith({ access_request_id: 23, page: 1, page_size: 20 }); expect(w.get('[data-test="task-session"]').text()).toContain('owner-b'); expect(w.get('[data-test="task-session"]').text()).not.toContain('#2'); expect(api.ledger).toHaveBeenCalledWith({ access_request_id: 23, offset: 0, limit: 20 }) })
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

it('polish 9：申請與核准逐項對照，縮限之處明示', async () => {
  const data = payload()
  data.request.items[0].approved_date_start = '2026-09-22T01:00:00Z'
  data.request.items[0].decided_by_username = 'lead'
  data.request.items.push({ id: 4, asset_id: 3, accounts: ['root'], status: 'rejected' })
  api.detail.mockResolvedValue(data)
  const w = await open()
  const cards = w.findAll('[data-test="grant-compare"]')
  expect(cards).toHaveLength(2)
  expect(cards[0].findAll('.cmp-col-h').map(node => node.text())).toEqual(['申請', '核准'])
  expect(cards[0].text()).toContain('app-host')
  // 核准會覆寫項目的帳號範圍，申請當時的範圍不再可讀，畫面據實說明而不照抄核准值
  expect(cards[0].get('[data-test="requested-accounts"]').text()).toContain('未留存')
  expect(cards[0].get('[data-test="approved-accounts"]').text()).toContain('ops')
  expect(cards[0].get('[data-test="approved-duration"]').text()).toContain('已縮限')
  expect(cards[0].get('[data-test="approved-duration"]').text()).toContain(formatDateTime('2026-09-22T01:00:00Z'))
  expect(cards[0].get('[data-test="approved-duration"]').text()).toContain(formatDateTime('2026-09-22T01:30:00Z'))
  // 決定者以帳號名呈現，畫面不再留 id
  expect(cards[0].get('[data-test="grant-decider"]').text()).toContain('lead')
  expect(cards[0].get('[data-test="grant-decider"]').text()).not.toContain('#4')
  expect(cards[1].get('[data-test="requested-accounts"]').text()).toContain('root')
  expect(cards[1].get('[data-test="approved-accounts"]').text()).toBe('沒有核准任何帳號')
  expect(cards[1].get('[data-test="grant-status"]').text()).toBe('整項未核准')
  expect(w.get('[data-test="narrowed-count"]').text()).toBe('2 項中有 2 項被縮限')
})

it('帳本對象欄由會話清單帶出資產與帳號', async () => {
  api.sessions.mockResolvedValue({ data: [{ id: 8, asset: { name: 'app-host' }, account_username: 'ops', start_time: '2026-09-22T01:00:00Z' }], total: 1 })
  api.ledger.mockResolvedValue({ data: [{ id: 1, seq: 1, session_id: 8, access_request_id: 23, tool: 'run_command', decision: 'allowed', denial_code: '', masked_count: 0, duration_ms: 5, args_redacted: {}, created_at: '2026-09-22T01:00:00Z' }], total: 1 })
  const w = await open()
  const target = w.get('[data-test="ledger-target"]')
  expect(target.text()).toContain('app-host'); expect(target.text()).toContain('ops')
})

it('申請帳號範圍留存時正常對照，帳號被縮限一併計入', async () => {
  const data = payload()
  data.request.items[0].requested_accounts = ['ops', 'reporting']
  data.request.items[0].decided_by_username = 'lead'
  api.detail.mockResolvedValue(data)
  const w = await open()
  const card = w.get('[data-test="grant-compare"]')
  expect(card.get('[data-test="requested-accounts"]').text()).toContain('reporting')
  expect(card.get('[data-test="requested-accounts"]').text()).not.toContain('未留存')
  expect(card.get('[data-test="approved-accounts"]').text()).toContain('ops')
  expect(card.get('[data-test="approved-accounts"]').text()).toContain('已縮限')
  expect(card.get('[data-test="grant-status"]').text()).toBe('已縮限')
  expect(w.get('[data-test="narrowed-count"]').text()).toBe('1 項中有 1 項被縮限')
})

it('無決定者時不顯示 id，自動核准維持政策文案', async () => {
  const data = payload()
  data.request.auto_approved = true
  delete data.request.items[0].decided_by_username
  api.detail.mockResolvedValue(data)
  const w = await open()
  const decider = w.get('[data-test="grant-decider"]')
  expect(decider.text()).toContain('自動核准')
  expect(decider.text()).not.toContain('#4')
})

it('帳本列自帶對象時免經會話清單', async () => {
  api.sessions.mockResolvedValue({ data: [], total: 0 })
  api.ledger.mockResolvedValue({ data: [{ id: 1, seq: 1, session_id: null, access_request_id: 23, asset_name: 'cache-01', account_username: 'appuser', tool: 'open_session', decision: 'denied', denial_code: 'AUTH_REQUEST_ITEM_MISMATCH', masked_count: 0, duration_ms: 8, args_redacted: {}, created_at: '2026-09-22T01:00:00Z' }], total: 1 })
  const w = await open()
  const target = w.get('[data-test="ledger-target"]')
  expect(target.text()).toContain('cache-01'); expect(target.text()).toContain('appuser')
  expect(target.text()).not.toContain('未建立會話')
})
