// SessionDetail 的錄影失敗標示：
// recording_error 存的是 cause code，tooltip 必須查譯而非顯裸碼。
// Sessions.vue 的三處同型 tooltip 另有 Sessions.spec.js 把關——本檔專守詳情頁。
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.setConfig({ testTimeout: 20_000 })

const getSessionMock = vi.fn()
const getCommandsMock = vi.fn()
const searchAlertsMock = vi.fn()

vi.mock('@/api/sessions', () => ({
  getSession: (...a) => getSessionMock(...a),
  getRecordingUrl: () => '',
  getRecordingToken: vi.fn().mockResolvedValue({ token: 't' }),
  recordingStreamUrlByToken: () => '',
  downloadRecording: vi.fn(),
}))

vi.mock('@/api/commands', () => ({
  getSessionCommands: (...a) => getCommandsMock(...a),
}))
vi.mock('@/api/alerts', () => ({ searchAlerts: (...a) => searchAlertsMock(...a) }))

// 剪貼簿事實列表：本檔不驗剪貼簿面，mock 成空集保持密封（B3 新增呼叫）
vi.mock('@/api/clipboardEvents', () => ({
  getSessionClipboardEvents: vi.fn().mockResolvedValue({ data: [] }),
  getClipboardEventContent: vi.fn(),
}))

// 離機保管設定：本檔不驗離機面，mock 成「未設定」保持密封
// （SessionDetail 於 admin 身分下會讀一次設定表以判斷 `''` 態要不要渲染）
vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteSettings: vi.fn().mockResolvedValue({ configured: false }),
  retryOffsiteObject: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 's-1' } }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))

vi.mock('@/api/agentTasks', () => ({ getAgentToolCalls: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
import { getAgentToolCalls } from '@/api/agentTasks'
import ToolCallLedger from '@/components/agent/ToolCallLedger.vue'
import SessionDetail from '../SessionDetail.vue'

const baseSession = (over) => ({
  id: 1,
  session_id: 's-1',
  protocol: 'ssh',
  status: 'closed',
  end_reason: 'normal',
  client_ip: '127.0.0.1',
  start_time: '2026-07-20T08:00:00Z',
  end_time: '2026-07-20T08:10:00Z',
  duration: 600,
  has_recording: false,
  user: { username: 'u1' },
  asset: { name: 'a1', host: 'h', port: 22 },
  ...over,
})

const mountDetail = () =>
  mount(SessionDetail, { global: { plugins: [ElementPlus] } })


describe('會話帳本', () => {
  beforeEach(() => {
    getCommandsMock.mockReset().mockResolvedValue({ data: [] })
    searchAlertsMock.mockReset().mockResolvedValue({ data: [], total: 0 })
  })
  it('會話帳本只含該會話呼叫', async () => {
    getSessionMock.mockResolvedValue(baseSession({ id: 8, actor_kind: 'agent' })); const w = mountDetail(); await flushPromises()
    expect(getAgentToolCalls).not.toHaveBeenCalled(); w.vm.evidenceTab = 'ledger'; await flushPromises()
    expect(getAgentToolCalls).toHaveBeenCalledWith({ session_id: 8, offset: 0, limit: 20 })
    expect(w.getComponent(ToolCallLedger).props('showSession')).toBe(false)
    w.getComponent(ToolCallLedger).vm.changePage(2); await flushPromises()
    expect(getAgentToolCalls).toHaveBeenLastCalledWith({ session_id: 8, offset: 20, limit: 20 })
  })

  it('以會話與阻斷條件查詢，將阻斷指令併入時間序並標示規則', async () => {
    getSessionMock.mockResolvedValue(baseSession({ id: 118, has_recording: true }))
    getCommandsMock.mockResolvedValue({ data: [
      { id: 1, seq: 1, command: 'pwd', executed_at: '2026-07-20T08:00:10Z' },
      { id: 2, seq: 2, command: 'whoami', executed_at: '2026-07-20T08:00:30Z' },
    ] })
    searchAlertsMock.mockResolvedValue({ data: [
      { id: 9, rule_name: 'SSH 限制', command: 'ssh 10.0.0.9', triggered_at: '2026-07-20T08:00:20Z', blocked: true },
    ], total: 1 })
    const w = mountDetail()
    await flushPromises()
    expect(searchAlertsMock).toHaveBeenCalledWith({ session_id: 118, blocked: 'true' })
    expect(w.get('[data-test="blocked-command-row"]').text()).toContain('ssh 10.0.0.9')
    expect(w.get('[data-test="blocked-command-row"]').text()).toContain('SSH 限制')
    expect(w.get('[data-test="blocked-command-row"]').text()).toContain('已阻斷，未送往目標')
    const blockedRow = w.get('[data-test="blocked-command-row"]')
    expect(blockedRow.get('.blocked-command-title .ot-tag-neutral').text()).toBe('已阻斷，未送往目標')
    expect(blockedRow.get('.blocked-command-title .blocked-rule-name').text()).toBe('SSH 限制')
    expect(blockedRow.get('.blocked-command-action code').text()).toBe('ssh 10.0.0.9')
    expect(blockedRow.get('.blocked-command-action [data-test="blocked-command-seek"]').exists()).toBe(true)
    expect(w.get('[data-test="blocked-command-count"]').text()).toContain('1')
    expect(w.vm.commandTimeline.map(row => row.command)).toEqual(['pwd', 'ssh 10.0.0.9', 'whoami'])
    await w.get('[data-test="blocked-command-seek"]').trigger('click')
    expect(w.vm.manualOffsetSeconds).toBe(20)
  })

  it('無阻斷告警時不渲染空區塊', async () => {
    getSessionMock.mockResolvedValue(baseSession({ id: 119 }))
    getCommandsMock.mockResolvedValue({ data: [{ id: 1, seq: 1, command: 'pwd', executed_at: '2026-07-20T08:00:10Z' }] })
    const w = mountDetail()
    await flushPromises()
    expect(searchAlertsMock).toHaveBeenCalledWith({ session_id: 119, blocked: 'true' })
    expect(w.find('[data-test="blocked-command-row"]').exists()).toBe(false)
    expect(w.find('[data-test="blocked-command-count"]').exists()).toBe(false)
    expect(w.text()).toContain('pwd')
  })
})
