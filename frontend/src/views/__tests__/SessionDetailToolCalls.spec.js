// SessionDetail 的錄影失敗標示：
// recording_error 存的是 cause code，tooltip 必須查譯而非顯裸碼。
// Sessions.vue 的三處同型 tooltip 另有 Sessions.spec.js 把關——本檔專守詳情頁。
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
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

vi.mock('@/api/sessions', () => ({
  getSession: (...a) => getSessionMock(...a),
  getRecordingUrl: () => '',
  getRecordingToken: vi.fn().mockResolvedValue({ token: 't' }),
  recordingStreamUrlByToken: () => '',
  downloadRecording: vi.fn(),
}))

vi.mock('@/api/commands', () => ({
  getSessionCommands: vi.fn().mockResolvedValue({ data: [] }),
}))

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
  it('會話帳本只含該會話呼叫', async () => {
    getSessionMock.mockResolvedValue(baseSession({ id: 8, actor_kind: 'agent' })); const w = mountDetail(); await flushPromises()
    expect(getAgentToolCalls).not.toHaveBeenCalled(); w.vm.evidenceTab = 'ledger'; await flushPromises()
    expect(getAgentToolCalls).toHaveBeenCalledWith({ session_id: 8, offset: 0, limit: 20 })
    expect(w.getComponent(ToolCallLedger).props('showSession')).toBe(false)
    w.getComponent(ToolCallLedger).vm.changePage(2); await flushPromises()
    expect(getAgentToolCalls).toHaveBeenLastCalledWith({ session_id: 8, offset: 20, limit: 20 })
  })
})
