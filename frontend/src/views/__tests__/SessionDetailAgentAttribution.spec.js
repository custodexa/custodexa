import i18n from '@/i18n'
// SessionDetail 的錄影失敗標示：
// recording_error 存的是 cause code，tooltip 必須查譯而非顯裸碼。
// Sessions.vue 的三處同型 tooltip 另有 Sessions.spec.js 把關——本檔專守詳情頁。
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { formatDateTime } from '@/utils/format'

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

describe('會話歸屬快照', () => {
  const agent = (extra = {}) => baseSession({ user_id: 5, actor_kind: 'agent', owner_user_id: 2, owner_username: 'owner-a', on_behalf_of_user_id: 7, on_behalf_of_username: 'human-7', agent_token_id: 8, access_request_id: 23, user: { username: 'agent-5', owner_user_id: 999 }, ...extra })
  it('輔助模式呈現代表人', async () => {
    getSessionMock.mockResolvedValue(agent()); const w = mountDetail(); await flushPromises()
    expect(w.get('[data-test="represented-user"]').text()).toBe('human-7')
    expect(w.get('[data-test="agent-attribution"]').text()).toContain('AI agent')
  })
  // 契約有名稱時一律顯示名稱：只寫識別碼的欄位讀者答不出「這是誰」
  it('名稱未投影時退回「未提供」而非裸識別碼', async () => {
    getSessionMock.mockResolvedValue(agent({ on_behalf_of_username: '', owner_username: '' })); const w = mountDetail(); await flushPromises()
    expect(w.get('[data-test="represented-user"]').text()).toBe('未提供')
    expect(w.get('[data-test="snapshot-owner"]').text()).toBe('未提供')
    expect(w.get('[data-test="agent-attribution"]').text()).not.toContain('#7')
  })
  it('自主模式明示無代表人而非留白', async () => {
    getSessionMock.mockResolvedValue(agent({ on_behalf_of_user_id: null, on_behalf_of_username: '' })); const w = mountDetail(); await flushPromises()
    expect(w.get('[data-test="represented-user"]').text()).toBe('無代表人（自主執行）')
  })
  it('標明為當時快照', async () => {
    getSessionMock.mockResolvedValue(agent()); const w = mountDetail(); await flushPromises()
    const text = w.get('[data-test="agent-attribution"]').text()
    expect(text).toContain('連線建立當時的主體快照'); expect(w.get('[data-test="snapshot-owner"]').text()).toBe('owner-a')
    expect(text).toContain('agent-5'); expect(text).not.toContain('#999')
    expect(text).toContain('鑰匙編號 8；名稱快照未提供')
  })
  it('撤權後仍活動於列表與詳情皆可見', async () => {
    getSessionMock.mockResolvedValue(agent({ status: 'active', revoked_during_session_at: '2026-09-22T01:00:00Z' })); const w = mountDetail(); await flushPromises()
    expect(w.get('[data-test="session-revocation"]').text()).toContain('授權撤銷，連線中斷')
    expect(w.get('[data-test="session-revocation"]').text()).toContain(formatDateTime('2026-09-22T01:00:00Z'))
  })
})

it('token 名稱只讀會話快照', async () => {
  getSessionMock.mockResolvedValue(baseSession({ user_id: 5, actor_kind: 'agent', owner_user_id: 2, agent_token_id: 8, agent_token_name: 'issued-name', user: { token_name: 'current-name' } }))
  const w = mountDetail(); await flushPromises()
  expect(w.get('[data-test="agent-attribution"]').text()).toContain('issued-name')
  expect(w.get('[data-test="agent-attribution"]').text()).not.toContain('current-name')
})

it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 4 三語 DOM：五欄快照與帳本分頁 %s', async locale => { i18n.global.locale.value = locale; getSessionMock.mockResolvedValue(baseSession({ id: 8, user_id: 5, actor_kind: 'agent', owner_user_id: 2, agent_token_name: 'issued', access_request_id: 23 })); const w = mountDetail(); await flushPromises(); expect(w.get('[data-test="agent-attribution"]').findAll('dt')).toHaveLength(5); expect(w.find('[data-test="session-evidence-tabs"]').exists()).toBe(true); expect(w.text()).not.toMatch(/agentSession\.|agentTasks\.|sessionDetail\./) })
