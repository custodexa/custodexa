// SessionDetail 的錄影失敗標示（backend-i18n-unification D8）：
// recording_error 自 M5 起存 cause code，tooltip 必須查譯而非顯裸碼。
// Sessions.vue 的三處同型 tooltip 另有 Sessions.spec.js 把關——本檔專守詳情頁。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
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

const tooltipContents = (wrapper) =>
  wrapper
    .findAllComponents({ name: 'ElTooltip' })
    .map((c) => c.props('content'))
    .filter(Boolean)

describe('SessionDetail 錄影失敗原因查譯', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('cause code 顯示詞庫短語，不漏出裸碼', async () => {
    getSessionMock.mockResolvedValue(
      baseSession({ recording_error: 'recording_file_missing' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    const contents = tooltipContents(wrapper)
    expect(contents.some((c) => c.includes('錄影檔缺失'))).toBe(true)
    expect(contents.some((c) => c.includes('recording_file_missing'))).toBe(false)
    wrapper.unmount()
  })

  it('存量散文（未碼化）原樣顯示，不吞資訊', async () => {
    getSessionMock.mockResolvedValue(
      baseSession({ recording_error: '啟動錄製失敗: 磁碟空間不足' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    expect(
      tooltipContents(wrapper).some((c) => c.includes('啟動錄製失敗: 磁碟空間不足'))
    ).toBe(true)
    wrapper.unmount()
  })
})
