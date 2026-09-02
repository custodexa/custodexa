// SessionDetail 對查詢主控台會話的呈現。
//
// 守三件事：
//   1. **結果欄位只在主控台會話出現**。命令列會話這幾欄恆空，渲染出來只會
//      讓稽核員以為系統漏記了。
//   2. **已結束會話上的 `running` 不得讀成「執行中」**。那是結果沒有回填，
//      是要人去查的狀態，照字面顯示等於把「不知道」講成「還在跑」。
//   3. **`#cmd-<event_id>` 深連結真的定得到位**。主控台的「結果未知」橫幅
//      指回這一列，定位落空就等於那條路徑不存在。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

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
const getSessionCommandsMock = vi.fn()
const routeHash = { value: '' }

vi.mock('@/api/sessions', () => ({
  getSession: (...a) => getSessionMock(...a),
  getRecordingUrl: () => '/rec',
  getRecordingToken: vi.fn().mockResolvedValue({ token: 't' }),
  recordingStreamUrlByToken: () => '/rec-token',
  downloadRecording: vi.fn(),
}))

vi.mock('@/api/commands', () => ({
  getSessionCommands: (...a) => getSessionCommandsMock(...a),
}))

vi.mock('@/api/clipboardEvents', () => ({
  getSessionClipboardEvents: vi.fn().mockResolvedValue({ data: [] }),
  getClipboardEventContent: vi.fn(),
}))

vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteSettings: vi.fn().mockResolvedValue({ configured: false }),
  retryOffsiteObject: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 's-1' }, query: {}, hash: routeHash.value }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))

vi.mock('@/components/AsciinemaPlayer.vue', () => ({
  default: {
    name: 'AsciinemaPlayer',
    props: ['recordingUrl', 'autoPlay', 'startAt'],
    emits: ['start-at-applied'],
    template: '<div data-test="ascii-player" />',
  },
}))

vi.mock('@/components/GuacamolePlayer.vue', () => ({
  default: {
    name: 'GuacamolePlayer',
    props: ['recordingUrl', 'autoPlay', 'startAt'],
    emits: ['start-at-applied'],
    template: '<div data-test="guac-player" />',
  },
}))

import SessionDetail from '../SessionDetail.vue'

const baseSession = (over) => ({
  id: 1,
  session_id: 's-1',
  protocol: 'mysql',
  status: 'closed',
  end_reason: 'normal',
  client_ip: '127.0.0.1',
  start_time: '2026-08-26T08:00:00Z',
  end_time: '2026-08-26T08:10:00Z',
  duration: 600,
  has_recording: true,
  db_console: true,
  user: { username: 'u1' },
  asset: { name: 'mysql-a', host: 'h', port: 3306 },
  ...over,
})

const CONSOLE_COMMANDS = [
  {
    id: 1,
    seq: 1,
    command: 'SELECT * FROM orders',
    executed_at: '2026-08-26T08:01:00Z',
    event_id: '01JBQEVENT0000000000000001',
    target_database: 'app',
    result_status: 'ok',
    result_rows: 42,
    duration_ms: 17,
  },
  {
    id: 2,
    seq: 2,
    command: 'UPDATE orders SET paid = 1',
    executed_at: '2026-08-26T08:02:00Z',
    event_id: '01JBQEVENT0000000000000002',
    target_database: 'app',
    result_status: 'running',
  },
  {
    id: 3,
    seq: 3,
    command: 'DELETE FROM orders WHERE id = 9',
    executed_at: '2026-08-26T08:03:00Z',
    event_id: '01JBQEVENT0000000000000003',
    target_database: 'app',
    result_status: 'partial',
    result_reason: 'error_after_results',
    rows_affected: 3,
    duration_ms: 220,
  },
]

const mountDetail = () => mount(SessionDetail, { global: { plugins: [ElementPlus] } })

beforeEach(() => {
  vi.clearAllMocks()
  routeHash.value = ''
  getSessionCommandsMock.mockResolvedValue({ data: CONSOLE_COMMANDS })
})

describe('SessionDetail 主控台會話的結果事實', () => {
  it('主控台會話渲染結果欄位並標示轉錄形態', async () => {
    getSessionMock.mockResolvedValue(baseSession())
    const wrapper = mountDetail()
    await flushPromises()

    const headers = wrapper.text()
    expect(headers).toContain('目標資料庫')
    expect(headers).toContain('結果狀態')
    expect(headers).toContain('事件識別')
    expect(wrapper.findAll('[data-test="event-id"]').length).toBe(3)

    // 錄影是轉錄，不含結果資料——這一句是稽核判讀的前提
    const note = wrapper.find('[data-test="console-recording-note"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toContain('不含結果資料')

    // 完成列的列數與耗時照實顯示
    expect(headers).toContain('42')
    expect(headers).toContain('17 毫秒')
    // 寫入列改以影響列數呈現（與查詢回傳列數互斥）
    expect(headers).toContain('影響 3 列')
  })

  it('命令列會話不渲染結果欄位與轉錄提示', async () => {
    getSessionMock.mockResolvedValue(baseSession({ protocol: 'ssh', db_console: false }))
    getSessionCommandsMock.mockResolvedValue({
      data: [{ id: 1, seq: 1, command: 'ls -al', executed_at: '2026-08-26T08:01:00Z' }],
    })
    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="console-recording-note"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-test="event-id"]').length).toBe(0)
    expect(wrapper.text()).not.toContain('目標資料庫')
  })

  it('已結束會話上的 running 顯示為結果未知，不顯示成執行中', async () => {
    getSessionMock.mockResolvedValue(baseSession())
    const wrapper = mountDetail()
    await flushPromises()

    const statuses = wrapper.findAll('[data-test="result-status"]').map((n) => n.text())
    expect(statuses).toContain('結果未知（未回填）')
    expect(statuses).not.toContain('進行中')
    // 要人去查的狀態不得呈現為成功或失敗
    const unsettledTag = wrapper
      .findAllComponents({ name: 'ElTag' })
      .find((c) => c.text() === '結果未知（未回填）')
    expect(unsettledTag.props('type')).toBe('warning')
  })

  it('進行中會話上的 running 維持執行中語義（判準是會話已結束，不是狀態值）', async () => {
    getSessionMock.mockResolvedValue(baseSession({ status: 'active', end_time: null }))
    const wrapper = mountDetail()
    await flushPromises()

    const statuses = wrapper.findAll('[data-test="result-status"]').map((n) => n.text())
    expect(statuses).not.toContain('結果未知（未回填）')
    expect(statuses).toContain('進行中')
  })

  it('#cmd-<event_id> 深連結定位到該列並標示落點', async () => {
    routeHash.value = '#cmd-01JBQEVENT0000000000000002'
    const scrollSpy = vi.fn()
    const original = window.HTMLElement.prototype.scrollIntoView
    window.HTMLElement.prototype.scrollIntoView = scrollSpy
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.vm.anchoredEventId).toBe('01JBQEVENT0000000000000002')
    const anchored = wrapper.findAll('[data-test="event-id"]')
      .filter((n) => n.classes().includes('is-anchored'))
    expect(anchored).toHaveLength(1)
    expect(anchored[0].text()).toBe('01JBQEVENT0000000000000002')
    expect(scrollSpy).toHaveBeenCalled()

    window.HTMLElement.prototype.scrollIntoView = original
  })

  it('hash 指向不存在的事件時不標示落點（不假裝找到了）', async () => {
    routeHash.value = '#cmd-01JBQEVENTNOTPRESENT000000'
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.vm.anchoredEventId).toBe('')
    expect(
      wrapper.findAll('[data-test="event-id"]').filter((n) => n.classes().includes('is-anchored'))
    ).toHaveLength(0)
  })
})
