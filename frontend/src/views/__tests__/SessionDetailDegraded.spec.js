// 會話詳情頁的降級列呈現與「下一步」（tasks 2.6）。
//
// 守三件事：
//   1. 降級列是**明確的狀態列**，不是空白格——空白會被讀成「按了 Enter 但沒打字」。
//   2. 下一步真的把回放定位到那一輪的時刻（沿用既有的錄影／會話起點差校正）。
//   3. 沒有錄影時**不得**說「錄影可能保留該時段畫面」，也不擺一顆點了會落空的按鈕。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import zhTW from '@/i18n/locales/zh-TW.json'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getSessionMock = vi.fn()
const getSessionCommandsMock = vi.fn()
const routeQuery = { value: {} }

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

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 's-1' }, query: routeQuery.value }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))

// 播放器以 stub 取代：本檔守的是父層算出的定位秒數，不是播放器自身的 seek 行為
vi.mock('@/components/AsciinemaPlayer.vue', () => ({
  default: {
    name: 'AsciinemaPlayer',
    props: ['recordingUrl', 'autoPlay', 'startAt'],
    emits: ['start-at-applied'],
    template: '<div data-test="ascii-player" :data-start-at="String(startAt)" />',
  },
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
  has_recording: true,
  recording_started_at: '2026-07-20T08:00:05Z',
  user: { username: 'u1' },
  asset: { name: 'a1', host: 'h', port: 22 },
  ...over,
})

const commandRows = [
  {
    id: 1,
    seq: 1,
    command: 'vim /etc/hosts',
    executed_at: '2026-07-20T08:01:00Z',
    degraded: false,
    degrade_reason: '',
  },
  {
    id: 2,
    seq: 2,
    command: '',
    executed_at: '2026-07-20T08:02:05Z',
    degraded: true,
    degrade_reason: 'altscreen_round',
  },
]

const mountDetail = () => mount(SessionDetail, { global: { plugins: [ElementPlus] } })

beforeEach(() => {
  vi.clearAllMocks()
  routeQuery.value = {}
  getSessionCommandsMock.mockResolvedValue({ data: commandRows })
})

describe('SessionDetail 降級列呈現', () => {
  it('降級列渲染成狀態列＋原因，絕不留空字串或看起來像空指令的符號', async () => {
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    const cell = wrapper.find('[data-test="degraded-command"]')
    expect(cell.exists()).toBe(true)
    expect(cell.text()).toContain(zhTW.commands.degrade.title)
    expect(cell.text()).toContain(zhTW.enum.commandDegrade.altscreen_round)
    expect(cell.text().trim()).not.toBe('-')
    for (const forbidden of ['(空)', '解析失敗', '系統錯誤']) {
      expect(cell.text()).not.toContain(forbidden)
    }
    // 一般列照舊
    expect(wrapper.text()).toContain('vim /etc/hosts')
  })

  it('無法還原的輪數與指令總數分開計（總數不得看起來像「N 筆都有內容」）', async () => {
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    const tag = wrapper.find('[data-test="degraded-count"]')
    expect(tag.exists()).toBe(true)
    expect(tag.text()).toContain('1')
  })

  it('有錄影時給「查看該時段錄影」，且文案是「可能保留」', async () => {
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="degraded-seek"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="degraded-recording-hint"]').text()).toBe(
      zhTW.commands.degrade.recordingMaybe
    )
  })

  it('沒有錄影時據實改口，且不擺一顆點了會落空的按鈕', async () => {
    getSessionMock.mockResolvedValue(baseSession({ has_recording: false }))

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="degraded-recording-hint"]').text()).toBe(
      zhTW.commands.degrade.recordingUnavailable
    )
    expect(wrapper.find('[data-test="degraded-seek"]').exists()).toBe(false)
  })

  it('回顯關閉類不沿用「錄影可能保留」（那一類連錄影都救不回）', async () => {
    getSessionMock.mockResolvedValue(baseSession())
    getSessionCommandsMock.mockResolvedValue({
      data: [{ ...commandRows[1], degrade_reason: 'input_without_echo' }],
    })

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="degraded-recording-hint"]').text()).toBe(
      zhTW.commands.degrade.recordingNoEcho
    )
  })
})

describe('SessionDetail 降級列的下一步（定位回放）', () => {
  it('點「查看該時段錄影」把播放器定位到該輪時刻（含錄影／會話起點差校正）', async () => {
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('null')

    await wrapper.find('[data-test="degraded-seek"]').trigger('click')
    await flushPromises()

    // 08:02:05 − 08:00:00 = 125 秒；錄影晚 5 秒 → 120
    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('120')
    // 定位提示同步出現（做不到時也要有結果，不靜默）
    expect(wrapper.find('[data-test="seek-notice"]').exists()).toBe(true)
  })

  it('由跨會話頁帶絕對時刻 ?at= 進來時，換算與 ?t= 同一條式子', async () => {
    routeQuery.value = { at: '2026-07-20T08:02:05Z' }
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('120')
  })

  it('?at= 非法時明說，不靜默忽略（靜默＝稽核以為畫面上就是那一刻）', async () => {
    routeQuery.value = { at: 'not-a-timestamp' }
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="seek-notice"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('null')
  })

  it('?t= 與 ?at= 並存時以 ?t= 為準（行為固定，不看參數順序）', async () => {
    routeQuery.value = { t: '65', at: '2026-07-20T08:02:05Z' }
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('60')
  })
})
