// SessionDetail 消費工作台帶來的回放錨點 ?t=。
//
// 守兩件事：
//   1. **時間基準換算**。工作台的 t 是「事件時刻 − 會話 StartTime」，但回放的
//      elapsed=0 是錄影起點。正確落點 p = t − (recording_started_at − start_time)；
//      直接 seek(t) 的誤差恆等於那個差：文字終端錄影**晚**於建檔（差為正）→ 落點
//      偏晚、衝過目標指令（危險側，且隨認證耗時放大）；圖形 guacd 握手**早**於建檔
//      （差為負）→ 落點偏早。本檔以兩個相反符號的案例把換算式釘住。
//   2. **做不到時誠實**。無錄影／無播放器協議／參數非法／越界，各自給出明說，
//      SHALL NOT 靜默忽略（靜默＝稽核以為畫面上就是那一刻）。
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
const routeQuery = { value: {} }

vi.mock('@/api/sessions', () => ({
  getSession: (...a) => getSessionMock(...a),
  getRecordingUrl: () => '/rec',
  getRecordingToken: vi.fn().mockResolvedValue({ token: 't' }),
  recordingStreamUrlByToken: () => '/rec-token',
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
  useRoute: () => ({ params: { id: 's-1' }, query: routeQuery.value }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))

// 播放器以 stub 取代：本檔守的是「父層算出的定位秒數與提示」，
// 播放器自身的 seek 行為由 AsciinemaPlayerStartAt／GuacamolePlayerStartAt 兩支守
vi.mock('@/components/AsciinemaPlayer.vue', () => ({
  default: {
    name: 'AsciinemaPlayer',
    props: ['recordingUrl', 'autoPlay', 'startAt'],
    emits: ['start-at-applied'],
    template: '<div data-test="ascii-player" :data-start-at="String(startAt)" />',
  },
}))

vi.mock('@/components/GuacamolePlayer.vue', () => ({
  default: {
    name: 'GuacamolePlayer',
    props: ['recordingUrl', 'autoPlay', 'startAt'],
    emits: ['start-at-applied'],
    template: '<div data-test="guac-player" :data-start-at="String(startAt)" />',
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
  user: { username: 'u1' },
  asset: { name: 'a1', host: 'h', port: 22 },
  ...over,
})

const mountDetail = () => mount(SessionDetail, { global: { plugins: [ElementPlus] } })

const notice = (wrapper) => wrapper.find('[data-test="seek-notice"]')

beforeEach(() => {
  vi.clearAllMocks()
  routeQuery.value = {}
})

describe('SessionDetail 回放錨點的時間基準換算', () => {
  it('文字終端：錄影晚於建檔 5 秒 → 扣掉那 5 秒（未扣就會衝過目標指令）', async () => {
    routeQuery.value = { t: '125' }
    getSessionMock.mockResolvedValue(
      baseSession({ recording_started_at: '2026-07-20T08:00:05Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('120')
  })

  it('圖形：guacd 握手早於建檔 3 秒 → 加回那 3 秒（符號相反，同一條換算式）', async () => {
    routeQuery.value = { t: '125' }
    getSessionMock.mockResolvedValue(
      baseSession({
        protocol: 'rdp',
        recording_started_at: '2026-07-20T07:59:57Z',
      })
    )

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="guac-player"]').attributes('data-start-at')).toBe('128')
  })

  it('缺 recording_started_at（存量資料）：退回未校正值並在提示中明說', async () => {
    routeQuery.value = { t: '125' }
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('125')
    expect(wrapper.find('[data-test="seek-detail"]').text()).toContain('存量資料')
  })

  it('換算後為負一律夾到 0，不傳負秒數給播放器', async () => {
    routeQuery.value = { t: '1' }
    getSessionMock.mockResolvedValue(
      baseSession({ recording_started_at: '2026-07-20T08:00:30Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('0')
  })
})

describe('SessionDetail 回放錨點的誠實處理', () => {
  it('未帶 t 時不顯示任何定位提示，也不傳定位秒數', async () => {
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(notice(wrapper).exists()).toBe(false)
    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('null')
  })

  it('t 非數字：明示忽略，且不把非法值傳進播放器', async () => {
    routeQuery.value = { t: 'abc' }
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(notice(wrapper).text()).toContain('無效')
    expect(wrapper.find('[data-test="ascii-player"]').attributes('data-start-at')).toBe('null')
  })

  it('t 為負值：同樣視為非法而非夾成 0', async () => {
    routeQuery.value = { t: '-5' }
    getSessionMock.mockResolvedValue(baseSession())

    const wrapper = mountDetail()
    await flushPromises()

    expect(notice(wrapper).text()).toContain('無效')
  })

  it('無錄影：明說無法定位，不假裝定位成功', async () => {
    routeQuery.value = { t: '30' }
    getSessionMock.mockResolvedValue(baseSession({ has_recording: false }))

    const wrapper = mountDetail()
    await flushPromises()

    expect(notice(wrapper).text()).toContain('沒有錄影內容')
  })

  it('無播放器協議：明說此協議無回放，仍不靜默忽略參數', async () => {
    routeQuery.value = { t: '30' }
    getSessionMock.mockResolvedValue(baseSession({ protocol: 'telnet' }))

    const wrapper = mountDetail()
    await flushPromises()

    const text = notice(wrapper).text()
    expect(text).toContain('無錄影回放')
    expect(text).toContain('TELNET')
    expect(wrapper.find('[data-test="ascii-player"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="guac-player"]').exists()).toBe(false)
  })

  it('播放器回報越界：顯示「不在錄影涵蓋範圍內」而非宣稱已定位', async () => {
    routeQuery.value = { t: '5000' }
    getSessionMock.mockResolvedValue(
      baseSession({ recording_started_at: '2026-07-20T08:00:00Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    await wrapper
      .findComponent({ name: 'AsciinemaPlayer' })
      .vm.$emit('start-at-applied', { requested: 5000, applied: 600, clamped: true, duration: 600 })
    await flushPromises()

    expect(notice(wrapper).text()).toContain('不在錄影涵蓋範圍內')
  })

  // 5.4 FAIL 的修復守衛（父層側）。
  // 播放器回報的 `applied` 是**實際落點**；它與請求值的差在稀疏幀錄影下可達數十秒
  // （實測 session-33 的 `?t=10` 原本落在 30.574s）。偏差本身不是缺陷，**看不見才是**。
  // 涵蓋邊界：本檔以直接 emit payload 的方式釘住「畫面顯示的是實際落點」與
  // 「偏差可見且分得出方向」；**真實播放器落在哪一秒只能由瀏覽器實測覆蓋**。
  it('畫面顯示的時刻取自播放器實際落點，不是請求值', async () => {
    routeQuery.value = { t: '10' }
    getSessionMock.mockResolvedValue(
      baseSession({ protocol: 'rdp', recording_started_at: '2026-07-20T08:00:00Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    await wrapper
      .findComponent({ name: 'GuacamolePlayer' })
      .vm.$emit('start-at-applied', { requested: 10, applied: 4.034, clamped: false, duration: 30.574 })
    await flushPromises()

    const text = notice(wrapper).text()
    expect(text).toContain('00:04') // 實際落點 4.034s
    expect(text).not.toContain('00:10') // 不得顯示請求值
  })

  it('落點在目標之前且偏差達 1 秒：提示看得見且說得出方向', async () => {
    routeQuery.value = { t: '10' }
    getSessionMock.mockResolvedValue(
      baseSession({ protocol: 'rdp', recording_started_at: '2026-07-20T08:00:00Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    await wrapper
      .findComponent({ name: 'GuacamolePlayer' })
      .vm.$emit('start-at-applied', { requested: 10, applied: 4.034, clamped: false, duration: 30.574 })
    await flushPromises()

    const detail = wrapper.find('[data-test="seek-detail"]').text()
    expect(detail).toContain('之前')
    expect(detail).toContain('6')
    // 之前一側只是提示，不升級為警示（type 由 el-alert 的 modifier class 反映）
    expect(wrapper.find('[data-test="seek-notice"] .el-alert--success').exists()).toBe(true)
  })

  it('落點在目標之後：升為警示並明說該筆紀錄可能已在畫面之前發生', async () => {
    routeQuery.value = { t: '10' }
    getSessionMock.mockResolvedValue(
      baseSession({ protocol: 'rdp', recording_started_at: '2026-07-20T08:00:00Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    // 落在目標之後＝目標事件可能已經播過去（原 FAIL 的形態）
    await wrapper
      .findComponent({ name: 'GuacamolePlayer' })
      .vm.$emit('start-at-applied', { requested: 10, applied: 30.574, clamped: false, duration: 30.574 })
    await flushPromises()

    const detail = wrapper.find('[data-test="seek-detail"]').text()
    expect(detail).toContain('之後')
    expect(detail).toContain('20.6')
    expect(detail).toContain('請往前檢視')
    expect(wrapper.find('[data-test="seek-notice"] .el-alert--warning').exists()).toBe(true)
  })

  it('偏差小於 1 秒（畫面上分辨不出）不加雜訊', async () => {
    routeQuery.value = { t: '11' }
    getSessionMock.mockResolvedValue(
      baseSession({ recording_started_at: '2026-07-20T08:00:00Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    await wrapper
      .findComponent({ name: 'AsciinemaPlayer' })
      .vm.$emit('start-at-applied', { requested: 11, applied: 11.004, clamped: false, duration: 600 })
    await flushPromises()

    expect(wrapper.find('[data-test="seek-detail"]').exists()).toBe(false)
  })

  it('定位成功的文案只說「前後」，不得宣稱精確', async () => {
    routeQuery.value = { t: '125' }
    getSessionMock.mockResolvedValue(
      baseSession({ recording_started_at: '2026-07-20T08:00:05Z' })
    )

    const wrapper = mountDetail()
    await flushPromises()

    await wrapper
      .findComponent({ name: 'AsciinemaPlayer' })
      .vm.$emit('start-at-applied', { requested: 120, applied: 120, clamped: false, duration: 600 })
    await flushPromises()

    const text = notice(wrapper).text()
    expect(text).toContain('前後')
    expect(text).toContain('02:00')
    expect(text).not.toContain('精確')
    expect(text).not.toContain('那一刻')
  })
})
