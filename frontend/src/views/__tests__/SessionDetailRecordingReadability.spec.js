// 會話詳情依 recording_state 呈現錄影是否讀得到。
//
// 詳情回應帶 recording_state（available／missing／unreadable）與可讀時的
// recording_source；欄位缺席（舊後端或探測無法下結論）維持現行行為。
// 讀不到時：狀態標籤改口、下載鈕停用並附原因、播放器區換成說明區塊，
// 且不取錄影 token、不掛播放器。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'

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
const tokenMock = vi.fn()
const downloadMock = vi.fn()
vi.mock('@/api/sessions', () => ({
  getSession: (...a) => getSessionMock(...a),
  getRecordingUrl: (id) => `/api/v1/sessions/${id}/recording/stream`,
  getRecordingToken: (...a) => tokenMock(...a),
  recordingStreamUrlByToken: (tok) => `/api/v1/recordings/stream?rtoken=${tok}`,
  downloadRecording: (...a) => downloadMock(...a),
}))

vi.mock('@/api/commands', () => ({
  getSessionCommands: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/alerts', () => ({
  searchAlerts: vi.fn().mockResolvedValue({ data: [] }),
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
  useRoute: () => ({ params: { id: '172' }, query: {} }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    ElMessage: { error: vi.fn(), success: vi.fn(), warning: vi.fn() },
  }
})

import SessionDetail from '../SessionDetail.vue'

const baseSession = (over) => ({
  id: 172,
  session_id: 's-172',
  protocol: 'ssh',
  status: 'closed',
  end_reason: 'normal',
  client_ip: '10.20.1.15',
  start_time: '2026-10-12T10:46:39Z',
  end_time: '2026-10-12T11:02:11Z',
  duration: 932,
  has_recording: true,
  recording_error: '',
  offsite_status: '',
  ...over,
})

const mountPage = async () => {
  const wrapper = mount(SessionDetail, {
    global: {
      plugins: [ElementPlus],
      stubs: { AsciinemaPlayer: true, GuacamolePlayer: true },
    },
  })
  await flushPromises()
  return wrapper
}

const at = (wrapper, name) => wrapper.find(`[data-test="${name}"]`)
const downloadButton = (wrapper) => at(wrapper, 'recording-download-button')

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  tokenMock.mockResolvedValue({ token: 'tok' })
})

describe('詳情頁依 recording_state 呈現', () => {
  const CASES = [
    // [案名, 回應欄位, 標籤文字, 下載鈕停用, 掛播放器, 取 token]
    ['available', { recording_state: 'available', recording_source: 'local' }, '有錄影', false, true, true],
    ['available＋offsite', { recording_state: 'available', recording_source: 'offsite' }, '有錄影', false, true, true],
    ['unreadable', { recording_state: 'unreadable' }, '錄影檔無法讀取', true, false, false],
    ['missing', { recording_state: 'missing' }, '錄影檔不存在', true, false, false],
    ['欄位缺席（舊後端）', {}, '有錄影', false, true, true],
  ]

  it.each(CASES)('%s', async (_name, fields, label, disabled, playerMounted, tokenCalled) => {
    getSessionMock.mockResolvedValue(baseSession(fields))
    const wrapper = await mountPage()

    expect(at(wrapper, 'recording-status-tag').text()).toContain(label)
    if (label !== '有錄影') {
      expect(wrapper.text()).not.toContain('有錄影')
    }

    const btn = downloadButton(wrapper)
    expect(btn.exists()).toBe(true)
    expect(btn.attributes('disabled') !== undefined).toBe(disabled)

    expect(wrapper.findComponent({ name: 'AsciinemaPlayer' }).exists()).toBe(playerMounted)
    expect(at(wrapper, 'recording-unavailable').exists()).toBe(!playerMounted)
    expect(tokenMock).toHaveBeenCalledTimes(tokenCalled ? 1 : 0)
  })

  it('可讀但來源為離機：標籤維持「有錄影」並附取回提示', async () => {
    getSessionMock.mockResolvedValue(baseSession({ recording_state: 'available', recording_source: 'offsite' }))
    const wrapper = await mountPage()
    expect(at(wrapper, 'recording-offsite-hint').text()).toBe(
      '錄影存放在離機保存處，播放與下載前要先取回，可能需要較久。'
    )
  })

  it('無法讀取：說明區塊有主句與下一步，機器碼收在第二層', async () => {
    getSessionMock.mockResolvedValue(baseSession({ recording_state: 'unreadable' }))
    const wrapper = await mountPage()
    const card = at(wrapper, 'recording-unavailable')
    expect(card.text()).toContain('目前讀不到這場連線的錄影檔')
    expect(card.text()).toContain('下一步：請系統管理員檢查錄影儲存位置的權限。')
    const shown = () => !String(at(wrapper, 'recording-admin-detail').attributes('style') || '').includes('display: none')
    expect(shown()).toBe(false)
    await at(wrapper, 'recording-admin-toggle').trigger('click')
    expect(shown()).toBe(true)
    expect(at(wrapper, 'recording-admin-detail').text()).toContain('INTERNAL_RECORDING_FILE_UNREADABLE')
    expect(at(wrapper, 'recording-admin-detail').text()).toContain('172')
  })

  it('停用原因可由鍵盤聚焦取得（外層可聚焦且以 aria-describedby 指向原因）', async () => {
    getSessionMock.mockResolvedValue(baseSession({ recording_state: 'missing' }))
    const wrapper = await mountPage()
    const holder = at(wrapper, 'recording-download-blocked')
    expect(holder.attributes('tabindex')).toBe('0')
    const reasonId = holder.attributes('aria-describedby')
    expect(reasonId).toBeTruthy()
    expect(wrapper.find(`[id="${reasonId}"]`).text()).toBe('錄影檔已不在儲存位置，無法下載。')
    // 鍵盤聚焦即顯示提示框（不只靠滑過）
    await holder.trigger('focus')
    await flushPromises()
    const tip = [...document.body.querySelectorAll('.el-popper')].map((n) => n.textContent).join('')
    expect(tip).toContain('錄影檔已不在儲存位置，無法下載。')
    // 停用鈕不用主色
    expect(downloadButton(wrapper).classes()).not.toContain('el-button--primary')
  })
})

describe('下載失敗依機器碼呈現', () => {
  it('500 blob 本體 INTERNAL_RECORDING_FILE_UNREADABLE → 對應文案', async () => {
    getSessionMock.mockResolvedValue(baseSession({ recording_state: 'available', recording_source: 'local' }))
    downloadMock.mockRejectedValue({
      response: {
        status: 500,
        data: new Blob([JSON.stringify({ code: 'INTERNAL_RECORDING_FILE_UNREADABLE' })], { type: 'application/json' }),
      },
    })
    const wrapper = await mountPage()
    await downloadButton(wrapper).trigger('click')
    await flushPromises()

    expect(downloadMock).toHaveBeenCalledTimes(1)
    expect(ElMessage.error).toHaveBeenCalledWith(
      '下載失敗：目前讀不到錄影檔，請系統管理員檢查錄影儲存位置的權限。'
    )
  })
})
