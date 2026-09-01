// 會話詳情的「離機保存」項（狀態行第二列）。
//
// 這一項回答的是「這份證據有沒有離開這台機器」，而稽核員會據此判斷「本機檔被
// 保留清理刪掉之後還播不播得出來」。因此守兩件事：
//   - **十態逐態各有自己的說法**：任何一態沒有文案，畫面上就是一個沒人看得懂的
//     標籤；`foreign` 尤其不得標成警示色（世代退役是管理員自己按的，物件仍取得回）。
//   - **不渲染的判準是帳冊零列**：停止離機後仍有帳冊列的會話照常
//     渲染，否則關閉之後的取回失敗無處可見，黑洞只是換個地方出現。
//     本頁拿不到全域帳冊列數（離機端點全為 admin），故判準收斂為「這一列自己有
//     帳冊態」或「admin 讀到設定表非空」——讀不到就不宣稱。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { OFFSITE_STATUS_VALUES } from '@/constants/offsite'

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

vi.mock('@/api/clipboardEvents', () => ({
  getSessionClipboardEvents: vi.fn().mockResolvedValue({ data: [] }),
  getClipboardEventContent: vi.fn(),
}))

const settingsMock = vi.fn()
const retryObjectMock = vi.fn()
vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteSettings: (...a) => settingsMock(...a),
  retryOffsiteObject: (...a) => retryObjectMock(...a),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 's-1' } }),
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
  recording_error: '',
  offsite_object_id: 31,
  offsite_status: 'uploaded',
  ...over,
})

const asAdmin = () =>
  localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['admin'] }))
const asAuditor = () =>
  localStorage.setItem('user', JSON.stringify({ id: 2, roles: ['auditor'] }))

const mountPage = async () => {
  const wrapper = mount(SessionDetail, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

const at = (wrapper, name) => wrapper.find(`[data-test="${name}"]`)

// el-tooltip 會在觸發元素外再包一層（happy-dom 下 data-test 落在那一層），
// 顏色斷言要看的是 el-tag 本身
const offsiteTag = (wrapper) => {
  const root = at(wrapper, 'offsite-status')
  if (!root.exists()) return root
  return root.classes().includes('el-tag') ? root : root.find('.el-tag')
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  getSessionMock.mockResolvedValue(baseSession())
  settingsMock.mockResolvedValue({ configured: true, disabled: false })
})

describe('十態各自的呈現', () => {
  // `''` 在對照表裡是「未排入」而不是缺欄；十態一個都不能少
  const CASES = [
    ['', '未排入', 'info'],
    ['pending', '待上傳', 'warning'],
    ['uploading', '上傳中', 'warning'],
    ['uploaded', '已離機保存', 'success'],
    ['failed', '上傳失敗', 'danger'],
    ['integrity_mismatch', '完整性不符', 'danger'],
    // 世代退役是管理員自己按下的動作，物件仍取得回來——不得染上警示色
    ['foreign', '舊儲存設定', 'info'],
    ['local_purged', '本機已清', 'info'],
    ['skipped_missing', '本機缺檔未回填', 'info'],
    ['skipped_expired', '逾保留未回填', 'info'],
  ]

  it('對照表涵蓋後端十態值域，缺一即紅', () => {
    expect(CASES.map(([s]) => s).sort()).toEqual([...OFFSITE_STATUS_VALUES].sort())
  })

  it.each(CASES)('狀態 %s 顯示為「%s」且 tag 走 %s', async (status, label, tagType) => {
    asAdmin()
    getSessionMock.mockResolvedValue(
      baseSession({ offsite_status: status, offsite_object_id: status === '' ? null : 31 })
    )
    const wrapper = await mountPage()

    const tag = offsiteTag(wrapper)
    expect(tag.exists()).toBe(true)
    expect(tag.text()).toBe(label)
    expect(tag.classes().join(' ')).toContain(`el-tag--${tagType}`)
  })

  it('未知狀態退回「未排入」而不顯示裸機器碼', async () => {
    asAdmin()
    getSessionMock.mockResolvedValue(baseSession({ offsite_status: 'brand_new_state' }))
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-status').text()).toBe('未排入')
  })
})

describe('渲染判準＝帳冊零列', () => {
  it('帳冊零列（設定表為空、該會話無帳冊態）：整項不渲染', async () => {
    asAdmin()
    settingsMock.mockResolvedValue({ configured: false })
    getSessionMock.mockResolvedValue(
      baseSession({ offsite_status: '', offsite_object_id: null })
    )
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-status').exists()).toBe(false)
  })

  it('已停止上傳但該會話有帳冊列：照常渲染', async () => {
    asAdmin()
    // 停用態＝有歷史世代、零現行世代；設定表非空
    settingsMock.mockResolvedValue({ configured: true, disabled: true })
    getSessionMock.mockResolvedValue(
      baseSession({ offsite_status: 'foreign', offsite_object_id: 31 })
    )
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-status').text()).toBe('舊儲存設定')
  })

  it('設定表讀不到時不宣稱：有帳冊態仍渲染，`` 則不渲染', async () => {
    asAdmin()
    settingsMock.mockRejectedValue(new Error('boom'))
    getSessionMock.mockResolvedValue(baseSession({ offsite_status: 'uploaded' }))
    const withRow = await mountPage()
    expect(at(withRow, 'offsite-status').exists()).toBe(true)

    getSessionMock.mockResolvedValue(
      baseSession({ offsite_status: '', offsite_object_id: null })
    )
    const withoutRow = await mountPage()
    expect(at(withoutRow, 'offsite-status').exists()).toBe(false)
  })

  it('非 admin 不讀離機設定端點（該端點僅 admin 可用）', async () => {
    asAuditor()
    getSessionMock.mockResolvedValue(baseSession({ offsite_status: 'uploaded' }))
    const wrapper = await mountPage()
    expect(settingsMock).not.toHaveBeenCalled()
    // 有帳冊態仍看得到狀態，只是少了重試入口
    expect(at(wrapper, 'offsite-status').exists()).toBe(true)
    expect(at(wrapper, 'offsite-retry').exists()).toBe(false)
  })
})

describe('重試入口', () => {
  it('admin 在失敗態看得到重試，呼叫單筆端點後重讀會話', async () => {
    asAdmin()
    getSessionMock.mockResolvedValue(baseSession({ offsite_status: 'failed' }))
    retryObjectMock.mockResolvedValue({ retried: 1 })
    const wrapper = await mountPage()

    const retry = at(wrapper, 'offsite-retry')
    expect(retry.exists()).toBe(true)
    await retry.trigger('click')
    await flushPromises()
    expect(retryObjectMock).toHaveBeenCalledWith(31)
    expect(getSessionMock).toHaveBeenCalledTimes(2)
  })

  it('完整性不符且本機已無檔：重試停用並說明原因', async () => {
    asAdmin()
    getSessionMock.mockResolvedValue(
      baseSession({ offsite_status: 'integrity_mismatch', has_recording: false })
    )
    const wrapper = await mountPage()

    expect(at(wrapper, 'offsite-retry').attributes('disabled')).toBeDefined()
    expect(at(wrapper, 'offsite-retry-hint').text()).toContain('無法重傳')
  })

  it('已上傳的正常態不提供重試', async () => {
    asAdmin()
    const wrapper = await mountPage()
    expect(at(wrapper, 'offsite-retry').exists()).toBe(false)
  })
})
