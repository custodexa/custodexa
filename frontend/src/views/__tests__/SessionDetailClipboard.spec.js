// SessionDetail 剪貼簿調閱面：列表只給事實，
// 按鍵才解密。
//
// 守六件事：
//   1. **列表只給事實**：載入列表不觸發單筆內容端點（沒按鍵＝未解密＝不留
//      逐筆調閱痕）；
//   2. **顯式解密才呼端點**：可調閱列給鎖頭＋「解密調閱」鍵，按鍵才呼單筆
//      端點，內容以等寬 <pre> 呈現。**展開列本身不發請求**——早期版本是展開即
//      直載，內容一冒出來讀起來就像本來就是明文躺著，稽核員感受不到自己剛
//      做了一次受控解密；
//   3. **留痕回饋**：內容之上一行「本次調閱已留存紀錄（時分秒）」——解密與
//      留痕要同時進眼，否則留痕這件事對使用者等於不存在；
//   4. **缺口誠實呈現**：content_status=failed 的列標示「內容留存失敗」、
//      不給解密鍵，展開給失敗說明而非呼端點——內容不存在，呼了只會留下
//      「交付了空無」的審計紀錄；
//   5. **無事件不渲染整卡**：空殼卡會讓「沒有剪貼簿流量」看起來像功能壞掉；
//   6. **#clipboard 錨點**：時間軸一鍵抵達的接收端——資料就緒後捲動至卡。
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
const getClipboardEventsMock = vi.fn()
const getClipboardContentMock = vi.fn()
const routeState = { query: {}, hash: '' }

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
  getSessionClipboardEvents: (...a) => getClipboardEventsMock(...a),
  getClipboardEventContent: (...a) => getClipboardContentMock(...a),
}))

// 離機保管設定：本檔不驗離機面，mock 成「未設定」保持密封
// （SessionDetail 於 admin 身分下會讀一次設定表以判斷 `''` 態要不要渲染）
vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteSettings: vi.fn().mockResolvedValue({ configured: false }),
  retryOffsiteObject: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({
    params: { id: 's-1' },
    query: routeState.query,
    hash: routeState.hash,
  }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))

import SessionDetail from '../SessionDetail.vue'

// RDP 會話（剪貼簿事件的主要來源協議；無錄影，避免掛播放器）
const baseSession = (over) => ({
  id: 1,
  session_id: 's-1',
  protocol: 'rdp',
  status: 'closed',
  end_reason: 'normal',
  client_ip: '127.0.0.1',
  start_time: '2026-07-20T08:00:00Z',
  end_time: '2026-07-20T08:10:00Z',
  duration: 600,
  has_recording: false,
  user: { username: 'u1' },
  asset: { name: 'a1', host: 'h', port: 3389 },
  ...over,
})

const availableEvent = (over) => ({
  id: 11,
  session_id: 1,
  direction: 'send',
  content_length: 42,
  content_status: 'available',
  created_at: '2026-07-20T08:01:00Z',
  ...over,
})

const failedEvent = (over) => ({
  id: 12,
  session_id: 1,
  direction: 'recv',
  content_length: 7,
  content_status: 'failed',
  created_at: '2026-07-20T08:02:00Z',
  ...over,
})

const mountDetail = () =>
  mount(SessionDetail, {
    global: { plugins: [ElementPlus] },
    attachTo: document.body,
  })

const card = (wrapper) => wrapper.find('[data-test="clipboard-card"]')

// el-table expand 欄的展開鍵（列序即資料序；查詢範圍鎖在剪貼簿卡內）
const expandIcon = (wrapper, rowIndex) =>
  card(wrapper).findAll('.el-table__expand-icon')[rowIndex]

// 列上的「解密調閱」鍵（唯一的解密入口；缺口列不渲染，故 index 只數可調閱列）
const decryptButtons = (wrapper) =>
  card(wrapper).findAll('[data-test="clipboard-decrypt-btn"]')

describe('SessionDetail 剪貼簿卡：事實列表', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routeState.query = {}
    routeState.hash = ''
    getSessionMock.mockResolvedValue(baseSession())
  })

  it('有事件即渲染卡：時間、方向、長度、狀態，缺口筆數另計', async () => {
    getClipboardEventsMock.mockResolvedValue({
      data: [availableEvent(), failedEvent()],
      total: 2,
    })
    const wrapper = mountDetail()
    await flushPromises()

    expect(card(wrapper).exists()).toBe(true)
    expect(getClipboardEventsMock).toHaveBeenCalledWith('s-1')

    const text = card(wrapper).text()
    expect(text).toContain('共 2 筆')
    expect(text).toContain('從本機複製到遠端')
    expect(text).toContain('從遠端複製回本機')
    expect(text).toContain('42')
    expect(text).toContain('可調閱')
    // 缺口列狀態標示＋另計徽章
    expect(wrapper.find('[data-test="clipboard-status-failed"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="clipboard-failed-count"]').text()).toContain('1')
  })

  it('載入列表不觸發單筆內容端點（未展開＝未解密）', async () => {
    getClipboardEventsMock.mockResolvedValue({
      data: [availableEvent(), failedEvent()],
      total: 2,
    })
    const wrapper = mountDetail()
    await flushPromises()

    expect(card(wrapper).exists()).toBe(true)
    expect(getClipboardContentMock).not.toHaveBeenCalled()
  })

  it('無事件不渲染整卡', async () => {
    getClipboardEventsMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountDetail()
    await flushPromises()

    expect(card(wrapper).exists()).toBe(false)
  })

  it('列表載入失敗時同樣不渲染卡（best-effort，不影響詳情頁）', async () => {
    getClipboardEventsMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountDetail()
    await flushPromises()

    expect(card(wrapper).exists()).toBe(false)
    expect(wrapper.find('.info-card').exists()).toBe(true)
  })
})

describe('SessionDetail 剪貼簿卡：按鍵才解密', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routeState.query = {}
    routeState.hash = ''
    getSessionMock.mockResolvedValue(baseSession())
    getClipboardEventsMock.mockResolvedValue({
      data: [availableEvent(), failedEvent()],
      total: 2,
    })
  })

  it('可調閱列給鎖頭＋「解密調閱」鍵，缺口列兩者皆無', async () => {
    const wrapper = mountDetail()
    await flushPromises()

    // 可調閱列一顆鍵；缺口列以「—」佔位，不給任何解密入口
    expect(decryptButtons(wrapper)).toHaveLength(1)
    expect(card(wrapper).findAll('[data-test="clipboard-lock-icon"]')).toHaveLength(1)
    expect(card(wrapper).findAll('[data-test="clipboard-action-none"]')).toHaveLength(1)
    expect(decryptButtons(wrapper)[0].text()).toContain('解密調閱')
  })

  it('只展開列不發任何請求，展開面給「上鎖」提示（不再展開直載）', async () => {
    const wrapper = mountDetail()
    await flushPromises()

    await expandIcon(wrapper, 0).trigger('click')
    await flushPromises()

    expect(getClipboardContentMock).not.toHaveBeenCalled()
    await vi.waitFor(
      () =>
        expect(
          wrapper.find('[data-test="clipboard-locked-hint"]').exists()
        ).toBe(true),
      { timeout: 5000 }
    )
    expect(wrapper.find('pre[data-test="clipboard-content"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="clipboard-access-logged"]').exists()).toBe(false)
  })

  it('按「解密調閱」才呼單筆端點，內容以 <pre> 呈現', async () => {
    getClipboardContentMock.mockResolvedValue({
      data: { ...availableEvent(), content: 'secret  text\nline2' },
    })
    const wrapper = mountDetail()
    await flushPromises()

    // 按鍵前零請求（載入列表與渲染都不解密）
    expect(getClipboardContentMock).not.toHaveBeenCalled()

    await decryptButtons(wrapper)[0].trigger('click')
    await flushPromises()

    expect(getClipboardContentMock).toHaveBeenCalledTimes(1)
    expect(getClipboardContentMock).toHaveBeenCalledWith('s-1', 11)
    // 全量並行下 DOM flush 可落後於資料態，DOM 斷言以 waitFor 收斂
    await vi.waitFor(
      () =>
        expect(
          wrapper.find('pre[data-test="clipboard-content"]').exists()
        ).toBe(true),
      { timeout: 5000 }
    )
    const pre = wrapper.find('pre[data-test="clipboard-content"]')
    expect(pre.text()).toContain('secret  text')
    expect(pre.text()).toContain('line2')
  })

  // 解密之後要讓人看見「這一次調閱已經被記下來了」，時刻＝收到內容的時刻
  it('內容之上帶留痕回饋行，含調閱時刻（時分秒）', async () => {
    getClipboardContentMock.mockResolvedValue({
      data: { ...availableEvent(), content: 'secret' },
    })
    const wrapper = mountDetail()
    await flushPromises()

    await decryptButtons(wrapper)[0].trigger('click')
    await flushPromises()

    await vi.waitFor(
      () =>
        expect(
          wrapper.find('[data-test="clipboard-access-logged"]').exists()
        ).toBe(true),
      { timeout: 5000 }
    )
    const logged = wrapper.find('[data-test="clipboard-access-logged"]')
    expect(logged.text()).toContain('本次調閱已留存紀錄')
    expect(logged.text()).toMatch(/\d{2}:\d{2}:\d{2}/)
    // 位置：留痕回饋必須在內容之前（先知道留痕，才看見內容）
    const pane = wrapper.find('[data-test="clipboard-content-pane"]')
    expect(pane.html().indexOf('clipboard-access-logged')).toBeLessThan(
      pane.html().indexOf('clipboard-content"')
    )
  })

  it('收合再展開、再按一次鍵都不重複呼叫（內容已在手，不重複留痕）', async () => {
    getClipboardContentMock.mockResolvedValue({
      data: { ...availableEvent(), content: 'x' },
    })
    const wrapper = mountDetail()
    await flushPromises()

    await decryptButtons(wrapper)[0].trigger('click')
    await flushPromises()
    await expandIcon(wrapper, 0).trigger('click') // 收合
    await flushPromises()
    await expandIcon(wrapper, 0).trigger('click') // 再展開
    await flushPromises()
    await decryptButtons(wrapper)[0].trigger('click') // 再按一次解密鍵
    await flushPromises()

    expect(getClipboardContentMock).toHaveBeenCalledTimes(1)
  })

  it('缺口列展開給失敗說明、不呼端點', async () => {
    const wrapper = mountDetail()
    await flushPromises()

    await expandIcon(wrapper, 1).trigger('click')
    await flushPromises()

    expect(getClipboardContentMock).not.toHaveBeenCalled()
    await vi.waitFor(
      () =>
        expect(
          wrapper.find('[data-test="clipboard-gap-detail"]').exists()
        ).toBe(true),
      { timeout: 5000 }
    )
    const gap = wrapper.find('[data-test="clipboard-gap-detail"]')
    expect(gap.text()).toContain('內容留存失敗')
    // 說明必須講「事件存在、內容缺席」，不得讓缺口讀成「無此事件」
    expect(gap.text()).toContain('不代表事件不存在')
    // 缺口列全程沒有解密入口（可調閱列那顆不算在內）
    expect(decryptButtons(wrapper)).toHaveLength(1)
  })

  it('單筆載入失敗：錯誤態＋重試鍵，重試成功後顯示內容', async () => {
    getClipboardContentMock
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce({ data: { ...availableEvent(), content: 'ok' } })
    const wrapper = mountDetail()
    await flushPromises()

    await decryptButtons(wrapper)[0].trigger('click')
    await flushPromises()

    await vi.waitFor(
      () =>
        expect(
          wrapper.find('[data-test="clipboard-content-error"]').exists()
        ).toBe(true),
      { timeout: 5000 }
    )
    expect(wrapper.find('pre[data-test="clipboard-content"]').exists()).toBe(false)

    await wrapper.find('[data-test="clipboard-content-retry"]').trigger('click')
    await flushPromises()

    expect(getClipboardContentMock).toHaveBeenCalledTimes(2)
    await vi.waitFor(
      () =>
        expect(
          wrapper.find('pre[data-test="clipboard-content"]').exists()
        ).toBe(true),
      { timeout: 5000 }
    )
    expect(wrapper.find('[data-test="clipboard-content-error"]').exists()).toBe(false)
    expect(wrapper.find('pre[data-test="clipboard-content"]').text()).toBe('ok')
  })
})

describe('SessionDetail 剪貼簿卡：#clipboard 錨點', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routeState.query = {}
    routeState.hash = ''
    getSessionMock.mockResolvedValue(baseSession())
  })

  it('帶 #clipboard 進入且有事件：資料就緒後捲動至卡', async () => {
    routeState.hash = '#clipboard'
    getClipboardEventsMock.mockResolvedValue({
      data: [availableEvent()],
      total: 1,
    })
    const scrollSpy = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollSpy

    const wrapper = mountDetail()
    await flushPromises()

    expect(card(wrapper).exists()).toBe(true)
    await vi.waitFor(() => expect(scrollSpy).toHaveBeenCalled(), {
      timeout: 5000,
    })
    delete window.HTMLElement.prototype.scrollIntoView
  })

  // 首捲發生在剪貼簿資料就緒當下，但上方佈局還在長高
  // （播放器等 recordingUrl 才掛載定高、指令表格晚到），首捲被「當時的」
  // 最大捲動量 clamp、卡片隨後被推出視窗外。佈局再變動時必須補捲
  it('首捲後佈局又長高：補捲至卡', async () => {
    routeState.hash = '#clipboard'
    getClipboardEventsMock.mockResolvedValue({
      data: [availableEvent()],
      total: 1,
    })
    const scrollSpy = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollSpy

    // 收集所有 RO 實例並記錄各自觀察的元素——掛載樹裡 Element Plus
    // 也可能建 RO，須以「觀察對象＝頁面根元素」指認出補捲用的那顆
    const roInstances = []
    class ResizeObserverStub {
      constructor(cb) {
        this.cb = cb
        roInstances.push(this)
      }
      observe(el) {
        this.el = el
      }
      disconnect() {
        this.disconnected = true
      }
    }
    const originalRO = globalThis.ResizeObserver
    globalThis.ResizeObserver = ResizeObserverStub

    try {
      const wrapper = mountDetail()
      await flushPromises()
      expect(card(wrapper).exists()).toBe(true)
      await vi.waitFor(() => expect(scrollSpy).toHaveBeenCalled(), {
        timeout: 5000,
      })

      const mine = roInstances.find((ro) =>
        ro.el?.classList?.contains('session-detail')
      )
      expect(mine).toBeTruthy()

      // **首個回報就必須補捲**（修復波第二輪）：RO 會合併批次回報，長高若
      // 發生在首次回報派送之前就併在首報裡。曾為了「不蓋掉 smooth 首捲」而
      // 無條件跳過首報，結果長高落在首批時唯一的補捲機會被吃掉、其後再無
      // 回報，卡片停在視窗外（實測連開六次重現 2 次，cardTop 809 卡底 1003）。
      // 補捲冪等，寧可多捲一次也不能漏那一次——本行擋的就是「跳過首報」回歸
      const before = scrollSpy.mock.calls.length
      mine.cb([], mine)
      expect(scrollSpy.mock.calls.length).toBeGreaterThan(before)

      // 後續每次長高（播放器定高／表格填充）同樣補捲
      const afterFirst = scrollSpy.mock.calls.length
      mine.cb([], mine)
      expect(scrollSpy.mock.calls.length).toBeGreaterThan(afterFirst)
    } finally {
      globalThis.ResizeObserver = originalRO
      delete window.HTMLElement.prototype.scrollIntoView
    }
  })

  it('無 hash 時不捲動', async () => {
    getClipboardEventsMock.mockResolvedValue({
      data: [availableEvent()],
      total: 1,
    })
    const scrollSpy = vi.fn()
    window.HTMLElement.prototype.scrollIntoView = scrollSpy

    mountDetail()
    await flushPromises()

    expect(scrollSpy).not.toHaveBeenCalled()
    delete window.HTMLElement.prototype.scrollIntoView
  })
})
