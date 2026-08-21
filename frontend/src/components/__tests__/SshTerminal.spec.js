import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// xterm 與 addons 在 happy-dom 無法真實渲染，以可觀察的 mock 取代
const terminalMock = {
  cols: 120,
  rows: 30,
  loadAddon: vi.fn(),
  open: vi.fn(),
  onData: vi.fn(),
  attachCustomKeyEventHandler: vi.fn(),
  write: vi.fn(),
  reset: vi.fn(),
  focus: vi.fn(),
  dispose: vi.fn(),
}
const fitMock = { fit: vi.fn() }
const searchMock = {
  findNext: vi.fn(),
  findPrevious: vi.fn(),
  clearDecorations: vi.fn(),
}

vi.mock('@xterm/xterm', () => ({
  Terminal: vi.fn(function () {
    return terminalMock
  }),
}))
vi.mock('@xterm/addon-fit', () => ({
  FitAddon: vi.fn(function () {
    return fitMock
  }),
}))
vi.mock('@xterm/addon-search', () => ({
  SearchAddon: vi.fn(function () {
    return searchMock
  }),
}))
vi.mock('@xterm/addon-web-links', () => ({
  WebLinksAddon: vi.fn(function () {
    return {}
  }),
}))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

vi.mock('@/api/connect', () => ({
  createConnectTokenWithConsent: vi
    .fn()
    .mockResolvedValue({ connect_token: 'ct-test', expires_in: 60 }),
}))

// WebSocket mock：記錄建構 URL 與送出的訊息，可手動觸發事件
class WebSocketMock {
  static instances = []
  static OPEN = 1

  constructor(url) {
    this.url = url
    this.readyState = WebSocketMock.OPEN
    this.sent = []
    this.onmessage = null
    this.onclose = null
    this.onerror = null
    WebSocketMock.instances.push(this)
  }

  send(payload) {
    this.sent.push(JSON.parse(payload))
  }

  close() {}

  receive(msg) {
    this.onmessage?.({ data: JSON.stringify(msg) })
  }
}

// ResizeObserver mock：保留 callback 供測試手動觸發
let resizeCallback = null
class ResizeObserverMock {
  constructor(cb) {
    resizeCallback = cb
  }
  observe() {}
  disconnect() {}
}

import { createConnectTokenWithConsent } from '@/api/connect'
import SshTerminal from '../SshTerminal.vue'
import { t } from '@/i18n'

const mountTerminal = () =>
  mount(SshTerminal, {
    props: { assetId: 7 },
    global: { plugins: [ElementPlus] },
    attachTo: document.body,
  })

// 模擬容器完成 layout（非零尺寸）並觸發 ResizeObserver
const layoutReady = async (wrapper) => {
  const el = wrapper.find('.terminal-container').element
  Object.defineProperty(el, 'clientWidth', { value: 800, configurable: true })
  Object.defineProperty(el, 'clientHeight', { value: 600, configurable: true })
  resizeCallback?.()
  // 兩段式連線：等 createConnectToken microtask 完成後 WS 才建立
  await vi.advanceTimersByTimeAsync(0)
}

describe('SshTerminal', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', WebSocketMock)
    vi.stubGlobal('ResizeObserver', ResizeObserverMock)
    WebSocketMock.instances = []
    resizeCallback = null
    localStorage.setItem('token', 'test-jwt')
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('容器尺寸為零時不連線，等首個非零尺寸才連線', async () => {
    const wrapper = mountTerminal()

    // 預設 clientWidth/Height 為 0：觸發 observer 不應連線
    resizeCallback?.()
    expect(WebSocketMock.instances).toHaveLength(0)

    await layoutReady(wrapper)
    expect(fitMock.fit).toHaveBeenCalled()
    expect(WebSocketMock.instances).toHaveLength(1)
    wrapper.unmount()
  })

  it('WS URL 僅帶一次性 connect_token 與尺寸，不含 JWT 與憑證欄位', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    const url = new URL(WebSocketMock.instances[0].url)
    expect(url.pathname).toBe('/api/v1/ssh')
    expect(url.searchParams.get('connect_token')).toBe('ct-test')
    expect(url.searchParams.get('cols')).toBe('120')
    expect(url.searchParams.get('rows')).toBe('30')
    expect(url.searchParams.has('token')).toBe(false)
    expect(url.searchParams.has('asset_id')).toBe(false)
    expect(url.searchParams.has('password')).toBe(false)
    expect(url.searchParams.has('username')).toBe(false)
    wrapper.unmount()
  })

  it('收到 data 訊息寫入終端、connected 後鍵入轉送 WS', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]

    ws.receive({ type: 'connected' })
    ws.receive({ type: 'data', data: 'hello\r\n' })
    expect(terminalMock.write).toHaveBeenCalledWith('hello\r\n')

    // terminal.onData 註冊的 handler 轉送鍵入
    const onDataHandler = terminalMock.onData.mock.calls[0][0]
    onDataHandler('ls\r')
    expect(ws.sent).toContainEqual({ type: 'data', data: 'ls\r' })
    wrapper.unmount()
  })

  it('連線後尺寸變化經防抖送出 resize 訊息', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]
    ws.receive({ type: 'connected' })

    resizeCallback?.()
    resizeCallback?.()
    expect(ws.sent.filter((m) => m.type === 'resize')).toHaveLength(0)

    vi.advanceTimersByTime(250)
    const resizes = ws.sent.filter((m) => m.type === 'resize')
    expect(resizes).toHaveLength(1)
    expect(JSON.parse(resizes[0].data)).toEqual({ cols: 120, rows: 30 })
    wrapper.unmount()
  })

  it('error 訊息顯示連線失敗與重新連線按鈕', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    WebSocketMock.instances[0].receive({ type: 'error', data: 'SSH 認證失敗，請確認資產憑證' })
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('連線失敗')
    expect(wrapper.text()).toContain('SSH 認證失敗，請確認資產憑證')
    expect(wrapper.text()).toContain('重新連線')
    wrapper.unmount()
  })

  // ssh-connect-error-surfacing：撥號失敗 code 的 i18n 顯示與 host key 引導
  it('error 訊息帶已譯 code 時顯示 apiError 譯文', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    WebSocketMock.instances[0].receive({
      type: 'error',
      code: 'RULE_SSH_DIAL_TIMEOUT',
      data: 'zh fallback 原文',
    })
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('連線目標主機逾時')
    expect(wrapper.text()).not.toContain('zh fallback 原文')
    wrapper.unmount()
  })

  it('error 訊息帶未知 code 時退回 data 文案', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    WebSocketMock.instances[0].receive({
      type: 'error',
      code: 'RULE_SSH_NOT_A_REAL_CODE',
      data: '後端原文文案',
    })
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('後端原文文案')
    wrapper.unmount()
  })

  it('host key 變更：admin 見前往資產設定按鈕，點擊開啟編輯深連結', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['admin'] }))
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    WebSocketMock.instances[0].receive({
      type: 'error',
      code: 'RULE_SSH_HOST_KEY_CHANGED',
      data: '主機金鑰已變更',
    })
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('主機金鑰已變更')
    const goBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('前往資產設定重置主機金鑰'))
    expect(goBtn).toBeTruthy()
    await goBtn.trigger('click')
    expect(openSpy).toHaveBeenCalledWith('/assets?edit=7', '_blank')
    openSpy.mockRestore()
    wrapper.unmount()
  })

  it('host key 變更：非 admin 見聯繫管理員提示、無重置入口', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 2, roles: ['user'] }))
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    WebSocketMock.instances[0].receive({
      type: 'error',
      code: 'RULE_SSH_HOST_KEY_CHANGED',
      data: '主機金鑰已變更',
    })
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('請聯繫管理員確認後重置主機金鑰')
    const goBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('前往資產設定重置主機金鑰'))
    expect(goBtn).toBeFalsy()
    wrapper.unmount()
  })

  // backend-i18n-unification F2：token 簽發失敗改走 resolveApiError（原直讀 data.error）
  it('連線 token 簽發失敗帶 code 時顯譯文，未知 code 退回後端 error', async () => {
    createConnectTokenWithConsent.mockRejectedValueOnce({
      response: { status: 403, data: { error: '後端 zh 原文', code: 'RULE_ASSET_DISABLED' } },
    })
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    await wrapper.vm.$nextTick()

    expect(WebSocketMock.instances).toHaveLength(0)
    expect(wrapper.text()).toContain('資產已停用，無法連線')
    expect(wrapper.text()).not.toContain('後端 zh 原文')
    wrapper.unmount()

    createConnectTokenWithConsent.mockRejectedValueOnce({
      response: { status: 500, data: { error: '後端未碼化訊息' } },
    })
    const w2 = mountTerminal()
    await layoutReady(w2)
    await w2.vm.$nextTick()
    expect(w2.text()).toContain('後端未碼化訊息')
    w2.unmount()
  })

  // backend-i18n-unification D7：MsgNotice 控制幀（指令阻斷警告）
  it('notice 幀查譯後以紅字注入終端，且不改變連線狀態', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]
    ws.receive({ type: 'connected' })
    terminalMock.write.mockClear()

    ws.receive({
      type: 'notice',
      code: 'RULE_COMMAND_BLOCKED',
      data: 'zh fallback 原文',
      params: { rule: '刪除根目錄' },
    })
    await wrapper.vm.$nextTick()

    expect(terminalMock.write).toHaveBeenCalledTimes(1)
    const written = terminalMock.write.mock.calls[0][0]
    expect(written).toContain('\x1b[31m')
    expect(written).toContain('\x1b[0m')
    expect(written.startsWith('\r\n')).toBe(true)
    expect(written.endsWith('\r\n')).toBe(true)
    // 查譯優先於後端 zh fallback；規則名以 params 插值
    expect(written).toContain('指令命中阻斷規則')
    expect(written).toContain('刪除根目錄')
    expect(written).not.toContain('zh fallback 原文')
    // 警告不是斷線：狀態維持 connected、不出遮罩
    expect(wrapper.vm.$el.querySelector('.status-overlay')).toBeFalsy()
    wrapper.unmount()
  })

  it('notice 幀未知 code 退回後端 data 文案', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]
    ws.receive({ type: 'connected' })
    terminalMock.write.mockClear()

    ws.receive({ type: 'notice', code: 'RULE_NOT_A_REAL_NOTICE', data: '後端原文警告' })
    await wrapper.vm.$nextTick()

    expect(terminalMock.write.mock.calls[0][0]).toContain('後端原文警告')
    wrapper.unmount()
  })

  it('notice 的 rule 值挾帶 ANSI 逃逸序列時被剝除，不得改寫終端', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]
    ws.receive({ type: 'connected' })
    terminalMock.write.mockClear()

    ws.receive({
      type: 'notice',
      code: 'RULE_COMMAND_BLOCKED',
      data: 'zh fallback',
      params: { rule: 'evil\x1b[2J\x1b[0;0H\x07pwned\r\nfake$ ' },
    })
    await wrapper.vm.$nextTick()

    const written = terminalMock.write.mock.calls[0][0]
    // 僅保留元件自身包的紅字序列與前後換行，值內的控制字元一律剝除
    const PREFIX = '\r\n\x1b[31m'
    const SUFFIX = '\x1b[0m\r\n'
    expect(written.startsWith(PREFIX)).toBe(true)
    expect(written.endsWith(SUFFIX)).toBe(true)
    const body = written.slice(PREFIX.length, -SUFFIX.length)
    // eslint-disable-next-line no-control-regex -- 斷言的對象就是控制字元
    expect(body).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/)
    // 剝除的是控制位元組本身：殘留的 '[2J' 等純可見文字不再是逃逸序列，
    // 無法改寫畫面，故不另做內容過濾（不吞使用者可見的規則名資訊）
    expect(body).toContain('evil[2J[0;0Hpwnedfake$')
    wrapper.unmount()
  })

  it('收到 pong 顯示延遲徽章，斷線後隱藏', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]
    ws.receive({ type: 'connected' })

    // 首次量測前不顯示
    expect(wrapper.find('.latency-badge').exists()).toBe(false)

    // 10s 觸發 ping（記時）→ 收 pong → 顯示徽章
    vi.advanceTimersByTime(10000)
    ws.receive({ type: 'pong' })
    await wrapper.vm.$nextTick()
    const badge = wrapper.find('.latency-badge')
    expect(badge.exists()).toBe(true)
    expect(badge.text()).toMatch(/^\d+ms$/)

    // 斷線清空
    ws.onclose?.({ code: 1006 })
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.latency-badge').exists()).toBe(false)
    wrapper.unmount()
  })

  it('Ctrl+F 開啟搜尋列並驅動 SearchAddon，Esc 關閉回焦', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    // 取得攔截 handler，模擬 Ctrl+F
    const keyHandler = terminalMock.attachCustomKeyEventHandler.mock.calls[0][0]
    const event = { type: 'keydown', key: 'f', ctrlKey: true, preventDefault: vi.fn() }
    expect(keyHandler(event)).toBe(false)
    expect(event.preventDefault).toHaveBeenCalled()
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.search-bar').exists()).toBe(true)

    // 輸入觸發增量搜尋
    const input = wrapper.find('.search-bar input')
    await input.setValue('error')
    expect(searchMock.findNext).toHaveBeenCalledWith('error', { incremental: true })

    // Esc 關閉、清除標記並回焦終端
    await input.trigger('keydown', { key: 'Escape' })
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.search-bar').exists()).toBe(false)
    expect(searchMock.clearDecorations).toHaveBeenCalled()
    expect(terminalMock.focus).toHaveBeenCalled()
    wrapper.unmount()
  })

  it('connected 後每 10 秒送 ping 保活', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)
    const ws = WebSocketMock.instances[0]
    ws.receive({ type: 'connected' })

    vi.advanceTimersByTime(10000)
    expect(ws.sent.filter((m) => m.type === 'ping')).toHaveLength(1)
    vi.advanceTimersByTime(20000)
    expect(ws.sent.filter((m) => m.type === 'ping')).toHaveLength(3)
    wrapper.unmount()
  })
})


describe('SshTerminal 行動快捷鍵列', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', WebSocketMock)
    vi.stubGlobal('ResizeObserver', ResizeObserverMock)
    WebSocketMock.instances = []
    resizeCallback = null
    localStorage.setItem('token', 'test-jwt')
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('桌面環境不渲染鍵列；強制行動旗標後渲染六鍵', async () => {
    const wrapper = mountTerminal()
    expect(wrapper.find('.mobile-key-row').exists()).toBe(false)

    wrapper.vm.showMobileKeys = true
    await wrapper.vm.$nextTick()
    expect(wrapper.findAll('.mobile-key')).toHaveLength(6)
    wrapper.unmount()
  })

  it('點擊 Ctrl+C 鍵送出 \x03 data 訊息', async () => {
    const wrapper = mountTerminal()
    await layoutReady(wrapper)

    wrapper.vm.showMobileKeys = true
    await wrapper.vm.$nextTick()

    const ws = WebSocketMock.instances[0]
    ws.sent.length = 0
    const ctrlC = wrapper.findAll('.mobile-key').find((b) => b.text() === 'Ctrl+C')
    await ctrlC.trigger('click')

    const sent = ws.sent
    expect(sent).toContainEqual({ type: 'data', data: '\u0003' })
    wrapper.unmount()
  })
})

// mssql 批次終止符提示（mssql-cli-audit-fidelity D6）：同一個 web CLI 上
// mysql/postgres 以 `;` 執行、mssql 需要獨立一行的 GO。協議一律取自資產欄位，
// 不從終端輸出內容推測；提示不寫入終端輸出流（不進錄影與審計）。
describe('SshTerminal mssql 批次終止符提示', () => {
  const HINT_KEY = 'sshTerminal.mssqlBatchHint'
  const HINT_TEXT = t(HINT_KEY)

  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', WebSocketMock)
    vi.stubGlobal('ResizeObserver', ResizeObserverMock)
    WebSocketMock.instances = []
    resizeCallback = null
    localStorage.setItem('token', 'test-jwt')
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  const mountWithProtocol = (protocol) =>
    mount(SshTerminal, {
      props: { assetId: 7, protocol },
      global: { plugins: [ElementPlus] },
      attachTo: document.body,
    })

  const connect = async (wrapper) => {
    await layoutReady(wrapper)
    WebSocketMock.instances[0].receive({ type: 'connected', data: '{}' })
    await wrapper.vm.$nextTick()
  }

  it('mssql 連線成功後顯示提示，點關閉後本次會話不再出現', async () => {
    const wrapper = mountWithProtocol('mssql')
    // 未連線前不顯示
    expect(wrapper.find('.protocol-hint').exists()).toBe(false)

    await connect(wrapper)
    const hint = wrapper.find('.protocol-hint')
    expect(hint.exists()).toBe(true)
    expect(hint.text()).toContain('GO')

    // el-alert 的關閉鈕由 Element Plus 負責，此處驗的是本元件對 close 事件的處置
    await wrapper.findComponent({ name: 'ElAlert' }).vm.$emit('close')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.protocol-hint').exists()).toBe(false)
    wrapper.unmount()
  })

  it.each(['ssh', 'mysql', 'postgres', 'redis', 'k8s'])('%s 連線不顯示提示', async (protocol) => {
    const wrapper = mountWithProtocol(protocol)
    await connect(wrapper)
    expect(wrapper.find('.protocol-hint').exists()).toBe(false)
    wrapper.unmount()
  })

  // 遮擋防線（結構代理）：jsdom 無版面計算，無法直接斷言「關閉鈕可被點到」，
  // 真正的遮擋驗證由 Playwright 實點覆蓋（見 tasks 3.4）。此處釘死的是造成遮擋的
  // **結構成因**：延遲徽章／搜尋列一旦回到 .ssh-terminal 這層當絕對定位子節點，
  // 就會壓在提示條帶上（實測 latency-badge subtree intercepts pointer events）。
  it('浮層（延遲徽章／搜尋列）錨在終端主體容器內，不與提示條同層', async () => {
    const wrapper = mountWithProtocol('mssql')
    await connect(wrapper)

    // 徽章：收 pong 後出現
    vi.advanceTimersByTime(10000)
    WebSocketMock.instances[0].receive({ type: 'pong' })
    // 搜尋列：Ctrl+F 開啟
    const keyHandler = terminalMock.attachCustomKeyEventHandler.mock.calls[0][0]
    keyHandler({ type: 'keydown', key: 'f', ctrlKey: true, preventDefault: vi.fn() })
    await wrapper.vm.$nextTick()

    const container = wrapper.find('.terminal-container').element
    const hint = wrapper.find('.protocol-hint').element
    // 提示條與終端主體是同層的 flex 兄弟；浮層必須落在主體之內（提示條之外）
    expect(container.contains(hint)).toBe(false)
    for (const selector of ['.latency-badge', '.search-bar']) {
      const el = wrapper.find(selector).element
      expect(el.parentElement).toBe(container)
    }
    wrapper.unmount()
  })

  it('提示只存在於 DOM，不寫入終端輸出流', async () => {
    const wrapper = mountWithProtocol('mssql')
    await connect(wrapper)
    expect(wrapper.find('.protocol-hint').exists()).toBe(true)
    const written = terminalMock.write.mock.calls.map((c) => String(c[0])).join('')
    expect(written).not.toContain('GO 送出批次')
    expect(written).not.toContain(HINT_TEXT)
    wrapper.unmount()
  })
})
