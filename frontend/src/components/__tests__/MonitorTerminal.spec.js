// 唯讀觀看（即時監看與分享觀看）的建線形態。
//
// 本檔守的是一件安全性質：**WebSocket URL 上不得出現登入憑證**。
// 登入憑證的壽命以分鐘計、射程是整個 API，而 URL 會進入瀏覽器歷程與各層存取
// 日誌；改走一次性觀看票之後，URL 只帶那張票，且票由掛認證中介層的簽發端點取得。
//
// 涵蓋：兩條入口各自呼叫正確的簽發端點、票進 query、URL 無登入憑證、
// 簽發失敗不建線（否則會出現一條沒有人負責關閉的連線）。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

const terminalMock = {
  cols: 80,
  rows: 24,
  loadAddon: vi.fn(),
  open: vi.fn(),
  write: vi.fn(),
  resize: vi.fn(),
  dispose: vi.fn(),
}

vi.mock('@xterm/xterm', () => ({
  Terminal: vi.fn(function () {
    return terminalMock
  }),
}))
vi.mock('@xterm/addon-fit', () => ({
  FitAddon: vi.fn(function () {
    return { fit: vi.fn() }
  }),
}))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

vi.mock('@/api/sessions', () => ({
  createMonitorTicket: vi.fn().mockResolvedValue({ connect_token: 'mt-1', expires_in: 60 }),
  createShareTicket: vi.fn().mockResolvedValue({ connect_token: 'st-1', expires_in: 60 }),
}))

class WebSocketMock {
  static instances = []
  static OPEN = 1

  constructor(url) {
    this.url = url
    this.readyState = WebSocketMock.OPEN
    this.sent = []
    WebSocketMock.instances.push(this)
  }
  send(payload) {
    this.sent.push(payload)
  }
  close() {}
}

import { createMonitorTicket, createShareTicket } from '@/api/sessions'
import MonitorTerminal from '../MonitorTerminal.vue'

const mountMonitor = (props) =>
  mount(MonitorTerminal, {
    props,
    global: { plugins: [ElementPlus] },
    attachTo: document.body,
  })

describe('MonitorTerminal 觀看票建線', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', WebSocketMock)
    WebSocketMock.instances = []
    vi.clearAllMocks()
    createMonitorTicket.mockResolvedValue({ connect_token: 'mt-1', expires_in: 60 })
    createShareTicket.mockResolvedValue({ connect_token: 'st-1', expires_in: 60 })
    // 舊形態的殘值也在：即使有人把憑證放進瀏覽器儲存，本元件也不得去讀
    localStorage.setItem('token', 'login-jwt-should-never-appear')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.clear()
  })

  it('監看：先取觀看票，WS URL 只帶票、不帶登入憑證', async () => {
    mountMonitor({ sessionId: 42 })
    await flushPromises()

    expect(createMonitorTicket).toHaveBeenCalledWith(42)
    expect(createShareTicket).not.toHaveBeenCalled()

    const { url } = WebSocketMock.instances[0]
    expect(url).toContain('/api/v1/sessions/42/monitor?')
    expect(url).toContain('connect_token=mt-1')
    expect(url).not.toContain('token=login-jwt-should-never-appear')
    expect(url).not.toMatch(/[?&]token=/)
  })

  it('分享：走分享碼的簽發端點與分享 WS 路徑', async () => {
    mountMonitor({ sessionId: 0, shareCode: 'abc123' })
    await flushPromises()

    expect(createShareTicket).toHaveBeenCalledWith('abc123')
    expect(createMonitorTicket).not.toHaveBeenCalled()

    const { url } = WebSocketMock.instances[0]
    expect(url).toContain('/api/v1/sessions/share/abc123/ws?')
    expect(url).toContain('connect_token=st-1')
    expect(url).not.toMatch(/[?&]token=/)
  })

  it('取票失敗即不建線，並呈現錯誤', async () => {
    createMonitorTicket.mockRejectedValue({
      response: { status: 403, data: { code: 'AUTH_MONITOR_ROLE_REQUIRED' } },
    })

    const wrapper = mountMonitor({ sessionId: 7 })
    await flushPromises()

    expect(WebSocketMock.instances).toHaveLength(0)
    expect(wrapper.find('.status-overlay').exists()).toBe(true)
  })
})
