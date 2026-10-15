import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ElementPlus from 'element-plus'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
enableAutoUnmount(afterEach)

// 元件在 module 層讀取 window.Guacamole，必須在元件 import 前注入 mock。
// StringReader 立即回放注入的 chunk，StringWriter 記錄送出的文字供斷言
const { sentClipboard, clients } = vi.hoisted(() => {
  const sentClipboard = []
  // 完整連線流程用的 client：記錄 sendSize／sendKeyEvent 與 display.scale 收到的值
  const clients = []

  class StringReaderMock {
    constructor(stream) {
      stream.__reader = this
    }
    emit(text) {
      this.ontext?.(text)
      this.onend?.()
    }
  }

  class StringWriterMock {
    constructor() {
      sentClipboard.push(this)
      this.texts = []
    }
    sendText(t) {
      this.texts.push(t)
    }
    sendEnd() {
      this.ended = true
    }
  }

  class ClientMock {
    static State = { CONNECTING: 1, CONNECTED: 3, DISCONNECTED: 5 }
    constructor() {
      clients.push(this)
      const element = document.createElement('div')
      this.element = element
      this.remote = { width: 800, height: 600 }
      this.scales = []
      const display = {
        getElement: () => element,
        getWidth: () => this.remote.width,
        getHeight: () => this.remote.height,
        getScale: () => this.scales.at(-1) ?? 1,
        scale: (v) => { this.scales.push(v) },
      }
      this.getDisplay = () => display
      this.createClipboardStream = vi.fn(() => ({}))
      this.sendKeyEvent = vi.fn()
      this.sendMouseState = vi.fn()
      this.sendSize = vi.fn()
      this.connect = vi.fn()
      this.disconnect = vi.fn()
    }
  }

  globalThis.window.Guacamole = {
    StringReader: StringReaderMock,
    StringWriter: StringWriterMock,
    WebSocketTunnel: function () {},
    Client: ClientMock,
    Mouse: class {},
    Keyboard: class {},
  }

  return { sentClipboard, clients }
})

vi.mock('@/api/connect', () => ({
  createConnectTokenWithConsent: vi.fn().mockResolvedValue({ connect_token: 'test' }),
}))
vi.mock('@/api/files', () => ({
  getTransferCapabilities: vi.fn().mockResolvedValue({ capabilities: {} }),
}))

import GuacamoleClient from '../GuacamoleClient.vue'

const clientMock = {
  createClipboardStream: vi.fn(() => ({})),
  getDisplay: () => ({ getScale: () => 1 }),
  disconnect: vi.fn(),
}

const mountClient = () =>
  mount(GuacamoleClient, {
    props: { assetId: 77, protocol: 'vnc', assetName: '測試 VNC' },
    global: { plugins: [ElementPlus] },
  })

describe('GuacamoleClient 剪貼簿同步', () => {
  let clipboardMock

  beforeEach(() => {
    sentClipboard.length = 0
    clipboardMock = {
      writeText: vi.fn().mockResolvedValue(undefined),
      readText: vi.fn().mockResolvedValue(''),
    }
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboardMock,
      configurable: true,
    })
    vi.stubGlobal('ResizeObserver', class {
      observe() {}
      disconnect() {}
    })
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('遠端剪貼簿（text/plain）寫入本機剪貼簿', async () => {
    const wrapper = mountClient()

    const stream = {}
    wrapper.vm.handleRemoteClipboard(stream, 'text/plain')
    stream.__reader.emit('remote-copy-text')
    await Promise.resolve()

    expect(clipboardMock.writeText).toHaveBeenCalledWith('remote-copy-text')
    wrapper.unmount()
  })

  it('非文字 mimetype 忽略', async () => {
    const wrapper = mountClient()

    wrapper.vm.handleRemoteClipboard({}, 'image/png')

    expect(clipboardMock.writeText).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('寫入被拒時暫存，focus 補寫', async () => {
    const wrapper = mountClient()
    clipboardMock.writeText.mockRejectedValueOnce(new Error('not focused'))

    const stream = {}
    wrapper.vm.handleRemoteClipboard(stream, 'text/plain')
    stream.__reader.emit('deferred-text')
    await Promise.resolve()
    await Promise.resolve()

    clipboardMock.writeText.mockResolvedValue(undefined)
    await wrapper.vm.syncClipboardOnFocus()

    expect(clipboardMock.writeText).toHaveBeenLastCalledWith('deferred-text')
    wrapper.unmount()
  })

  it('focus 時本機新內容送往遠端，重複內容去重', async () => {
    const wrapper = mountClient()
    wrapper.vm.__test__setConnectedClient(clientMock)
    clipboardMock.readText.mockResolvedValue('local-text')

    await wrapper.vm.syncClipboardOnFocus()
    expect(clientMock.createClipboardStream).toHaveBeenCalledWith('text/plain')
    expect(sentClipboard).toHaveLength(1)
    expect(sentClipboard[0].texts).toEqual(['local-text'])
    expect(sentClipboard[0].ended).toBe(true)

    // 同內容再次 focus：不重送
    await wrapper.vm.syncClipboardOnFocus()
    expect(sentClipboard).toHaveLength(1)
    wrapper.unmount()
  })

  it('readText 權限被拒時靜默降級', async () => {
    const wrapper = mountClient()
    wrapper.vm.__test__setConnectedClient(clientMock)
    clipboardMock.readText.mockRejectedValue(new Error('denied'))

    await expect(wrapper.vm.syncClipboardOnFocus()).resolves.toBeUndefined()
    expect(clientMock.createClipboardStream).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('未連線時不讀取本機剪貼簿', async () => {
    const wrapper = mountClient()

    await wrapper.vm.syncClipboardOnFocus()

    expect(clipboardMock.readText).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})

// guacd error instruction 帶狀態碼，前端按碼查譯，
// 中文 args[0] 降為 fallback。guacamole-common-js 把 args[1] parseInt 後放進
// Guacamole.Status.code、args[0] 放進 .message
describe('GuacamoleClient guacd 逾時錯誤查譯', () => {
  beforeEach(() => {
    vi.stubGlobal('ResizeObserver', class {
      observe() {}
      disconnect() {}
    })
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('776（CLIENT_TIMEOUT）譯為閒置逾時，不用後端原文', () => {
    const wrapper = mountClient()
    const msg = wrapper.vm.guacErrorMessage({ code: 776, message: '後端 zh fallback' })
    expect(msg).toBe('閒置逾時，連線已中斷')
    wrapper.unmount()
  })

  it('523（SESSION_CLOSED）譯為會話時間上限，與 776 不同文案', () => {
    const wrapper = mountClient()
    const idle = wrapper.vm.guacErrorMessage({ code: 776, message: 'x' })
    const max = wrapper.vm.guacErrorMessage({ code: 523, message: 'x' })
    expect(max).toBe('已達會話時間上限，連線已中斷')
    expect(max).not.toBe(idle)
    wrapper.unmount()
  })

  it('未映射的狀態碼退回 guacd 訊息，無訊息時退回通用語', () => {
    const wrapper = mountClient()
    expect(wrapper.vm.guacErrorMessage({ code: 519, message: 'upstream error' })).toBe('upstream error')
    expect(wrapper.vm.guacErrorMessage({ code: 519 })).toBe('未知錯誤')
    expect(wrapper.vm.guacErrorMessage(undefined)).toBe('未知錯誤')
    wrapper.unmount()
  })
})

// 圖形畫面尺寸同步與縮放：游標停在畫面邊緣時不得出現「出捲軸 → 縮小 → 合成輸入
// 把游標拉回 → 捲軸消失 → 放大」的回饋迴圈，縮放後的畫面不得大於容器
describe('GuacamoleClient 尺寸同步與縮放', () => {
  let resizeCallback

  const mountRdp = () =>
    mount(GuacamoleClient, {
      props: { assetId: 77, protocol: 'rdp', assetName: '測試 RDP' },
      global: { plugins: [ElementPlus] },
    })

  // 走真實連線流程：ResizeObserver 回報首個尺寸 → 簽發 → 建 client → 狀態 CONNECTED
  const connectAt = async (width, height) => {
    const wrapper = mountRdp()
    resizeCallback([{ contentRect: { width, height } }])
    await flushPromises()
    const client = clients.at(-1)
    return { wrapper, client }
  }

  const countMouseMoves = (element) => {
    const moves = []
    element.addEventListener('mousemove', (e) => moves.push(e))
    return moves
  }

  beforeEach(() => {
    clients.length = 0
    vi.stubGlobal('ResizeObserver', class {
      constructor(callback) { this.callback = callback }
      observe(element) { if (element.classList.contains('display-container')) resizeCallback = this.callback }
      disconnect() {}
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('縮放以量測尺寸為準且向下取整：縮放後外框不大於容器', async () => {
    const { wrapper, client } = await connectAt(1111.7, 624.9)
    client.remote = { width: 1126, height: 639 }
    wrapper.vm.fitDisplay()
    const scale = client.scales.at(-1)
    expect(scale).toBeGreaterThan(0)
    expect(scale * 1126).toBeLessThanOrEqual(1111)
    expect(scale * 639).toBeLessThanOrEqual(624)
    // 精度 1e-4，且只比理論值小不到 1e-4
    expect(Math.round(scale * 1e4)).toBe(scale * 1e4)
    expect(Math.min(1111 / 1126, 624 / 639) - scale).toBeLessThan(1e-4)
  })

  it('fitDisplay 不讀 clientWidth／clientHeight（避免與 ResizeObserver 取整不一致）', async () => {
    const { wrapper, client } = await connectAt(1111, 624)
    const container = wrapper.find('.display-container').element
    const reads = vi.fn(() => 9999)
    Object.defineProperty(container, 'clientWidth', { configurable: true, get: reads })
    Object.defineProperty(container, 'clientHeight', { configurable: true, get: reads })
    client.remote = { width: 1126, height: 639 }
    wrapper.vm.fitDisplay()
    expect(reads).not.toHaveBeenCalled()
    expect(client.scales.at(-1) * 1126).toBeLessThanOrEqual(1111)
  })

  it('連續兩次相同尺寸只送一次 sendSize、只重算一次縮放', async () => {
    const { wrapper, client } = await connectAt(800, 600)
    client.onstatechange(3)
    await flushPromises()
    client.sendSize.mockClear()
    const scalesBefore = client.scales.length

    wrapper.vm.handleResize(1000, 700)
    wrapper.vm.handleResize(1000, 700)

    expect(client.sendSize).toHaveBeenCalledTimes(1)
    expect(client.sendSize).toHaveBeenCalledWith(1000, 700)
    expect(client.scales.length - scalesBefore).toBe(1)
  })

  it('量到與連線時相同的尺寸不重送（連線 URL 的尺寸即首次套用）', async () => {
    const { client } = await connectAt(800, 600)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] })
    client.onstatechange(3)
    resizeCallback([{ contentRect: { width: 800.6, height: 600.2 } }])
    await vi.advanceTimersByTimeAsync(1000)
    expect(client.sendSize).not.toHaveBeenCalled()
  })

  it('連線後首幀合成重繪恰好一次，且不送任何按鍵', async () => {
    const { client } = await connectAt(800, 600)
    const moves = countMouseMoves(client.element)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] })
    client.onstatechange(3)
    await vi.advanceTimersByTimeAsync(1000)
    expect(moves).toHaveLength(1)
    expect(client.sendKeyEvent).not.toHaveBeenCalled()
  })

  it('resize 路徑不合成 mousemove、不送 Shift 等按鍵', async () => {
    const { client } = await connectAt(800, 600)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] })
    client.onstatechange(3)
    await vi.advanceTimersByTimeAsync(1000)
    const moves = countMouseMoves(client.element)

    resizeCallback([{ contentRect: { width: 1024, height: 700 } }])
    await vi.advanceTimersByTimeAsync(1000)
    resizeCallback([{ contentRect: { width: 900, height: 650 } }])
    await vi.advanceTimersByTimeAsync(1000)

    expect(client.sendSize).toHaveBeenCalledTimes(2)
    expect(moves).toHaveLength(0)
    expect(client.sendKeyEvent).not.toHaveBeenCalled()
  })

  it('握手期間容器尺寸改變時，連線後補送一次新尺寸', async () => {
    const { client } = await connectAt(800, 600)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] })
    // 尚未 CONNECTED：只記錄量測，不排程
    resizeCallback([{ contentRect: { width: 1000, height: 600 } }])
    await vi.advanceTimersByTimeAsync(1000)
    expect(client.sendSize).not.toHaveBeenCalled()
    client.onstatechange(3)
    await vi.advanceTimersByTimeAsync(1000)
    expect(client.sendSize).toHaveBeenCalledTimes(1)
    expect(client.sendSize).toHaveBeenCalledWith(1000, 600)
  })

  it('畫面容器不捲動：游標圖像溢出不得長出捲軸', () => {
    const src = readFileSync(join(process.cwd(), 'src', 'components', 'GuacamoleClient.vue'), 'utf8')
    const block = src.match(/\.display-container\s*\{([^}]*)\}/)
    expect(block).not.toBeNull()
    expect(block[1]).toMatch(/overflow:\s*hidden;/)
    expect(block[1]).not.toMatch(/overflow:\s*(auto|scroll)/)
  })
})
