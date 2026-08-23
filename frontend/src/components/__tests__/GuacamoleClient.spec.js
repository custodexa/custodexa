import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// 元件在 module 層讀取 window.Guacamole，必須在元件 import 前注入 mock。
// StringReader 立即回放注入的 chunk，StringWriter 記錄送出的文字供斷言
const { sentClipboard } = vi.hoisted(() => {
  const sentClipboard = []

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

  globalThis.window.Guacamole = {
    StringReader: StringReaderMock,
    StringWriter: StringWriterMock,
    WebSocketTunnel: function () {},
    Client: function () {},
  }

  return { sentClipboard }
})

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
