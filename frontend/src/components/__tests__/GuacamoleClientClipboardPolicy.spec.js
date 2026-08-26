// 圖形連線的剪貼簿自動同步是否遵守「本機→遠端」的傳輸能力。
//
// 守衛的不變式：**連線不允許把本機剪貼簿送到遠端時，視窗回焦的自動同步不得
// 走到送出路徑**。內容本來就進不了遠端，但送出動作會落成一筆審計紀錄，
// 讓事後查紀錄的人以為真的發生過傳輸。
//
// 雙向驗：只驗「禁止時不送」會被「永遠不送」矇混過去，那等於把自動同步整個
// 拿掉；故允許時必須仍會送。另驗方向不得混淆——禁止送出不影響遠端→本機補寫。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

vi.mock('@/api/files', () => ({
  listFiles: vi.fn(),
  uploadFile: vi.fn(),
  downloadFile: vi.fn(),
  mkdir: vi.fn(),
  deleteFile: vi.fn(),
  getTransferCapabilities: vi.fn(),
}))

// 元件在 module 層讀取 window.Guacamole，必須在元件 import 前注入 mock
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
import { getTransferCapabilities } from '@/api/files'

const caps = (overrides = {}) => ({
  capabilities: {
    clipboard_send: true,
    clipboard_recv: true,
    file_upload: true,
    file_download: true,
    file_delete: true,
    ...overrides,
  },
  clipboard_enforced_protocols: ['rdp', 'vnc'],
  clipboard_requires_reconnect: true,
})

describe('GuacamoleClient focus 自動同步遵守剪貼簿送出能力', () => {
  let clipboardMock
  let clientMock

  const mountClient = () =>
    mount(GuacamoleClient, {
      props: { assetId: 77, protocol: 'rdp', assetName: '測試 RDP' },
      global: { plugins: [ElementPlus] },
    })

  // 以指定能力建線：能力於連線前取得，之後不刷新，故此處順序與實機一致
  const mountConnected = async (capsPayload) => {
    getTransferCapabilities.mockResolvedValue(capsPayload)
    const wrapper = mountClient()
    await wrapper.vm.loadCapabilities(77)
    await flushPromises()
    wrapper.vm.__test__setConnectedClient(clientMock)
    return wrapper
  }

  beforeEach(() => {
    vi.clearAllMocks()
    sentClipboard.length = 0
    clientMock = {
      createClipboardStream: vi.fn(() => ({})),
      getDisplay: () => ({ getScale: () => 1 }),
      disconnect: vi.fn(),
    }
    clipboardMock = {
      writeText: vi.fn().mockResolvedValue(undefined),
      readText: vi.fn().mockResolvedValue('local-text'),
    }
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboardMock,
      configurable: true,
    })
    vi.stubGlobal('ResizeObserver', class {
      observe() {}
      disconnect() {}
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('不允許送出時，focus 同步不讀本機剪貼簿也不開送出串流', async () => {
    const wrapper = await mountConnected(caps({ clipboard_send: false }))

    await wrapper.vm.syncClipboardOnFocus()

    expect(clipboardMock.readText).not.toHaveBeenCalled()
    expect(clientMock.createClipboardStream).not.toHaveBeenCalled()
    expect(sentClipboard).toHaveLength(0)
    wrapper.unmount()
  })

  it('允許送出時，focus 同步照樣把本機內容送往遠端', async () => {
    const wrapper = await mountConnected(caps())

    await wrapper.vm.syncClipboardOnFocus()

    expect(clipboardMock.readText).toHaveBeenCalled()
    expect(clientMock.createClipboardStream).toHaveBeenCalledWith('text/plain')
    expect(sentClipboard).toHaveLength(1)
    expect(sentClipboard[0].texts).toEqual(['local-text'])
    wrapper.unmount()
  })

  it('禁止送出不影響遠端→本機的補寫（方向不得混淆）', async () => {
    const wrapper = await mountConnected(caps({ clipboard_send: false }))
    clipboardMock.writeText.mockRejectedValueOnce(new Error('not focused'))

    const stream = {}
    wrapper.vm.handleRemoteClipboard(stream, 'text/plain')
    stream.__reader.emit('deferred-text')
    await flushPromises()

    clipboardMock.writeText.mockResolvedValue(undefined)
    await wrapper.vm.syncClipboardOnFocus()

    expect(clipboardMock.writeText).toHaveBeenLastCalledWith('deferred-text')
    expect(clientMock.createClipboardStream).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
