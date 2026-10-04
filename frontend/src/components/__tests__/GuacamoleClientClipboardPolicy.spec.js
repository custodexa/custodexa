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
const { sentClipboard, clients, keyboards } = vi.hoisted(() => {
  const sentClipboard = []
  const clients = []
  const keyboards = []

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
      this.getDisplay = () => ({ getElement: () => element, getWidth: () => 800, getHeight: () => 600, getScale: () => 1, scale() {} })
      this.createClipboardStream = vi.fn(() => ({}))
      this.sendKeyEvent = vi.fn()
      this.sendMouseState = vi.fn()
      this.sendSize = vi.fn()
      this.connect = vi.fn()
      this.disconnect = vi.fn(() => this.onstatechange?.(5))
    }
  }
  globalThis.window.Guacamole = {
    StringReader: StringReaderMock,
    StringWriter: StringWriterMock,
    WebSocketTunnel: function () {},
    Client: ClientMock,
    Mouse: class {},
    Keyboard: class { constructor() { keyboards.push(this) } },
  }

  return { sentClipboard, clients, keyboards }
})

vi.mock('@/api/connect', () => ({ createConnectTokenWithConsent: vi.fn().mockResolvedValue({ connect_token: 'test' }) }))

import GuacamoleClient from '../GuacamoleClient.vue'
import { createConnectTokenWithConsent } from '@/api/connect'
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

  let resizeCallback

  // Drive the real pre-connect load before using the existing clipboard fixture.
  const mountConnected = async (capsPayload) => {
    getTransferCapabilities.mockResolvedValue(capsPayload)
    const wrapper = mountClient()
    resizeCallback([{ contentRect: { width: 800, height: 600 } }])
    await flushPromises()
    wrapper.vm.__test__setConnectedClient(clientMock)
    return wrapper
  }

  beforeEach(() => {
    vi.clearAllMocks()
    sentClipboard.length = 0
    clients.length = 0
    createConnectTokenWithConsent.mockResolvedValue({ connect_token: 'test' })
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
      constructor(callback) { this.callback = callback }
      observe(element) { if (element.classList.contains('display-container')) resizeCallback = this.callback }
      disconnect() {}
    })
  })

  afterEach(() => {
    vi.useRealTimers()
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

  it('政策變更提示與上傳刷新保留剪貼簿基準', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
    const advance = async ms => { await vi.advanceTimersByTimeAsync(ms); await flushPromises() }
    const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r }); return { promise, resolve } }
    const button = (wrapper, text) => wrapper.findAll('.client-toolbar button').find(b => b.text() === text)
    const notice = wrapper => wrapper.find('.policy-notice')
    const start = async (protocol, payload) => {
      getTransferCapabilities.mockReset().mockResolvedValue(payload)
      const wrapper = mount(GuacamoleClient, {
        attachTo: document.body, props: { assetId: 77, protocol, assetName: 'fixture' }, global: { plugins: [ElementPlus] },
      })
      resizeCallback([{ contentRect: { width: 800, height: 600 } }])
      await flushPromises()
      const client = clients.at(-1)
      client.onfilesystem({}, 'disk')
      client.onstatechange(3)
      await flushPromises()
      return { wrapper, client }
    }
    for (const protocol of ['rdp', 'vnc']) {
      for (const send of [false, true]) {
        const baseline = caps({ clipboard_send: send, clipboard_recv: !send, file_download: false, file_delete: false })
        const changed = caps({ clipboard_send: !send, clipboard_recv: send, file_upload: false, file_download: true })
        const { wrapper, client } = await start(protocol, baseline)
        const initialQueries = getTransferCapabilities.mock.calls.length
        expect(button(wrapper, '貼上到遠端').element.disabled).toBe(!send)
        expect(button(wrapper, '取遠端剪貼簿').element.disabled).toBe(send)
        getTransferCapabilities.mockResolvedValue(changed)
        await button(wrapper, '上傳檔案').trigger('click')
        await flushPromises()
        expect(wrapper.vm.canClipboardSend, 'upload refresh must preserve the connect-time clipboard baseline').toBe(send)
        expect(wrapper.vm.canClipboardRecv).toBe(!send)
        expect(initialQueries).toBe(2) // pre-connect + CONNECTED
        expect(button(wrapper, '上傳檔案').element.disabled).toBe(true)
        expect(wrapper.vm.canFileDownload, 'relaxing download cannot bypass handshake baseline').toBe(false)
        expect(wrapper.vm.canFileDelete).toBe(true)
        expect(notice(wrapper).exists(), 'upload refresh is not a clipboard observation').toBe(false)
        clipboardMock.readText.mockClear()
        const queries = getTransferCapabilities.mock.calls.length
        await advance(29999)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(queries)
        await advance(1)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(queries + 1)
        expect(notice(wrapper).exists(), 'periodic clipboard difference must show a notice').toBe(true)
        expect(notice(wrapper).attributes('role')).toBe('status')
        expect(notice(wrapper).attributes('aria-live')).toBe('polite')
        expect(notice(wrapper).text()).toContain('目前查得的剪貼簿政策與連線前不同，重新連線後套用。')
        expect(notice(wrapper).findAll('button')).toHaveLength(1)
        expect(notice(wrapper).find('button').text()).toBe('關閉提示')
        expect(clipboardMock.readText).not.toHaveBeenCalled()
        expect(client.disconnect).not.toHaveBeenCalled()
        const noticeElement = notice(wrapper).element
        await advance(30000)
        expect(notice(wrapper).element).toBe(noticeElement) // no repeat announcement / remount
        const dismiss = notice(wrapper).find('button')
        dismiss.element.focus()
        client.sendKeyEvent.mockClear()
        const keyboard = keyboards.at(-1)
        expect(keyboard.onkeydown(0xff09)).toBe(true) // Tab remains browser navigation
        expect(keyboard.onkeydown(send ? 0x20 : 0xff0d)).toBe(true)
        expect(client.sendKeyEvent).not.toHaveBeenCalled()
        await dismiss.trigger(send ? 'keyup' : 'keydown', { key: send ? ' ' : 'Enter' })
        expect(notice(wrapper).exists()).toBe(false)
        keyboard.onkeyup(send ? 0x20 : 0xff0d) // notice may have disappeared before release
        expect(client.sendKeyEvent).not.toHaveBeenCalled()
        await advance(30000)
        expect(notice(wrapper).exists()).toBe(false)
        const next = caps({ clipboard_send: send, clipboard_recv: send })
        getTransferCapabilities.mockResolvedValue(next)
        const focusCount = getTransferCapabilities.mock.calls.length
        for (let i = 0; i < 3; i++) {
          window.dispatchEvent(new Event('focus'))
          document.dispatchEvent(new Event('visibilitychange'))
        }
        await flushPromises()
        expect(clipboardMock.readText.mock.calls.length > 0).toBe(send) // independent immediate sync
        await advance(4999)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(focusCount)
        await advance(1)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(focusCount + 1)
        expect(notice(wrapper).exists()).toBe(true)
        for (const payload of [null, {}, { capabilities: { clipboard_send: true } }, caps({ clipboard_send: 'false' })]) {
          getTransferCapabilities.mockResolvedValue(payload)
          window.dispatchEvent(new Event('focus'))
          await advance(5000)
          expect(notice(wrapper).exists()).toBe(true)
          expect(wrapper.vm.canClipboardSend).toBe(send)
        }
        for (const error of [new Error('network'), { response: { status: 403 } }, new Error('timeout')]) {
          getTransferCapabilities.mockRejectedValue(error)
          window.dispatchEvent(new Event('focus'))
          await advance(5000)
          expect(notice(wrapper).exists()).toBe(true)
        }
        await notice(wrapper).find('button').trigger('click')
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(notice(wrapper).exists()).toBe(false) // failed read also preserves dismissed tuple
        getTransferCapabilities.mockResolvedValue(next)
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(notice(wrapper).exists()).toBe(false)
        getTransferCapabilities.mockResolvedValue(baseline)
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(notice(wrapper).exists()).toBe(false)
        getTransferCapabilities.mockResolvedValue(next)
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(notice(wrapper).exists()).toBe(true) // returning to baseline clears dismissal
        getTransferCapabilities.mockResolvedValue(caps({ ...baseline.capabilities, file_upload: false, file_download: true, file_delete: true }))
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(notice(wrapper).exists()).toBe(false) // file-only changes
        expect(wrapper.vm.canFileUpload).toBe(false)
        expect(wrapper.vm.canFileDownload).toBe(false)
        expect(wrapper.vm.canFileDelete).toBe(true)
        const late = deferred()
        getTransferCapabilities.mockReturnValue(late.promise)
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        const inFlightCount = getTransferCapabilities.mock.calls.length
        window.dispatchEvent(new Event('focus'))
        document.dispatchEvent(new Event('visibilitychange'))
        await advance(30000)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(inFlightCount)
        client.onstatechange(5)
        await flushPromises()
        const disconnectedCount = getTransferCapabilities.mock.calls.length
        window.dispatchEvent(new Event('focus'))
        await advance(30000)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(disconnectedCount)
        getTransferCapabilities.mockResolvedValue(changed)
        await button(wrapper, '連線到 fixture').trigger('click')
        resizeCallback([{ contentRect: { width: 800, height: 600 } }])
        await flushPromises()
        const reconnected = clients.at(-1)
        reconnected.onfilesystem({}, 'disk')
        reconnected.onstatechange(3)
        await flushPromises()
        expect(wrapper.vm.canClipboardSend).toBe(!send)
        expect(wrapper.vm.canClipboardRecv).toBe(send)
        expect(wrapper.vm.canFileDownload).toBe(true)
        expect(wrapper.vm.canFileUpload).toBe(false)
        getTransferCapabilities.mockResolvedValue(caps())
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(wrapper.vm.canFileUpload, 'upload relaxation also waits for reconnect').toBe(false)
        expect(wrapper.vm.canFileDownload).toBe(true)
        getTransferCapabilities.mockResolvedValue(caps({ file_download: false }))
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(wrapper.vm.canFileDownload, 'download tightening applies immediately').toBe(false)
        getTransferCapabilities.mockResolvedValue(caps())
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        expect(wrapper.vm.canFileDownload).toBe(true) // baseline allowed this direction
        const currentNotice = notice(wrapper).element
        late.resolve(caps({ ...next.capabilities, file_download: false }))
        await flushPromises()
        expect(wrapper.vm.canClipboardSend).toBe(!send)
        expect(wrapper.vm.canFileDownload).toBe(true)
        expect(notice(wrapper).element).toBe(currentNotice)
        const pending = deferred()
        getTransferCapabilities.mockReturnValue(pending.promise)
        window.dispatchEvent(new Event('focus'))
        await advance(5000)
        reconnected.onerror({ code: 519, message: 'disconnected' })
        await flushPromises()
        expect(notice(wrapper).exists()).toBe(false)
        expect(wrapper.emitted('status-change').at(-1)).toEqual(['closed'])
        const stopped = getTransferCapabilities.mock.calls.length
        pending.resolve(next)
        await flushPromises()
        expect(notice(wrapper).exists()).toBe(false)
        window.dispatchEvent(new Event('focus'))
        document.dispatchEvent(new Event('visibilitychange'))
        await advance(30000)
        expect(getTransferCapabilities).toHaveBeenCalledTimes(stopped)
        wrapper.unmount()
      }
      // Unknown pre-connect baseline remains unknown even after valid all-denied 200.
      getTransferCapabilities.mockReset().mockRejectedValue(new Error('initial unavailable'))
      const wrapper = mount(GuacamoleClient, { props: { assetId: 77, protocol }, global: { plugins: [ElementPlus] } })
      resizeCallback([{ contentRect: { width: 800, height: 600 } }])
      await flushPromises()
      getTransferCapabilities.mockResolvedValue(caps({ clipboard_send: false, clipboard_recv: false, file_upload: false, file_download: false, file_delete: false }))
      const client = clients.at(-1)
      client.onstatechange(3)
      await flushPromises()
      expect(wrapper.vm.canClipboardSend).toBe(true)
      expect(wrapper.vm.canClipboardRecv).toBe(true)
      expect(wrapper.vm.canFileUpload).toBe(false)
      expect(notice(wrapper).exists()).toBe(false)
      const late = deferred()
      getTransferCapabilities.mockReturnValue(late.promise)
      await advance(30000)
      const beforeUnmount = getTransferCapabilities.mock.calls.length
      wrapper.unmount()
      expect(wrapper.emitted('status-change').at(-1)).toEqual(['closed'])
      late.resolve(caps())
      window.dispatchEvent(new Event('focus'))
      document.dispatchEvent(new Event('visibilitychange'))
      await advance(60000)
      expect(getTransferCapabilities).toHaveBeenCalledTimes(beforeUnmount)
      // Unmount before the pre-connect response must not issue a token or create a client.
      const initial = deferred()
      getTransferCapabilities.mockReturnValue(initial.promise)
      const abandoned = mount(GuacamoleClient, { props: { assetId: 77, protocol }, global: { plugins: [ElementPlus] } })
      resizeCallback([{ contentRect: { width: 800, height: 600 } }])
      const tokensBefore = createConnectTokenWithConsent.mock.calls.length
      abandoned.unmount()
      initial.resolve(caps())
      await flushPromises()
      expect(createConnectTokenWithConsent).toHaveBeenCalledTimes(tokensBefore)
      // A failed token request never starts observation or revives an old notice.
      createConnectTokenWithConsent.mockRejectedValueOnce(new Error('token refused'))
      getTransferCapabilities.mockResolvedValue(caps())
      const failed = mount(GuacamoleClient, { props: { assetId: 77, protocol }, global: { plugins: [ElementPlus] } })
      const clientsBefore = clients.length
      resizeCallback([{ contentRect: { width: 800, height: 600 } }])
      await flushPromises()
      const failedQueries = getTransferCapabilities.mock.calls.length
      window.dispatchEvent(new Event('focus'))
      await advance(60000)
      expect(getTransferCapabilities).toHaveBeenCalledTimes(failedQueries)
      expect(clients).toHaveLength(clientsBefore)
      expect(notice(failed).exists()).toBe(false)
      failed.unmount()
    }
  }, 30000)

})
