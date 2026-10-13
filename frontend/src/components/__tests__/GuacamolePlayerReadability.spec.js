// 圖形播放器讀不到錄影時的呈現：取內容的那次請求失敗（!response.ok）時，
// 解析錯誤信封依機器碼顯示白話說明；解析不了退回通用文案，不顯示
// 「HTTP <狀態>: <狀態列>」原文。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

// 元件在 module 層讀 window.Guacamole，必須在 import 前注入
const { instances } = vi.hoisted(() => {
  const instances = []
  class SessionRecordingMock {
    constructor() {
      instances.push(this)
    }
    getDisplay() {
      return { getElement: () => document.createElement('div'), showCursor: () => {} }
    }
    getDuration() { return 0 }
    getPosition() { return 0 }
    isPlaying() { return false }
    play() {}
    pause() {}
    seek() {}
  }
  globalThis.window.Guacamole = { SessionRecording: SessionRecordingMock }
  return { instances }
})

import GuacamolePlayer from '../GuacamolePlayer.vue'

const mountPlayer = () =>
  mount(GuacamolePlayer, {
    props: { recordingUrl: '/api/v1/sessions/9/recording/stream', autoPlay: false },
    global: { plugins: [ElementPlus] },
  })

const overlay = (wrapper) => wrapper.find('[data-test="recording-playback-error"]')

let fetchMock
beforeEach(() => {
  instances.length = 0
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})

describe('GuacamolePlayer 依機器碼呈現讀不到的錄影', () => {
  it('500 INTERNAL_RECORDING_FILE_UNREADABLE → 無法讀取說明', async () => {
    fetchMock.mockResolvedValueOnce(new Response(
      JSON.stringify({ code: 'INTERNAL_RECORDING_FILE_UNREADABLE' }),
      { status: 500, statusText: 'Internal Server Error' }))
    const wrapper = mountPlayer()
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/sessions/9/recording/stream')
    expect(overlay(wrapper).text()).toContain('播放中斷：目前讀不到錄影檔')
    expect(wrapper.text()).not.toContain('HTTP 500')
    expect(wrapper.text()).not.toContain('Internal Server Error')
    expect(instances).toHaveLength(0)
  })

  it('404 NOTFOUND_RECORDING_FILE → 不存在說明', async () => {
    fetchMock.mockResolvedValueOnce(new Response(
      JSON.stringify({ code: 'NOTFOUND_RECORDING_FILE' }), { status: 404, statusText: 'Not Found' }))
    const wrapper = mountPlayer()
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(overlay(wrapper).text()).toContain('播放中斷：錄影檔已不在儲存位置')
    expect(wrapper.text()).not.toContain('HTTP 404')
  })

  it('非 JSON 本體 → 通用文案，不顯示 HTTP 狀態列原文', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>bad gateway</html>',
      { status: 502, statusText: 'Bad Gateway' }))
    const wrapper = mountPlayer()
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(overlay(wrapper).text()).toContain('載入失敗')
    expect(overlay(wrapper).text()).toContain('播放器初始化失敗')
    expect(wrapper.text()).not.toContain('HTTP 502')
    expect(wrapper.text()).not.toContain('Bad Gateway')
  })
})
