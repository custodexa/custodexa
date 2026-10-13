// 文字播放器讀不到錄影時的呈現。
//
// 播放器自行取得錄影內容一次，再以 data 交給函式庫：函式庫從不自己抓 URL，
// 所以「實際取內容的那次請求」就是本元件發的這一次。它失敗時依回應的機器碼
// 顯示白話說明，不建立播放器（也就不會出現函式庫的錯誤圖示）。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

const { createdSources } = vi.hoisted(() => ({ createdSources: [] }))

vi.mock('asciinema-player', () => ({
  create: (src) => {
    createdSources.push(src)
    return {
      addEventListener() {},
      async getDuration() { return 60 },
      async getCurrentTime() { return 0 },
      async seek() {},
      async play() {},
      async pause() {},
      dispose() {},
    }
  },
}))

import AsciinemaPlayer from '../AsciinemaPlayer.vue'

const jsonResponse = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const castResponse = () => new Response('{"version":2}\n[0.1,"o","hi"]\n', { status: 200 })

const mountPlayer = (url = '/api/v1/recordings/stream?rtoken=a') =>
  mount(AsciinemaPlayer, {
    props: { recordingUrl: url, autoPlay: false },
    global: { plugins: [ElementPlus] },
  })

const overlay = (wrapper) => wrapper.find('[data-test="recording-playback-error"]')

let fetchMock
beforeEach(() => {
  createdSources.length = 0
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})

describe('AsciinemaPlayer 依機器碼呈現讀不到的錄影', () => {
  it('500 INTERNAL_RECORDING_FILE_UNREADABLE → 無法讀取說明，不建立播放器', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(500, { code: 'INTERNAL_RECORDING_FILE_UNREADABLE' }))
    const wrapper = mountPlayer()
    await flushPromises()

    expect(overlay(wrapper).text()).toContain('播放中斷：目前讀不到錄影檔')
    expect(overlay(wrapper).text()).toContain('重新載入播放器')
    expect(createdSources).toHaveLength(0)
    expect(wrapper.find('.ap-player').exists()).toBe(false)
  })

  it('404 NOTFOUND_RECORDING_FILE → 不存在說明', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(404, { code: 'NOTFOUND_RECORDING_FILE' }))
    const wrapper = mountPlayer()
    await flushPromises()

    expect(overlay(wrapper).text()).toContain('播放中斷：錄影檔已不在儲存位置')
    expect(createdSources).toHaveLength(0)
  })

  it('200 正常：以取得的內容建立播放器，無覆蓋層', async () => {
    fetchMock.mockResolvedValueOnce(castResponse())
    const wrapper = mountPlayer()
    await flushPromises()

    expect(overlay(wrapper).exists()).toBe(false)
    expect(createdSources).toHaveLength(1)
    expect(createdSources[0]).toEqual({ data: '{"version":2}\n[0.1,"o","hi"]\n' })
  })

  it('先成功、之後真正取內容的那次回 500：走失敗分支，函式庫從未拿到 URL', async () => {
    fetchMock
      .mockResolvedValueOnce(castResponse())
      .mockResolvedValueOnce(jsonResponse(500, { code: 'INTERNAL_RECORDING_FILE_UNREADABLE' }))
    const wrapper = mountPlayer('/api/v1/recordings/stream?rtoken=a')
    await flushPromises()
    expect(createdSources).toHaveLength(1)

    // 重新取得內容（例如換了一張錄影 token）：這一次的取內容請求失敗
    await wrapper.setProps({ recordingUrl: '/api/v1/recordings/stream?rtoken=b' })
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/recordings/stream?rtoken=b')
    expect(overlay(wrapper).text()).toContain('播放中斷：目前讀不到錄影檔')
    expect(createdSources).toHaveLength(1)
    expect(createdSources.every((src) => typeof src === 'object' && 'data' in src)).toBe(true)
  })

  it('一次播放只發一次帶錄影 token 的取內容請求（變速重建重用內容）', async () => {
    fetchMock.mockResolvedValue(castResponse())
    const wrapper = mountPlayer()
    await flushPromises()

    const select = wrapper.findComponent({ name: 'ElSelect' })
    select.vm.$emit('change', 2)
    await flushPromises()

    expect(createdSources).toHaveLength(2)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
