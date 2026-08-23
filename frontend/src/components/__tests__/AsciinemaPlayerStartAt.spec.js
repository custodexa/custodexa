// AsciinemaPlayer 的初始定位。
//
// 兩件事要守住：
//   1. 給 start-at 時實際落在請求的秒數（不是停在 0——初始化的取時長 dance 原本
//      無條件 seek(0)，那行若回歸就等於定位被靜默吃掉）；
//   2. 請求超過總時長時夾到末端並以 clamped 回報，不假裝成功。
// 另附「不給 prop 時起點為 0」，確保新能力沒有改動既有行為。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

const { createdOptions, instances } = vi.hoisted(() => ({
  createdOptions: [],
  instances: [],
}))

vi.mock('asciinema-player', () => ({
  create: (url, el, opts) => {
    createdOptions.push(opts)
    const inst = {
      duration: instances.__nextDuration ?? 300,
      seekCalls: [],
      position: 0,
      listeners: {},
      addEventListener(name, fn) {
        this.listeners[name] = fn
      },
      async getDuration() {
        return this.duration
      },
      async getCurrentTime() {
        return this.position
      },
      async seek(v) {
        this.seekCalls.push(v)
        this.position = v
      },
      async play() {},
      async pause() {},
      dispose() {},
    }
    instances.push(inst)
    return inst
  },
}))

import AsciinemaPlayer from '../AsciinemaPlayer.vue'

const mountPlayer = (startAt) =>
  mount(AsciinemaPlayer, {
    props: { recordingUrl: '/rec.cast', autoPlay: false, startAt },
    global: { plugins: [ElementPlus] },
  })

beforeEach(() => {
  createdOptions.length = 0
  instances.length = 0
  instances.__nextDuration = 300
})

afterEach(() => {
  vi.clearAllTimers()
})

describe('AsciinemaPlayer 初始定位', () => {
  it('start-at=120 掛載後落在 120（不被初始化流程重置回 0）', async () => {
    const wrapper = mountPlayer(120)
    await flushPromises()

    const inst = instances[0]
    expect(createdOptions[0].startAt).toBe(120)
    expect(await inst.getCurrentTime()).toBeCloseTo(120, 3)
    expect(inst.seekCalls).not.toContain(0)

    const applied = wrapper.emitted('start-at-applied')
    expect(applied).toHaveLength(1)
    expect(applied[0][0]).toMatchObject({ requested: 120, applied: 120, clamped: false })
  })

  it('不給 prop 時起點為 0 且不回報定位', async () => {
    const wrapper = mountPlayer(null)
    await flushPromises()

    expect(createdOptions[0].startAt).toBe(0)
    expect(await instances[0].getCurrentTime()).toBe(0)
    expect(wrapper.emitted('start-at-applied')).toBeUndefined()
  })

  it('超過總時長：夾到末端並回報 clamped', async () => {
    instances.__nextDuration = 90
    const wrapper = mountPlayer(999)
    await flushPromises()

    expect(await instances[0].getCurrentTime()).toBe(90)
    expect(wrapper.emitted('start-at-applied')[0][0]).toMatchObject({
      requested: 999,
      applied: 90,
      clamped: true,
    })
  })
})
