// GuacamolePlayer 的初始定位。
//
// 本檔守的是一個**靜默失敗**：guacamole-common-js 的 SessionRecording.seek 在
// frames 尚未解析出來時是 no-op（`this.seek=function(b,d){if(0!==c.length)...`），
// 呼叫端拿不到任何錯誤。若在載入完成前就下 seek，畫面會停在開頭而介面顯示
// 「已定位」——稽核會把開頭那一幕讀成目標時刻。故：
//   1. 解析尚未越過目標時刻，**不得**呼叫 seek；
//   2. 解析越過目標後才 seek，且只 seek 一次；
//   3. 目標超過總時長時夾到末端並以 clamped 回報（不得靜默裝作成功）。
//   4. （5.4 修復）回報的 `applied` 必須是 `getPosition()` 的**實際落點**，不是請求值；
//      且稀疏幀錄影下挑的是「目標之前最近的一幀」，不把目標秒數丟給 seek。
//
// **涵蓋邊界（誠實標註）**：jsdom 無法真正播放 guacamole 錄影，本檔的 SessionRecording
// 是 stub——它能釘住的只有**結構與資料流**（seek 拿到哪個毫秒、emit 的值從哪裡來、
// 只 emit 一次）。「真實 `.guac` 稀疏幀下播放器停在哪一秒」**只能由瀏覽器實測覆蓋**
// （verification.md 5.4 複驗段）。stub 的 `getPosition` 刻意回傳與請求值不同的值，
// 就是為了讓「回報請求值」這種假綠在單測層即轉紅。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

// 元件在 module 層讀 window.Guacamole，必須在 import 前注入
const { instances } = vi.hoisted(() => {
  const instances = []

  class SessionRecordingMock {
    constructor() {
      this.seekCalls = []
      this.durationMs = 0
      this.positionMs = 0
      // 已解析出的幀時間戳（毫秒）。空陣列＝不模擬幀，落點即 seek 引數
      this.frames = []
      this.onload = null
      this.onprogress = null
      this.onplay = null
      this.onpause = null
      this.onseek = null
      this.onerror = null
      instances.push(this)
    }
    getDisplay() {
      return {
        getElement: () => document.createElement('div'),
        showCursor: () => {},
      }
    }
    getDuration() {
      return this.durationMs
    }
    getPosition() {
      return this.positionMs
    }
    isPlaying() {
      return false
    }
    play() {}
    pause() {}
    // 模擬 guacamole 的落幀行為：落在**目標之後**最近的可用幀（實測 5.4：
    // t=10.003 落在 30.574s）。故元件若把目標秒數直接丟給 seek，落點就會偏晚——
    // 這正是本檔要擋的假綠。
    landingFor(ms) {
      if (this.frames.length === 0) return ms
      const after = this.frames.find((f) => f >= ms)
      return after === undefined ? this.frames[this.frames.length - 1] : after
    }
    seek(ms, cb) {
      this.seekCalls.push(ms)
      this.positionMs = this.landingFor(ms)
      cb?.()
    }
  }

  globalThis.window.Guacamole = { SessionRecording: SessionRecordingMock }
  return { instances }
})

import GuacamolePlayer from '../GuacamolePlayer.vue'

const mountPlayer = (startAt) =>
  mount(GuacamolePlayer, {
    props: { recordingUrl: '/api/v1/sessions/1/recording', autoPlay: false, startAt },
    global: { plugins: [ElementPlus] },
  })

beforeEach(() => {
  instances.length = 0
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({ ok: true, status: 200, blob: async () => new Blob(['x']) })
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('GuacamolePlayer 初始定位須等解析到位', () => {
  it('解析尚未越過目標時刻時不呼叫 seek（否則是 no-op 的假成功）', async () => {
    const wrapper = mountPlayer(120)
    await flushPromises()

    const rec = instances[0]
    expect(rec).toBeTruthy()
    expect(rec.seekCalls).toEqual([])

    // 只解析到 60 秒，目標在 120 秒——仍不得 seek
    rec.onprogress(60_000, 0)
    await flushPromises()
    expect(rec.seekCalls).toEqual([])
    expect(wrapper.find('[data-test="guac-seek-pending"]').exists()).toBe(true)
  })

  it('解析越過目標後才 seek，且只 seek 一次', async () => {
    const wrapper = mountPlayer(120)
    await flushPromises()
    const rec = instances[0]

    // 逐幀解析：60s 與 130s 兩幀，目標 120s 落在兩者之間的空檔
    rec.onprogress(60_000, 0)
    rec.onprogress(130_000, 0)
    await flushPromises()

    // 目標之前最近的一幀是 60s——不得把 120_000 丟給 seek（那會落到 130s、目標之後）
    expect(rec.seekCalls).toEqual([60_000])

    // 後續進度回報與 onload 都不得再 seek 一次
    rec.onprogress(200_000, 0)
    rec.durationMs = 200_000
    rec.onload()
    await flushPromises()
    expect(rec.seekCalls).toEqual([60_000])

    const applied = wrapper.emitted('start-at-applied')
    expect(applied).toHaveLength(1)
    expect(applied[0][0]).toMatchObject({ requested: 120, applied: 60, clamped: false })
    expect(wrapper.find('[data-test="guac-seek-pending"]').exists()).toBe(false)
  })

  it('目標超過總時長：夾到末端並回報 clamped，不靜默裝作成功', async () => {
    const wrapper = mountPlayer(999)
    await flushPromises()
    const rec = instances[0]

    rec.durationMs = 90_000
    rec.onprogress(90_000, 0)
    await flushPromises()
    // 尚未 onload 前不能斷定越界（後面可能還有幀），故此時仍不 seek
    expect(rec.seekCalls).toEqual([])

    rec.onload()
    await flushPromises()

    expect(rec.seekCalls).toEqual([90_000])
    expect(wrapper.emitted('start-at-applied')[0][0]).toMatchObject({
      requested: 999,
      applied: 90,
      clamped: true,
    })
  })

  it('未給 start-at 時完全不 seek（行為與改動前相同）', async () => {
    const wrapper = mountPlayer(null)
    await flushPromises()
    const rec = instances[0]

    rec.durationMs = 90_000
    rec.onprogress(90_000, 0)
    rec.onload()
    await flushPromises()

    expect(rec.seekCalls).toEqual([])
    expect(wrapper.emitted('start-at-applied')).toBeUndefined()
    expect(wrapper.find('[data-test="guac-seek-pending"]').exists()).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// 5.4 FAIL 的修復守衛。
//
// 原缺陷：`.guac` 是稀疏幀（RDP 畫面靜止時 guacd 不寫幀），實測 session-33 在
// 4.034s→30.574s 之間有 26.5 秒完全無幀；guacamole 的 seek 落在目標**之後**的幀，
// 而元件回報的是**請求值**，於是介面對稽核宣稱「回放 00:10」、播放器實際停在 30.574s。
//
// **本區塊的涵蓋邊界**：以 stub 釘住「挑哪一幀」與「回報哪個數字」兩件**結構**事實。
// 真實錄影的落點（例如 session-33 的 `?t=10` 究竟停在幾秒）**單測無法覆蓋**，
// 只能由瀏覽器實測（verification.md 5.4 複驗段的實測數值）。
// ---------------------------------------------------------------------------
describe('GuacamolePlayer 稀疏幀下的落點與回報', () => {
  // 實測 session-33 的 11 個 sync 幀時間戳（毫秒）
  const SESSION_33_FRAMES = [0, 265, 2138, 3433, 3502, 3672, 3776, 3820, 3909, 4034, 30574]

  const feedFrames = async (rec, frames) => {
    rec.frames = frames
    for (const ts of frames) rec.onprogress(ts, 0)
    await flushPromises()
  }

  it('目標落進無幀空檔：定位到目標之前最近的一幀，不落到空檔尾端（不得偏晚）', async () => {
    const wrapper = mountPlayer(10) // 原 FAIL 案例：?t=10
    await flushPromises()
    const rec = instances[0]
    rec.durationMs = 30574

    await feedFrames(rec, SESSION_33_FRAMES)

    // 目標 10_000ms 落在 4034→30574 的空檔內：取 4034（之前最近），非 30574（之後）
    expect(rec.seekCalls).toEqual([4034])
    expect(rec.getPosition()).toBe(4034)

    const payload = wrapper.emitted('start-at-applied')[0][0]
    expect(payload.requested).toBe(10)
    expect(payload.applied).toBeCloseTo(4.034, 3)
    expect(payload.clamped).toBe(false)
    // 落點在目標之前＝寧早勿晚，與文字終端同一側
    expect(payload.applied).toBeLessThan(payload.requested)
  })

  it('回報的 applied 取自 getPosition()，不是請求值（播放器落在哪就說哪）', async () => {
    const wrapper = mountPlayer(3) // 目標 3s，幀表中之前最近的一幀是 2138
    await flushPromises()
    const rec = instances[0]
    rec.durationMs = 30574

    await feedFrames(rec, SESSION_33_FRAMES)
    expect(rec.seekCalls).toEqual([2138])

    const payload = wrapper.emitted('start-at-applied')[0][0]
    // 若回報請求值，這裡會是 3；若回報 seek 引數而非實際位置，也仍是 2.138——
    // 故下一個案例以「位置與 seek 引數刻意不同」把資料來源釘死
    expect(payload.applied).toBeCloseTo(2.138, 3)
  })

  it('落點與 seek 引數不同時（播放器自行落在別處），回報的是播放器的位置', async () => {
    const wrapper = mountPlayer(120)
    await flushPromises()
    const rec = instances[0]

    // 播放器把 seek 落在別的地方（真實 guacamole 由內部二分搜尋決定，呼叫端無從指定）
    rec.seek = (ms, cb) => {
      rec.seekCalls.push(ms)
      rec.positionMs = 77_777
      cb?.()
    }

    rec.onprogress(60_000, 0)
    rec.onprogress(130_000, 0)
    await flushPromises()

    const payload = wrapper.emitted('start-at-applied')[0][0]
    expect(rec.seekCalls).toEqual([60_000])
    expect(payload.applied).toBeCloseTo(77.777, 3) // ≠ 請求值 120，也 ≠ seek 引數 60
    expect(payload.requested).toBe(120)
  })

  it('seek 未回呼（落點未知）時不回報定位成功，「定位中」維持顯示', async () => {
    const wrapper = mountPlayer(10)
    await flushPromises()
    const rec = instances[0]
    rec.durationMs = 30574
    rec.seek = (ms) => {
      rec.seekCalls.push(ms) // 刻意不呼叫 callback
    }

    await feedFrames(rec, SESSION_33_FRAMES)

    expect(rec.seekCalls).toEqual([4034])
    // 寧可停在「定位中」，也不得在落點未知時宣稱已定位
    expect(wrapper.emitted('start-at-applied')).toBeUndefined()
    expect(wrapper.find('[data-test="guac-seek-pending"]').exists()).toBe(true)
  })
})
