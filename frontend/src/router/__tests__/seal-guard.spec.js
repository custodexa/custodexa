import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'
import { createSealGuard } from '../index'
import {
  SEAL_PHASE_HALTED,
  SEAL_PHASE_SEALED,
  SEAL_PHASE_UNKNOWN,
  SEAL_PHASE_UNSEALED,
  getSealPhase,
  markSealed,
  publishHaltStatus,
  publishSealStatus,
  resetSealPhase,
} from '@/utils/sealPhase'

// 封印導覽守衛。
//
// 缺陷實測：`KEK_PROVIDER=ui` 的全新安裝，管理員開站 → 被導到登入頁 → 輸入帳密 →
// 得到「系統尚未解封」→ 卡死。`/unseal` 存在且封印期可達，但沒有任何東西會把人
// 送過去。反向的「已解封仍可開解封頁」則平白留一個可互動的對外表單。
// 兩者是**同一個守衛的兩個方向**，故在同一支測試裡一起釘。

// **只攔 axios.get、不整包 mock axios**：整包 mock 會讓 `axios.create` 消失，
// 而 router/index.js 經 MainLayout 拉進 api/request，後者在模組載入期就呼叫它。
// 相位探測刻意走裸 axios（不經 api/request 攔截器，見 utils/sealPhase.js），
// 故 spy 在 axios.get 上即可精確控制探測結果。
let getSpy

const route = (path) => ({ path })

const statusResponse = (state) => ({ data: { state, generation: 0 } })

// 攔下期的封印狀態回應：`state` 仍是 sealed（服務確實未上線），
// 相位判定看 `instance_guard.state`
const haltedResponse = () => ({
  data: { state: 'sealed', generation: 0, instance_guard: { state: 'halted', peers: 0 } },
})

describe('封印導覽守衛', () => {
  let guard
  let next

  beforeEach(() => {
    resetSealPhase()
    getSpy = vi.spyOn(axios, 'get')
    guard = createSealGuard()
    next = vi.fn()
  })

  afterEach(() => {
    getSpy.mockRestore()
  })

  it('封印期自根路徑進站被導向 /unseal', async () => {
    getSpy.mockResolvedValue(statusResponse('sealed'))
    await guard(route('/'), route('/'), next)
    expect(next).toHaveBeenCalledWith('/unseal')
  })

  it('封印期自任一深連結進站皆被導向 /unseal', async () => {
    getSpy.mockResolvedValue(statusResponse('sealed'))
    for (const path of ['/dashboard', '/assets', '/login', '/key-management', '/workspace']) {
      next.mockClear()
      resetSealPhase()
      await guard(route(path), route('/'), next)
      expect(next, `${path} 未被導向解封頁`).toHaveBeenCalledWith('/unseal')
    }
  })

  it('封印期在 /unseal 上放行（否則永遠到不了解封表單）', async () => {
    getSpy.mockResolvedValue(statusResponse('sealed'))
    await guard(route('/unseal'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('sealed-faulted 與 unsealing 同樣視為封印相位', async () => {
    for (const state of ['sealed-faulted', 'unsealing']) {
      next.mockClear()
      resetSealPhase()
      getSpy.mockResolvedValue(statusResponse(state))
      await guard(route('/dashboard'), route('/'), next)
      expect(next, `${state} 未被視為封印`).toHaveBeenCalledWith('/unseal')
    }
  })

  it('已解封時 /unseal 不可達（導離）', async () => {
    getSpy.mockResolvedValue(statusResponse('unsealed'))
    await guard(route('/unseal'), route('/'), next)
    expect(next).toHaveBeenCalledWith('/')
  })

  it('已解封時其他路徑照常放行，且不再重複探測', async () => {
    getSpy.mockResolvedValue(statusResponse('unsealed'))
    await guard(route('/dashboard'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
    await guard(route('/assets'), route('/'), next)
    expect(getSpy).toHaveBeenCalledTimes(1)
  })

  it('解封成功當下不把正在完成流程的人踢掉，其後離開也不被彈回', async () => {
    // 解封頁上：一開始是封印相位
    getSpy.mockResolvedValue(statusResponse('sealed'))
    await guard(route('/unseal'), route('/'), next)
    expect(next).toHaveBeenCalledWith()

    // 解封成功：頁面**沒有導覽**，使用者仍停在 /unseal 看成功畫面。
    // Unseal.vue 把新狀態發佈進相位模組（少了這一步，下一步會被彈回）
    publishSealStatus({ state: 'unsealed' })
    expect(getSealPhase()).toBe(SEAL_PHASE_UNSEALED)

    // 點「前往登入」：這一次導覽讀到的是最新相位，故不被導回 /unseal
    next.mockClear()
    await guard(route('/login'), route('/unseal'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('狀態探測失敗維持未知相位並放行（不以短暫不可用把已解封部署的人踢出）', async () => {
    getSpy.mockRejectedValue(new Error('network down'))
    await guard(route('/dashboard'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
    expect(getSealPhase()).toBe(SEAL_PHASE_UNKNOWN)
    // 未知相位下 /unseal 亦放行（不猜、不阻擋）
    next.mockClear()
    await guard(route('/unseal'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('執行期訊號：收到封印機器碼後回到封印相位並於下次導覽被接住', async () => {
    getSpy.mockResolvedValue(statusResponse('unsealed'))
    await guard(route('/dashboard'), route('/'), next)
    expect(next).toHaveBeenCalledWith()

    // 使用者停留期間後端重啟而重新封印：攔截器見到 SEAL_SERVICE_SEALED
    markSealed()
    expect(getSealPhase()).toBe(SEAL_PHASE_SEALED)

    next.mockClear()
    await guard(route('/assets'), route('/dashboard'), next)
    expect(next).toHaveBeenCalledWith('/unseal')
  })

  it('併發導覽只探測一次（single-flight）', async () => {
    getSpy.mockResolvedValue(statusResponse('sealed'))
    await Promise.all([
      guard(route('/dashboard'), route('/'), next),
      guard(route('/assets'), route('/'), next),
      guard(route('/login'), route('/'), next),
    ])
    expect(getSpy).toHaveBeenCalledTimes(1)
  })
})

// 守衛攔下相位（服務前頁面的路由相位新增 halted）。
//
// 攔下期後端只開 /health、/seal/status 與兩條 instance-guard 端點，`seal/status`
// 的 `state` 仍是 sealed——照封印那一列處理會把人送去一個同樣打不通的解封頁，
// 正是本相位要修的東西。故 halted **先於** sealed 判定。
describe('守衛攔下相位', () => {
  let guard
  let next

  beforeEach(() => {
    resetSealPhase()
    getSpy = vi.spyOn(axios, 'get')
    guard = createSealGuard()
    next = vi.fn()
  })

  afterEach(() => {
    getSpy.mockRestore()
  })

  it('探測到 instance_guard.state=halted 即進入攔下相位', async () => {
    getSpy.mockResolvedValue(haltedResponse())
    await guard(route('/dashboard'), route('/'), next)
    expect(getSealPhase()).toBe(SEAL_PHASE_HALTED)
  })

  it('攔下期自任一路徑進站皆被導向 /instance-guard（含 /unseal）', async () => {
    for (const path of ['/', '/dashboard', '/login', '/unseal', '/workspace', '/key-management']) {
      next.mockClear()
      resetSealPhase()
      getSpy.mockResolvedValue(haltedResponse())
      await guard(route(path), route('/'), next)
      expect(next, `${path} 未被導向攔下頁`).toHaveBeenCalledWith('/instance-guard')
    }
  })

  it('攔下期在 /instance-guard 上放行（否則永遠到不了確認表單）', async () => {
    getSpy.mockResolvedValue(haltedResponse())
    await guard(route('/instance-guard'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('非攔下相位時 /instance-guard 導離（不留一個服務已上線仍可互動的接手表單）', async () => {
    for (const state of ['sealed', 'unsealed', 'sealed-faulted']) {
      next.mockClear()
      resetSealPhase()
      getSpy.mockResolvedValue(statusResponse(state))
      await guard(route('/instance-guard'), route('/'), next)
      expect(next, `${state} 相位下 /instance-guard 未被導離`).toHaveBeenCalledWith('/')
    }
  })

  it('探測失敗（未知相位）對 /instance-guard 放行——不猜、不阻擋', async () => {
    getSpy.mockRejectedValue(new Error('network down'))
    await guard(route('/instance-guard'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
    expect(getSealPhase()).toBe(SEAL_PHASE_UNKNOWN)
  })

  it('確認接手後不把人留在攔下頁：running 清掉攔下相位，離開時不被彈回', async () => {
    getSpy.mockResolvedValue(haltedResponse())
    await guard(route('/instance-guard'), route('/'), next)
    expect(next).toHaveBeenCalledWith()

    // 攔下頁沒有導覽即完成確認，由頁面把新狀態發佈進相位模組
    publishHaltStatus({ state: 'running' })
    expect(getSealPhase()).toBe(SEAL_PHASE_UNKNOWN)

    // 服務起來後的第一次導覽重新探測：已解封即照常放行
    next.mockClear()
    getSpy.mockResolvedValue(statusResponse('unsealed'))
    await guard(route('/login'), route('/instance-guard'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('攔下期由封印狀態發佈：sealed 那一列不得搶先（否則被送去打不通的解封頁）', () => {
    publishSealStatus({ state: 'sealed', instance_guard: { state: 'halted' } })
    expect(getSealPhase()).toBe(SEAL_PHASE_HALTED)
    publishSealStatus({ state: 'sealed', instance_guard: { state: 'held' } })
    expect(getSealPhase()).toBe(SEAL_PHASE_SEALED)
  })
})
