import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'
import {
  SIGNAL_LOGIN,
  SIGNAL_LOGOUT,
  announceLogin,
  clearSession,
  ensureSession,
  getAccessToken,
  hasSessionHint,
  installCrossTabSync,
  refreshAccessToken,
  resetSessionForTests,
  setAccessToken,
} from '../session'
import {
  hasRefreshSucceeded,
  resetReloginContext,
} from '../reloginContext'

const SIGNAL_KEY = 'ot-session-signal'

// 訊號監聽只掛一次（模組層），與正式啟動路徑相同
installCrossTabSync()

// 他分頁的寫入在真實瀏覽器裡是由 storage 事件送達的；同一個 JS context 內
// localStorage.setItem 不會觸發自己的監聽，故直接派發事件模擬跨分頁
const dispatchSignal = (payload, key = SIGNAL_KEY) => {
  window.dispatchEvent(
    new StorageEvent('storage', {
      key,
      newValue: typeof payload === 'string' ? payload : JSON.stringify(payload),
    })
  )
}

describe('會話模組：記憶體持有與跡象', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    resetReloginContext()
    vi.restoreAllMocks()
    window.location.href = 'http://localhost:3000/dashboard'
  })

  it('token 只存記憶體，讀寫不碰瀏覽器儲存', () => {
    setAccessToken('jwt-in-memory')
    expect(getAccessToken()).toBe('jwt-in-memory')
    expect(localStorage.getItem('token')).toBeNull()
    expect(sessionStorage.getItem('token')).toBeNull()
    // 整份儲存內都不應出現該值
    expect(JSON.stringify(localStorage)).not.toContain('jwt-in-memory')
  })

  it('登入跡象即使用者快取；clearSession 一併清除', () => {
    expect(hasSessionHint()).toBe(false)
    localStorage.setItem('user', '{"username":"admin"}')
    expect(hasSessionHint()).toBe(true)

    setAccessToken('jwt')
    clearSession()
    expect(getAccessToken()).toBe('')
    expect(localStorage.getItem('user')).toBeNull()
    expect(hasSessionHint()).toBe(false)
  })
})

describe('會話模組：頁面載入恢復', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    resetReloginContext()
    vi.restoreAllMocks()
    window.location.href = 'http://localhost:3000/dashboard'
  })

  it('無登入跡象時零網路（不製造拒絕事件）', async () => {
    const postSpy = vi.spyOn(axios, 'post')
    await expect(ensureSession()).resolves.toBe(false)
    expect(postSpy).not.toHaveBeenCalled()
  })

  it('記憶體已有 token 時零網路', async () => {
    const postSpy = vi.spyOn(axios, 'post')
    setAccessToken('already-here')
    await expect(ensureSession()).resolves.toBe(true)
    expect(postSpy).not.toHaveBeenCalled()
  })

  it('有跡象時以空本文換發、寫入記憶體並記下成功續期', async () => {
    localStorage.setItem('user', '{"username":"admin"}')
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockResolvedValue({ data: { token: 'fresh-jwt' } })

    await expect(ensureSession()).resolves.toBe(true)

    expect(postSpy).toHaveBeenCalledWith(
      '/api/v1/auth/refresh',
      {},
      expect.anything()
    )
    expect(getAccessToken()).toBe('fresh-jwt')
    expect(localStorage.getItem('token')).toBeNull()
    expect(sessionStorage.getItem('token')).toBeNull()
    expect(hasRefreshSucceeded()).toBe(true)
  })

  it('換發失敗時清除跡象並回報未登入；再次呼叫不再打網路', async () => {
    localStorage.setItem('user', '{"username":"admin"}')
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockRejectedValue({ response: { status: 401 } })

    await expect(ensureSession()).resolves.toBe(false)
    expect(getAccessToken()).toBe('')
    expect(localStorage.getItem('user')).toBeNull()
    expect(postSpy).toHaveBeenCalledTimes(1)

    await expect(ensureSession()).resolves.toBe(false)
    expect(postSpy).toHaveBeenCalledTimes(1)
  })

  it('三個併發恢復共用一次換發（single-flight）', async () => {
    localStorage.setItem('user', '{"username":"admin"}')
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockResolvedValue({ data: { token: 'fresh-jwt' } })

    const results = await Promise.all([
      ensureSession(),
      ensureSession(),
      ensureSession(),
    ])

    expect(results).toEqual([true, true, true])
    expect(postSpy).toHaveBeenCalledTimes(1)
  })

  it('併發換發共用一次請求且各自取得同一枚新 token', async () => {
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockResolvedValue({ data: { token: 'fresh-jwt' } })

    const tokens = await Promise.all([
      refreshAccessToken('stale'),
      refreshAccessToken('stale'),
    ])

    expect(tokens).toEqual(['fresh-jwt', 'fresh-jwt'])
    expect(postSpy).toHaveBeenCalledTimes(1)
  })

  it('記憶體 token 已比失效者新時短路，不再輪替憑證', async () => {
    const postSpy = vi.spyOn(axios, 'post')
    setAccessToken('newer-jwt')

    await expect(refreshAccessToken('stale-jwt')).resolves.toBe('newer-jwt')
    expect(postSpy).not.toHaveBeenCalled()
  })
})

// 跨分頁的續期序列化
//
// **為什麼需要它**：模組內的 single-flight 只管同一個 JS context。兩個分頁是兩個
// context，各自持有一份 refreshInFlight——同時重新載入就會以同一枚續期憑證併發
// 輪替，而後端的重放偵測會把整個家族撤銷，兩個分頁一起被登出。
// 序列化靠的是 Web Locks：鎖名同源共享，跨分頁生效。
//
// **測試環境沒有 Web Locks**（happy-dom 未實作），故此處注入一份**真的會排隊**的
// 替身：它不是「回傳固定值的 stub」，而是一條有序等待佇列——第二位申請者必須等到
// 第一位釋放才拿得到鎖。要證的性質（先來者未放手時後來者不得發出請求）因此是被
// 執行出來的，不是被 mock 寫死的。
describe('會話模組：跨分頁續期序列化（Web Locks）', () => {
  // 有序佇列版替身：同名鎖一次只有一位持有者
  const installFakeLocks = () => {
    const queues = new Map()
    const seen = []
    const request = (name, fn) => {
      seen.push(name)
      const prev = queues.get(name) || Promise.resolve()
      const mine = prev.then(() => fn())
      // 佇列本身不因回呼失敗而中斷（否則一次失敗會永久卡住該鎖）
      queues.set(
        name,
        mine.then(
          () => undefined,
          () => undefined
        )
      )
      return mine
    }
    Object.defineProperty(window.navigator, 'locks', {
      value: { request },
      configurable: true,
      writable: true,
    })
    return { seen }
  }

  const removeFakeLocks = () => {
    Object.defineProperty(window.navigator, 'locks', {
      value: undefined,
      configurable: true,
      writable: true,
    })
  }

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    resetReloginContext()
    vi.restoreAllMocks()
    window.location.href = 'http://localhost:3000/dashboard'
  })

  afterEach(() => {
    removeFakeLocks()
  })

  it('換發在具名鎖內進行（鎖名同源共享，跨分頁才序列化得起來）', async () => {
    const { seen } = installFakeLocks()
    localStorage.setItem('user', '{"username":"admin"}')
    vi.spyOn(axios, 'post').mockResolvedValue({ data: { token: 'fresh-jwt' } })

    await expect(ensureSession()).resolves.toBe(true)

    expect(seen).toEqual(['custodexa-token-refresh'])
  })

  it('鎖已被他方持有時，本分頁的換發排隊等待，不併發輪替憑證', async () => {
    installFakeLocks()
    localStorage.setItem('user', '{"username":"admin"}')
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockResolvedValue({ data: { token: 'fresh-jwt' } })

    // 他分頁：先取得同一把鎖並持有不放
    let releaseOther
    const otherHolder = new Promise((resolve) => {
      releaseOther = resolve
    })
    navigator.locks.request('custodexa-token-refresh', () => otherHolder)

    const mine = ensureSession()
    // 讓事件圈跑幾輪：若沒有鎖，換發此刻早就發出去了
    await Promise.resolve()
    await Promise.resolve()
    expect(postSpy).not.toHaveBeenCalled()

    releaseOther()
    await expect(mine).resolves.toBe(true)
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(getAccessToken()).toBe('fresh-jwt')
  })

  it('瀏覽器不支援 Web Locks 時退回單頁去重，換發照常完成', async () => {
    removeFakeLocks()
    localStorage.setItem('user', '{"username":"admin"}')
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockResolvedValue({ data: { token: 'fresh-jwt' } })

    const results = await Promise.all([ensureSession(), ensureSession()])

    expect(results).toEqual([true, true])
    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(getAccessToken()).toBe('fresh-jwt')
  })
})

describe('會話模組：跨分頁訊號', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    resetReloginContext()
    vi.restoreAllMocks()
    window.location.href = 'http://localhost:3000/dashboard'
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('登出廣播的內容只有事件與時戳，不含任何憑證', () => {
    setAccessToken('secret-jwt')
    localStorage.setItem('user', '{"username":"admin"}')

    clearSession({ broadcast: true })

    const raw = localStorage.getItem(SIGNAL_KEY)
    expect(raw).toBeTruthy()
    expect(raw).not.toContain('secret-jwt')
    const payload = JSON.parse(raw)
    expect(Object.keys(payload).sort()).toEqual(['at', 'type'])
    expect(payload.type).toBe(SIGNAL_LOGOUT)
  })

  it('登入廣播同樣只帶事件與時戳', () => {
    setAccessToken('secret-jwt')
    announceLogin()
    const payload = JSON.parse(localStorage.getItem(SIGNAL_KEY))
    expect(payload.type).toBe(SIGNAL_LOGIN)
    expect(JSON.stringify(payload)).not.toContain('secret-jwt')
  })

  it('不廣播時不寫訊號（換發終敗不得殃及他分頁的連線）', () => {
    setAccessToken('jwt')
    clearSession()
    expect(localStorage.getItem(SIGNAL_KEY)).toBeNull()
  })

  it('收到登出訊號：清記憶體 token 並導向登入頁', () => {
    const replace = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      pathname: '/dashboard',
      search: '',
      replace,
      reload: vi.fn(),
    })
    setAccessToken('jwt')
    localStorage.setItem('user', '{"username":"admin"}')

    dispatchSignal({ type: SIGNAL_LOGOUT, at: Date.now() })

    expect(getAccessToken()).toBe('')
    expect(localStorage.getItem('user')).toBeNull()
    expect(replace).toHaveBeenCalledWith('/login')
  })

  it('收到登出訊號不再回廣播（否則兩分頁互相回彈）', () => {
    setAccessToken('jwt')
    localStorage.removeItem(SIGNAL_KEY)
    dispatchSignal({ type: SIGNAL_LOGOUT, at: Date.now() })
    expect(localStorage.getItem(SIGNAL_KEY)).toBeNull()
  })

  it('收到登入訊號：停在登入頁的分頁重新載入', () => {
    const reload = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      pathname: '/login',
      search: '',
      replace: vi.fn(),
      reload,
    })

    dispatchSignal({ type: SIGNAL_LOGIN, at: Date.now() })
    expect(reload).toHaveBeenCalled()
  })

  it('收到登入訊號：單一登入交換進行中（帶 ticket）不打斷', () => {
    const reload = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      pathname: '/login',
      search: '?ticket=abc',
      replace: vi.fn(),
      reload,
    })

    dispatchSignal({ type: SIGNAL_LOGIN, at: Date.now() })
    expect(reload).not.toHaveBeenCalled()
  })

  it('收到登入訊號：不在登入頁的分頁不動作', () => {
    const reload = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      pathname: '/dashboard',
      search: '',
      replace: vi.fn(),
      reload,
    })

    dispatchSignal({ type: SIGNAL_LOGIN, at: Date.now() })
    expect(reload).not.toHaveBeenCalled()
  })

  it('其他鍵的變動一律忽略（使用者快取、偏好設定等）', () => {
    const replace = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      pathname: '/dashboard',
      search: '',
      replace,
      reload: vi.fn(),
    })
    setAccessToken('jwt')

    dispatchSignal({ type: SIGNAL_LOGOUT, at: Date.now() }, 'user')
    dispatchSignal({ type: SIGNAL_LOGOUT, at: Date.now() }, 'sidebar-collapsed')

    expect(getAccessToken()).toBe('jwt')
    expect(replace).not.toHaveBeenCalled()
  })

  it('無法解析的訊號值不擲例外、不動會話', () => {
    setAccessToken('jwt')
    expect(() => dispatchSignal('not-json')).not.toThrow()
    expect(getAccessToken()).toBe('jwt')
  })
})
