import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('element-plus', () => ({
  ElMessage: {
    error: vi.fn(),
    success: vi.fn(),
    info: vi.fn(),
  },
}))

import { ElMessage } from 'element-plus'
import axios from 'axios'
import request from '../request'
import { SEAL_PHASE_SEALED, getSealPhase, resetSealPhase } from '@/utils/sealPhase'

// 取得 axios instance 上註冊的攔截器 handlers
const requestHandler = request.interceptors.request.handlers[0]
const responseHandler = request.interceptors.response.handlers[0]

const makeError = (status, data = {}) => ({
  response: { status, data },
})

describe('request interceptor', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('injects Authorization header when token exists', () => {
    localStorage.setItem('token', 'abc123')
    const config = requestHandler.fulfilled({ headers: {} })
    expect(config.headers.Authorization).toBe('Bearer abc123')
  })

  it('does not inject Authorization header when token absent', () => {
    const config = requestHandler.fulfilled({ headers: {} })
    expect(config.headers.Authorization).toBeUndefined()
  })
})

describe('response interceptor', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    // happy-dom 預設路徑為 about:blank，固定為非 /login 起點
    window.location.href = 'http://localhost:3000/dashboard'
  })

  it('unwraps response.data on success', () => {
    const result = responseHandler.fulfilled({ data: { ok: true } })
    expect(result).toEqual({ ok: true })
  })

  it('clears credentials and redirects to /login on 401', async () => {
    localStorage.setItem('token', 'abc123')
    localStorage.setItem('user', '{"username":"admin"}')

    await expect(
      responseHandler.rejected(makeError(401, { code: 'AUTH_TOKEN_INVALID' }))
    ).rejects.toBeTruthy()

    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
    expect(window.location.href).toContain('/login')
  })

  it('maps 400 to server error message', async () => {
    await expect(
      responseHandler.rejected(makeError(400, { error: '參數不合法' }))
    ).rejects.toBeTruthy()
    expect(ElMessage.error).toHaveBeenCalledWith('參數不合法')
  })

  it('shows server error field for any non-401 status', async () => {
    await expect(
      responseHandler.rejected(makeError(403, { error: '您沒有此資產的連線權限' }))
    ).rejects.toBeTruthy()
    expect(ElMessage.error).toHaveBeenCalledWith('您沒有此資產的連線權限')
  })

  it('falls back to generic message with status when error field missing', async () => {
    await expect(responseHandler.rejected(makeError(404))).rejects.toBeTruthy()
    expect(ElMessage.error).toHaveBeenCalledWith('請求失敗 (404)')
  })

  it('shows server error field on 500', async () => {
    await expect(
      responseHandler.rejected(makeError(500, { error: '查詢資產失敗' }))
    ).rejects.toBeTruthy()
    expect(ElMessage.error).toHaveBeenCalledWith('查詢資產失敗')
  })

  it('suppresses toast when skipErrorToast is set', async () => {
    const err = { ...makeError(400, { error: '參數不合法' }), config: { skipErrorToast: true } }
    await expect(responseHandler.rejected(err)).rejects.toBeTruthy()
    expect(ElMessage.error).not.toHaveBeenCalled()
  })

  it('does not toast 423 (account locked shown inline by login/MFA views)', async () => {
    await expect(
      responseHandler.rejected(makeError(423, { error: '帳號已鎖定', code: 'AUTH_ACCOUNT_LOCKED' }))
    ).rejects.toBeTruthy()
    expect(ElMessage.error).not.toHaveBeenCalled()
  })

  it('maps network failure (no response) to connection message', async () => {
    await expect(
      responseHandler.rejected({ request: {} })
    ).rejects.toBeTruthy()
    expect(ElMessage.error).toHaveBeenCalledWith('網路連線失敗，請檢查網路')
  })
})

// auth-hardening 輪2b：401 透明刷新（D6/D10）
describe('response interceptor - token refresh', () => {
  const originalAdapter = request.defaults.adapter
  let adapterMock

  const make401 = (url, headers = { Authorization: 'Bearer stale-jwt' }) => ({
    response: { status: 401, data: { error: '未授權', code: 'AUTH_TOKEN_INVALID' } },
    config: { url, headers, skipErrorToast: true },
  })

  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    window.location.href = 'http://localhost:3000/dashboard'
    // 重試請求走 mock adapter，不發真網路
    adapterMock = vi.fn(async (config) => ({
      data: { ok: true },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }))
    request.defaults.adapter = adapterMock
  })

  afterEach(() => {
    request.defaults.adapter = originalAdapter
    vi.restoreAllMocks()
  })

  it('refreshes access token and retries original request on 401', async () => {
    localStorage.setItem('token', 'stale-jwt')
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({
      data: { token: 'fresh-jwt' },
    })

    const result = await responseHandler.rejected(make401('/users'))

    // 刷新端點以**空本文**呼叫：refresh 憑證是 httpOnly cookie，由瀏覽器自動附帶，
    // JS 讀不到也就帶不進本文；回應僅寫回 access token
    expect(postSpy).toHaveBeenCalledWith(
      '/api/v1/auth/refresh',
      {},
      expect.anything()
    )
    expect(localStorage.getItem('token')).toBe('fresh-jwt')
    expect(localStorage.getItem('refresh_token')).toBeNull()

    // 原請求以新 token 重試且結果透明回傳
    expect(result).toEqual({ ok: true })
    const retriedConfig = adapterMock.mock.calls[0][0]
    expect(retriedConfig.headers.Authorization).toBe('Bearer fresh-jwt')
    expect(retriedConfig._retried).toBe(true)
  })

  // refresh-token-httponly-cookie：憑證是 httpOnly cookie，script 讀不到。
  // 「本地沒有憑證就別打了」這種前置檢查在遷移後只會製造假的失敗——
  // 有沒有憑證只有伺服器答得出來，前端一律送出、由 401 驅動導向登入
  it('attempts refresh even with no credential in localStorage (cookie is invisible to script)', async () => {
    localStorage.setItem('token', 'stale-jwt')
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({
      data: { token: 'fresh-jwt' },
    })

    const result = await responseHandler.rejected(make401('/users'))

    expect(postSpy).toHaveBeenCalledWith('/api/v1/auth/refresh', {}, expect.anything())
    expect(result).toEqual({ ok: true })
  })

  it('does not refresh a business 401 (business code, not token-expiry)', async () => {
    const postSpy = vi.spyOn(axios, 'post')

    // MFA 驗證碼錯是業務 401（RULE_MFA_INVALID_CODE），非 access token 失效 → 不刷新
    await expect(
      responseHandler.rejected({
        response: { status: 401, data: { error: 'MFA 驗證碼錯誤', code: 'RULE_MFA_INVALID_CODE' } },
        config: { url: '/auth/mfa/verify', skipErrorToast: true },
      })
    ).rejects.toBeTruthy()

    expect(postSpy).not.toHaveBeenCalled()
    expect(adapterMock).not.toHaveBeenCalled()
  })

  it('clears session and redirects when refresh fails', async () => {
    localStorage.setItem('token', 'stale-jwt')
    localStorage.setItem('user', '{"username":"admin"}')
    vi.spyOn(axios, 'post').mockRejectedValue(make401('/auth/refresh'))

    await expect(
      responseHandler.rejected(make401('/users'))
    ).rejects.toBeTruthy()

    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
    expect(window.location.href).toContain('/login')
  })

  it('does not refresh again for an already-retried request', async () => {
    const postSpy = vi.spyOn(axios, 'post')

    const err = make401('/users')
    err.config._retried = true
    await expect(responseHandler.rejected(err)).rejects.toBeTruthy()

    expect(postSpy).not.toHaveBeenCalled()
    expect(window.location.href).toContain('/login')
  })

  it('shares a single refresh call across concurrent 401s (single-flight)', async () => {
    localStorage.setItem('token', 'stale-jwt')
    const postSpy = vi.spyOn(axios, 'post').mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(() => resolve({ data: { token: 'fresh-jwt' } }), 10)
        )
    )

    const [a, b] = await Promise.all([
      responseHandler.rejected(make401('/users')),
      responseHandler.rejected(make401('/assets')),
    ])

    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(a).toEqual({ ok: true })
    expect(b).toEqual({ ok: true })
    expect(adapterMock).toHaveBeenCalledTimes(2)
  })
})

// i18n-backend-error-codes New-C2 / 實作審查 P2：401 依 response code 分流，非 URL。
// 雙模端點（同 URL 可回兩類 401）唯有靠 code 才能正確區分。
describe('response interceptor - 401 依 code 分流（New-C2 / 實作審查 P2）', () => {
  const originalAdapter = request.defaults.adapter
  let adapterMock

  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    window.location.href = 'http://localhost:3000/dashboard'
    adapterMock = vi.fn(async (config) => ({
      data: { ok: true },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }))
    request.defaults.adapter = adapterMock
  })

  afterEach(() => {
    request.defaults.adapter = originalAdapter
    vi.restoreAllMocks()
  })

  const reject401 = (code, url, data = {}) =>
    responseHandler.rejected({
      response: { status: 401, data: { code, ...data } },
      config: { url, headers: { Authorization: 'Bearer stale-jwt' }, skipErrorToast: true },
    })

  it('AUTH_TOKEN_INVALID 走刷新，無視 URL（/auth/me 過期→刷新）', async () => {
    localStorage.setItem('token', 'stale-jwt')
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({
      data: { token: 'fresh-jwt' },
    })

    const result = await reject401('AUTH_TOKEN_INVALID', '/auth/me')

    expect(postSpy).toHaveBeenCalled()
    expect(result).toEqual({ ok: true })
  })

  it('雙模端點 /auth/change-password 自願改密過期（AUTH_TOKEN_INVALID）仍刷新（codex 案1）', async () => {
    localStorage.setItem('token', 'stale-jwt')
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({
      data: { token: 'fresh-jwt' },
    })

    const result = await reject401('AUTH_TOKEN_INVALID', '/auth/change-password')

    expect(postSpy).toHaveBeenCalled()
    expect(result).toEqual({ ok: true })
  })

  it('雙模端點 /auth/mfa/disable 密碼錯（AUTH_INVALID_CREDENTIALS）不刷新不導向（codex 案2）', async () => {
    localStorage.setItem('token', 'x')
    const postSpy = vi.spyOn(axios, 'post')

    await expect(
      responseHandler.rejected({
        response: { status: 401, data: { error: '使用者名稱或密碼錯誤', code: 'AUTH_INVALID_CREDENTIALS' } },
        config: { url: '/auth/mfa/disable' },
      })
    ).rejects.toBeTruthy()

    expect(postSpy).not.toHaveBeenCalled()
    expect(adapterMock).not.toHaveBeenCalled()
    expect(localStorage.getItem('token')).toBe('x')
    expect(window.location.href).not.toContain('/login')
  })

  it('業務登入 401（AUTH_INVALID_CREDENTIALS）解析文字、不刷新不導向', async () => {
    localStorage.setItem('token', 'x')
    const postSpy = vi.spyOn(axios, 'post')

    await expect(
      responseHandler.rejected({
        response: { status: 401, data: { error: '使用者名稱或密碼錯誤', code: 'AUTH_INVALID_CREDENTIALS' } },
        config: { url: '/auth/login' },
      })
    ).rejects.toBeTruthy()

    expect(postSpy).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('使用者名稱或密碼錯誤')
    expect(localStorage.getItem('token')).toBe('x')
    expect(window.location.href).not.toContain('/login')
  })

  // 錯版相容（實作審查 P2）：舊後端 401 無 code
  it('無 code 的 401 於非 /auth/* 仍刷新（新前端＋舊後端相容）', async () => {
    localStorage.setItem('token', 'stale-jwt')
    const postSpy = vi.spyOn(axios, 'post').mockResolvedValue({
      data: { token: 'fresh-jwt' },
    })

    const result = await responseHandler.rejected({
      response: { status: 401, data: { error: '未授權' } }, // 無 code
      config: {
        url: '/users',
        headers: { Authorization: 'Bearer stale-jwt' },
        skipErrorToast: true,
      },
    })

    expect(postSpy).toHaveBeenCalled()
    expect(result).toEqual({ ok: true })
  })

  it('無 code 的 401 於 /auth/* 不刷新（沿用舊行為）', async () => {
    const postSpy = vi.spyOn(axios, 'post')

    await expect(
      responseHandler.rejected({
        response: { status: 401, data: { error: '帳密錯誤' } }, // 無 code
        config: { url: '/auth/login', skipErrorToast: true },
      })
    ).rejects.toBeTruthy()

    expect(postSpy).not.toHaveBeenCalled()
  })
})

// 對抗審查 HIGH-2：攔截器是全域唯一的 API 錯誤日誌出口，
// 印出 error 本體即等同把明文憑證與有效 token 寫進 DevTools
describe('攔截器錯誤日誌去識別', () => {
  let consoleSpy

  beforeEach(() => {
    vi.clearAllMocks()
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => consoleSpy.mockRestore())

  const accountError = {
    message: 'Request failed with status code 409',
    config: {
      method: 'post',
      url: '/assets/1/accounts',
      data: JSON.stringify({
        username: 'root',
        password: 'hunter2',
        private_key: '-----BEGIN OPENSSH PRIVATE KEY-----',
      }),
      headers: { Authorization: 'Bearer real-jwt-token' },
      skipErrorToast: true,
    },
    response: { status: 409, data: { code: 'CONFLICT_ACCOUNT_USERNAME' } },
  }

  it('回應錯誤不得把明文憑證或 Authorization 寫進 console', async () => {
    await expect(responseHandler.rejected(accountError)).rejects.toBe(accountError)

    expect(consoleSpy).toHaveBeenCalled()
    const logged = JSON.stringify(consoleSpy.mock.calls)
    expect(logged).not.toContain('hunter2')
    expect(logged).not.toContain('BEGIN OPENSSH PRIVATE KEY')
    expect(logged).not.toContain('real-jwt-token')
    // 仍保留定位資訊，否則除錯不能用
    expect(logged).toContain('/assets/1/accounts')
    expect(logged).toContain('CONFLICT_ACCOUNT_USERNAME')
  })

  it('絕不把 error 物件本身交給 console（config 帶請求本文）', async () => {
    await expect(responseHandler.rejected(accountError)).rejects.toBe(accountError)
    for (const call of consoleSpy.mock.calls) {
      expect(call).not.toContain(accountError)
    }
  })

  it('請求攔截器同樣去識別', () => {
    expect(() => requestHandler.rejected(accountError)).toThrow
    requestHandler.rejected(accountError).catch(() => {})
    const logged = JSON.stringify(consoleSpy.mock.calls)
    expect(logged).not.toContain('hunter2')
  })
})

// 封印閘的執行期訊號（kek-encoding-and-unseal-entry 決策 6 的第 3 個相位來源）：
// 使用者停留於頁面時後端行程重啟而重新封印，導覽守衛不會再跑一次，
// 唯一會撞到的就是下一個 API 呼叫的 503。
describe('封印閘 503 的導向', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    resetSealPhase()
    window.location.href = 'http://localhost:3000/dashboard'
  })

  it('見到 SEAL_SERVICE_SEALED 即回到封印相位並導向 /unseal', async () => {
    localStorage.setItem('token', 'abc123')
    await expect(
      responseHandler.rejected(makeError(503, { code: 'SEAL_SERVICE_SEALED' }))
    ).rejects.toBeTruthy()
    expect(getSealPhase()).toBe(SEAL_PHASE_SEALED)
    expect(window.location.pathname).toBe('/unseal')
    // 封印不是認證失敗：token 仍然有效，解封後照常可用
    expect(localStorage.getItem('token')).toBe('abc123')
  })

  it('已在 /unseal 上時不重複導向（避免導向迴圈）', async () => {
    window.location.href = 'http://localhost:3000/unseal'
    await expect(
      responseHandler.rejected(makeError(503, { code: 'SEAL_SERVICE_SEALED' }))
    ).rejects.toBeTruthy()
    expect(window.location.pathname).toBe('/unseal')
  })

  it('其他 503 不觸發導向（判定走機器碼而非狀態碼）', async () => {
    await expect(
      responseHandler.rejected(makeError(503, { code: 'SEAL_JOURNAL_IO_FAILURE' }))
    ).rejects.toBeTruthy()
    expect(getSealPhase()).not.toBe(SEAL_PHASE_SEALED)
    expect(window.location.pathname).toBe('/dashboard')
  })
})
