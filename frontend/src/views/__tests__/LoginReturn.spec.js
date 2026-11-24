// 登入後回到原頁：涵蓋各種登入分支。
//
// 登入頁把網址上的 next 原樣交給伺服端，只保存回應的 redirect_next，之後的驗證碼、綁定、
// 改密步驟完成時都導向它；單一登入失敗或返回後不恢復；帶 source 的登入測試連結忽略 next。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Login from '../Login.vue'
import { resetSessionForTests } from '@/utils/session'
import { SSO_SECRET_KEY } from '@/utils/sso'
import { createAuthGuard } from '@/router'
import routerInstance from '@/router'

enableAutoUnmount(afterEach)

const pushMock = vi.fn()
const loginMock = vi.fn()
const verifyMFAMock = vi.fn()
const changePasswordMock = vi.fn()
const enrollSetupMock = vi.fn()
const enrollConfirmMock = vi.fn()
const getAuthMethodsMock = vi.fn()
const exchangeSSOTicketMock = vi.fn()
const buildOIDCBeginURLMock = vi.fn((id, binding) => `/api/v1/auth/oidc/${id}/begin?binding=${binding}`)
const connectMocks = {
  createConnectToken: vi.fn(),
  createConnectTokenWithConsent: vi.fn(),
  createTransmissionConsent: vi.fn(),
}

vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, useRouter: () => ({ push: pushMock }) }
})
vi.mock('@/api/auth', () => ({
  login: (...a) => loginMock(...a),
  verifyMFA: (...a) => verifyMFAMock(...a),
  changePassword: (...a) => changePasswordMock(...a),
  mfaEnrollSetup: (...a) => enrollSetupMock(...a),
  mfaEnrollConfirm: (...a) => enrollConfirmMock(...a),
  getCurrentUser: vi.fn(),
  logout: vi.fn(),
}))
vi.mock('@/api/oidc', () => ({
  getAuthMethods: (...a) => getAuthMethodsMock(...a),
  buildOIDCBeginURL: (...a) => buildOIDCBeginURLMock(...a),
  exchangeSSOTicket: (...a) => exchangeSSOTicketMock(...a),
}))
vi.mock('@/api/loginBanner', () => ({ getLoginBanner: vi.fn().mockResolvedValue({ enabled: false }) }))
vi.mock('@/api/connect', () => ({
  createConnectToken: (...a) => connectMocks.createConnectToken(...a),
  createConnectTokenWithConsent: (...a) => connectMocks.createConnectTokenWithConsent(...a),
  createTransmissionConsent: (...a) => connectMocks.createTransmissionConsent(...a),
  confirmTransmissionRisks: vi.fn(),
  resolveConnectError: vi.fn(),
}))
vi.mock('qrcode', () => ({ default: { toCanvas: vi.fn().mockResolvedValue(undefined) } }))

const USER = { username: 'lin.mei', display_name: 'Lin', roles: ['approver'] }
const DIRECT = '/approvals?tab=pending&request=42'
// 回應刻意與網址上的值不同，證明採用的是回應
const SERVER_NEXT = '/approvals?request=42'

const setUrl = (pathAndQuery) => window.history.replaceState({}, '', pathAndQuery)
const loginUrlWithNext = (next) => `/login?${new URLSearchParams({ next }).toString()}`

const mountLogin = () => mount(Login, { global: { plugins: [ElementPlus] } })

const submitCredentials = async (wrapper, password = 'right-pass') => {
  const inputs = wrapper.findAll('input')
  await inputs[0].setValue('lin.mei')
  await inputs[1].setValue(password)
  await wrapper.find('.login-btn').trigger('click')
  await flushPromises()
}

const enterMfaCode = async (wrapper) => {
  await wrapper.find('.mfa-input input').setValue('123456')
  await wrapper.find('.mfa-verify-btn').trigger('click')
  await flushPromises()
}

const submitNewPassword = async (wrapper) => {
  const pw = wrapper.findAll('input[type="password"]')
  await pw[1].setValue('new-pass-12345')
  await pw[2].setValue('new-pass-12345')
  await wrapper.find('.login-btn').trigger('click')
  await flushPromises()
}

const lastPush = () => pushMock.mock.calls.at(-1)?.[0]

describe('登入後回到原頁：帳號密碼的各分支', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: [] })
    enrollSetupMock.mockResolvedValue({ secret: 'S', otpauth_url: 'otpauth://x' })
    setUrl(loginUrlWithNext(DIRECT))
  })
  afterEach(() => setUrl('/'))

  it('(a) 直接完成：送出網址上的 next，導向回應的 redirect_next（不是網址上的值）', async () => {
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: SERVER_NEXT })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenCalledWith({ username: 'lin.mei', password: 'right-pass', next: DIRECT })
    expect(lastPush()).toBe(SERVER_NEXT)
  })

  it('(a) 驗證碼：第一步回傳的 redirect_next 在驗證通過後採用', async () => {
    loginMock.mockResolvedValue({ mfa_required: true, pending_token: 'p', redirect_next: SERVER_NEXT })
    verifyMFAMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(pushMock).not.toHaveBeenCalled()
    await enterMfaCode(wrapper)
    expect(lastPush()).toBe(SERVER_NEXT)
  })

  it('(a) 強制綁定驗證器：綁定完成後採用第一步的 redirect_next', async () => {
    loginMock.mockResolvedValue({ mfa_enrollment_required: true, enrollment_token: 'e', redirect_next: SERVER_NEXT })
    enrollConfirmMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    await enterMfaCode(wrapper)
    expect(enrollConfirmMock).toHaveBeenCalledWith('123456', 'e')
    expect(lastPush()).toBe(SERVER_NEXT)
  })

  it('(a) 強制改密：改密完成後採用第一步的 redirect_next', async () => {
    loginMock.mockResolvedValue({ password_change_required: true, change_token: 'c', redirect_next: SERVER_NEXT })
    changePasswordMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    await submitNewPassword(wrapper)
    expect(lastPush()).toBe(SERVER_NEXT)
  })

  it('(a) 驗證碼之後才強制改密：改密完成後仍採用第一步的 redirect_next', async () => {
    loginMock.mockResolvedValue({ mfa_required: true, pending_token: 'p', redirect_next: SERVER_NEXT })
    verifyMFAMock.mockResolvedValue({ password_change_required: true, change_token: 'c' })
    changePasswordMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    await enterMfaCode(wrapper)
    await submitNewPassword(wrapper)
    expect(lastPush()).toBe(SERVER_NEXT)
  })

  it('回應的 redirect_next 為 / 或缺席時導向儀表板', async () => {
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: '/' })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(lastPush()).toBe('/dashboard')
  })

  it('(b) 密碼錯誤後再登入：第二次仍帶網址上的 next 並回到原頁', async () => {
    loginMock.mockRejectedValueOnce({ response: { status: 401, data: { code: 'AUTH_INVALID_CREDENTIALS' } } })
    loginMock.mockResolvedValueOnce({ token: 't', user: USER, redirect_next: DIRECT })
    const wrapper = mountLogin()
    await submitCredentials(wrapper, 'wrong')
    expect(pushMock).not.toHaveBeenCalled()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenNthCalledWith(1, expect.objectContaining({ next: DIRECT }))
    expect(loginMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ next: DIRECT }))
    expect(lastPush()).toBe(DIRECT)
  })

  it('(b) 帳號被鎖後再登入：仍帶網址上的 next', async () => {
    loginMock.mockRejectedValueOnce({ response: { status: 423, data: { code: 'AUTH_ACCOUNT_LOCKED' } } })
    loginMock.mockResolvedValueOnce({ token: 't', user: USER, redirect_next: DIRECT })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ next: DIRECT }))
    expect(lastPush()).toBe(DIRECT)
  })

  it('(b) 驗證碼步驟按返回再登入：重新以網址上的 next 送出', async () => {
    loginMock.mockResolvedValueOnce({ mfa_required: true, pending_token: 'p', redirect_next: SERVER_NEXT })
    loginMock.mockResolvedValueOnce({ token: 't', user: USER, redirect_next: DIRECT })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    await wrapper.find('.mfa-back-btn').trigger('click')
    await flushPromises()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ next: DIRECT }))
    expect(lastPush()).toBe(DIRECT)
  })

  it('(d) 帶 source 的登入測試連結：忽略 next，登入請求不帶目的地', async () => {
    setUrl(`/login?source=oidc:3&${new URLSearchParams({ next: DIRECT }).toString()}`)
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: '/' })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenCalledWith({ username: 'lin.mei', password: 'right-pass' })
    expect(lastPush()).toBe('/dashboard')
  })

  it('沒有 next 時登入請求與既有形狀相同（不帶 next 欄位）', async () => {
    setUrl('/login')
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: '/' })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenCalledWith({ username: 'lin.mei', password: 'right-pass' })
  })
})

describe('登入後回到原頁：單一登入', () => {
  let assignSpy
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: [{ id: 3, name: 'Azure AD' }] })
    assignSpy = vi.spyOn(window.location, 'assign').mockImplementation(() => {})
  })
  afterEach(() => {
    assignSpy.mockRestore()
    setUrl('/')
  })

  it('發起時把網址上的 next 交給 buildOIDCBeginURL', async () => {
    setUrl(loginUrlWithNext(DIRECT))
    const wrapper = mountLogin()
    await flushPromises()
    await wrapper.find('.sso-btn').trigger('click')
    await vi.waitFor(() => expect(buildOIDCBeginURLMock).toHaveBeenCalled())
    expect(buildOIDCBeginURLMock.mock.calls[0][2]).toBe(DIRECT)
  })

  it('(c) /login#sso_ticket= 兌換成功後經驗證碼完成：落在兌換回應的 redirect_next', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret')
    setUrl('/login#sso_ticket=ticket-1')
    exchangeSSOTicketMock.mockResolvedValue({ login: { mfa_required: true, pending_token: 'p' }, redirect_next: DIRECT })
    verifyMFAMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await flushPromises()
    await enterMfaCode(wrapper)
    expect(lastPush()).toBe(DIRECT)
  })

  it('(c) /login#sso_error= 之後改帳密登入：網址上已沒有 next，落在儀表板', async () => {
    setUrl('/login#sso_error=oidc_admission_denied')
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: '/' })
    const wrapper = mountLogin()
    await flushPromises()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenCalledWith({ username: 'lin.mei', password: 'right-pass' })
    expect(lastPush()).toBe('/dashboard')
  })

  it('(c) 兌換回 423 之後改帳密登入：落在儀表板', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret')
    setUrl('/login#sso_ticket=ticket-2')
    exchangeSSOTicketMock.mockRejectedValue({ response: { status: 423, data: { code: 'AUTH_ACCOUNT_LOCKED' } } })
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: '/' })
    const wrapper = mountLogin()
    await flushPromises()
    await submitCredentials(wrapper)
    expect(loginMock).toHaveBeenCalledWith({ username: 'lin.mei', password: 'right-pass' })
    expect(lastPush()).toBe('/dashboard')
  })

  it('(c) 兌換成功進驗證碼後按返回、改帳密登入：不帶兌換的目的地，落在儀表板', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret')
    setUrl('/login#sso_ticket=ticket-3')
    exchangeSSOTicketMock.mockResolvedValue({ login: { mfa_required: true, pending_token: 'p' }, redirect_next: DIRECT })
    // 帳密這一次刻意走「要驗證碼」再完成，若記憶體裡殘留兌換的目的地就會被採用
    loginMock.mockResolvedValue({ mfa_required: true, pending_token: 'p2' })
    verifyMFAMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await flushPromises()
    await wrapper.find('.mfa-back-btn').trigger('click')
    await flushPromises()
    await submitCredentials(wrapper)
    await enterMfaCode(wrapper)
    expect(loginMock).toHaveBeenCalledWith({ username: 'lin.mei', password: 'right-pass' })
    expect(lastPush()).toBe('/dashboard')
  })
})

describe('(e) 端到端：守衛產生的登入頁網址經登入回到原本的 fullPath', () => {
  // 伺服端判準的等價替身：只接受通知會指到的頁面樣式與三個查詢鍵（後端的完整判準另有表格測試）
  const PATHS = [/^\/approvals$/, /^\/audit-logs$/, /^\/audit\/agent-tasks\/[0-9]{1,10}$/, /^\/agent-breakers$/,
    /^\/alerts$/, /^\/sessions\/[0-9]{1,10}$/, /^\/notification-channels$/]
  const serverSanitize = (raw) => {
    if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/'
    const u = new URL(raw, 'http://x')
    if (!PATHS.some((re) => re.test(u.pathname))) return '/'
    const keep = new URLSearchParams()
    for (const key of ['tab', 'request', 'user_id']) {
      const all = u.searchParams.getAll(key)
      if (all.length > 1 || (all.length === 1 && !/^[A-Za-z0-9_-]{1,32}$/.test(all[0]))) return '/'
      if (all.length === 1) keep.set(key, all[0])
    }
    const qs = keep.toString()
    return qs ? `${u.pathname}?${qs}` : u.pathname
  }

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: [] })
    loginMock.mockImplementation(async (body) => ({ token: 't', user: USER, redirect_next: serverSanitize(body.next) }))
  })
  afterEach(() => setUrl('/'))

  it.each([
    '/approvals?tab=pending&request=42',
    '/approvals?tab=reviews&request=9',
    '/approvals?tab=history&request=12',
    '/audit-logs?tab=reviews',
    '/sessions/42',
  ])('%s', async (fullPath) => {
    const guard = createAuthGuard()
    const r = routerInstance.resolve(fullPath)
    const next = vi.fn()
    await guard({ path: r.path, name: r.name, meta: r.meta, fullPath: r.fullPath, query: r.query }, { path: '/' }, next)
    const href = routerInstance.resolve(next.mock.calls[0][0]).href
    setUrl(href)
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(loginMock.mock.calls[0][0].next).toBe(fullPath)
    expect(lastPush()).toBe(fullPath)
  })
})

describe('8.3 會建立連線的頁面不會因登入被開啟', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: [] })
  })
  afterEach(() => setUrl('/'))

  it('next 被改成 /terminal/7：伺服端回 /，登入後落在儀表板，沒有發出任何建立連線的請求', async () => {
    setUrl(loginUrlWithNext('/terminal/7'))
    loginMock.mockResolvedValue({ token: 't', user: USER, redirect_next: '/' })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    expect(loginMock.mock.calls[0][0].next).toBe('/terminal/7')
    expect(pushMock).toHaveBeenCalledTimes(1)
    expect(lastPush()).toBe('/dashboard')
    for (const fn of Object.values(connectMocks)) expect(fn).toHaveBeenCalledTimes(0)
  })

  it('驗證碼分支同樣落在儀表板', async () => {
    setUrl(loginUrlWithNext('/workspace?asset=3'))
    loginMock.mockResolvedValue({ mfa_required: true, pending_token: 'p', redirect_next: '/' })
    verifyMFAMock.mockResolvedValue({ token: 't', user: USER })
    const wrapper = mountLogin()
    await submitCredentials(wrapper)
    await enterMfaCode(wrapper)
    expect(lastPush()).toBe('/dashboard')
    for (const fn of Object.values(connectMocks)) expect(fn).toHaveBeenCalledTimes(0)
  })
})
