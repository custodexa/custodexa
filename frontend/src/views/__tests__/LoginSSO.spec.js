// Login.vue 的 SSO（OIDC）區塊與交棒流程（idp-oidc-integration D14.4 / tasks 5.1-5.2）。
//
// 守的是四件會靜默壞掉的事：
//   1. `/auth/methods` 失敗必須降級為「只有本地表單」（封印期該端點為 503）；
//   2. 送出的 binding 必須是 sessionStorage 原值的 SHA-256，**原值不得離開本分頁**；
//   3. fragment 的 ticket 必須在做任何其他事之前就被 replaceState 抹除；
//   4. 跨分頁（sessionStorage 讀不到原值）必須給可行動訊息，不得只說「失敗」。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { createHash } from 'node:crypto'
import Login from '../Login.vue'
import { SSO_SECRET_KEY } from '@/utils/sso'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const pushMock = vi.fn()
const getAuthMethodsMock = vi.fn()
const exchangeSSOTicketMock = vi.fn()
const buildOIDCBeginURLMock = vi.fn(
  (id, binding) => `/api/v1/auth/oidc/${id}/begin?binding=${binding}`
)

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
}))

vi.mock('@/api/auth', () => ({
  login: vi.fn(),
  verifyMFA: vi.fn(),
  changePassword: vi.fn(),
  mfaEnrollSetup: vi.fn().mockResolvedValue({ secret: 'S', otpauth_url: 'otpauth://x' }),
  mfaEnrollConfirm: vi.fn(),
}))

vi.mock('@/api/oidc', () => ({
  getAuthMethods: (...args) => getAuthMethodsMock(...args),
  buildOIDCBeginURL: (...args) => buildOIDCBeginURLMock(...args),
  exchangeSSOTicket: (...args) => exchangeSSOTicketMock(...args),
}))

vi.mock('qrcode', () => ({ default: { toCanvas: vi.fn().mockResolvedValue(undefined) } }))

const PROVIDERS = [
  { id: 3, name: 'Azure AD' },
  { id: 7, name: 'Google Workspace' },
]

const sha256Hex = (v) => createHash('sha256').update(v).digest('hex')

const mountLogin = () => mount(Login, { global: { plugins: [ElementPlus] } })

// 進入登入頁時 URL 帶 fragment（模擬 callback 導回）
const setHash = (hash) => {
  window.history.replaceState({}, '', `/login${hash}`)
}

let assignSpy
let replaceStateSpy

describe('Login SSO 區塊', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: PROVIDERS })
    window.history.replaceState({}, '', '/login')
    assignSpy = vi.spyOn(window.location, 'assign').mockImplementation(() => {})
    replaceStateSpy = vi.spyOn(window.history, 'replaceState')
  })

  afterEach(() => {
    assignSpy.mockRestore()
    replaceStateSpy.mockRestore()
  })

  it('列出縱向 SSO 按鈕與 i18n 分隔線（不硬編碼 Or）', async () => {
    const wrapper = mountLogin()
    await flushPromises()

    const buttons = wrapper.findAll('.sso-btn')
    expect(buttons.length).toBe(2)
    expect(buttons[0].text()).toBe('使用 Azure AD 登入')
    expect(buttons[1].text()).toBe('使用 Google Workspace 登入')
    expect(wrapper.find('.sso-divider-text').text()).toBe('或使用單一登入')
  })

  it('/auth/methods 失敗時降級為只顯示本地表單（封印期 503 亦然）', async () => {
    getAuthMethodsMock.mockRejectedValue({ response: { status: 503 } })

    const wrapper = mountLogin()
    await flushPromises()

    expect(wrapper.findAll('.sso-btn').length).toBe(0)
    expect(wrapper.find('.sso-divider').exists()).toBe(false)
    // 本地表單完好，且不得因清單失敗而顯示錯誤
    expect(wrapper.find('.login-btn').exists()).toBe(true)
    expect(wrapper.find('.sso-alert').exists()).toBe(false)
  })

  it('回應無 oidc 欄位時同樣不渲染 SSO 區塊', async () => {
    getAuthMethodsMock.mockResolvedValue({ local: true })

    const wrapper = mountLogin()
    await flushPromises()

    expect(wrapper.findAll('.sso-btn').length).toBe(0)
  })

  it('MFA 分支不顯示 SSO 區塊（流程中段不給跳出入口）', async () => {
    const wrapper = mountLogin()
    await flushPromises()
    expect(wrapper.findAll('.sso-btn').length).toBe(2)

    // 直接以交棒回應把狀態機推進到 MFA 步驟
    exchangeSSOTicketMock.mockResolvedValue({
      login: { mfa_required: true, pending_token: 'pending-jwt' },
    })
    sessionStorage.setItem(SSO_SECRET_KEY, 'secret-value')
    setHash('#sso_ticket=t-1')
    const wrapper2 = mountLogin()
    await flushPromises()

    expect(wrapper2.find('.mfa-panel').exists()).toBe(true)
    expect(wrapper2.findAll('.sso-btn').length).toBe(0)
    wrapper.unmount()
  })

  it('發起時只送出 secret 的 SHA-256，原值留在 sessionStorage', async () => {
    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.findAll('.sso-btn')[0].trigger('click')
    // crypto.subtle.digest 走 Node threadpool，非單一 microtask 可完成——
    // 只 flushPromises 會在機器負載高時偶發搶跑
    await vi.waitFor(() => expect(buildOIDCBeginURLMock).toHaveBeenCalled())

    const secret = sessionStorage.getItem(SSO_SECRET_KEY)
    expect(secret).toBeTruthy()
    expect(secret).toMatch(/^[0-9a-f]{64}$/)

    expect(buildOIDCBeginURLMock).toHaveBeenCalledTimes(1)
    const [providerId, binding] = buildOIDCBeginURLMock.mock.calls[0]
    expect(providerId).toBe(3)
    expect(binding).toBe(sha256Hex(secret))
    // 原值本身不得出現在導向網址內
    const target = assignSpy.mock.calls[0][0]
    expect(target).toContain(`binding=${sha256Hex(secret)}`)
    expect(target).not.toContain(secret)
  })

  it('callback 返回：先抹除 fragment 再兌換，成功後導向 redirect_next', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret-1')
    setHash('#sso_ticket=ticket-abc')

    let hashAtExchange = 'not-called'
    exchangeSSOTicketMock.mockImplementation(async () => {
      hashAtExchange = window.location.hash
      return {
        login: {
          token: 'sso-jwt',
          user: { username: 'alice', display_name: 'Alice', roles: ['user'] },
        },
        redirect_next: '/assets',
      }
    })

    mountLogin()
    await vi.waitFor(() => expect(exchangeSSOTicketMock).toHaveBeenCalled())
    await flushPromises()

    // 抹除先於兌換：兌換當下網址已無 fragment
    expect(hashAtExchange).toBe('')
    expect(window.location.hash).toBe('')
    expect(replaceStateSpy).toHaveBeenCalled()

    expect(exchangeSSOTicketMock).toHaveBeenCalledWith('ticket-abc', 'browser-secret-1')
    // 綁定原值一次性：兌換後即清除
    expect(sessionStorage.getItem(SSO_SECRET_KEY)).toBeNull()
    expect(localStorage.getItem('token')).toBe('sso-jwt')
    // SSO 的巢狀回應同樣不帶憑證明文：refresh 憑證走 httpOnly cookie
    expect(localStorage.getItem('refresh_token')).toBeNull()
    expect(pushMock).toHaveBeenCalledWith('/assets')
  })

  it('redirect_next 缺席或為根路徑時導向儀表板', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret-1')
    setHash('#sso_ticket=ticket-abc')
    exchangeSSOTicketMock.mockResolvedValue({
      login: { token: 'jwt', user: { username: 'alice', roles: ['user'] } },
      redirect_next: '/',
    })

    mountLogin()
    await vi.waitFor(() => expect(pushMock).toHaveBeenCalledWith('/dashboard'))
  })

  it('交棒回應含 mfa_required 時走既有 MFA 步驟，不存 token', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret-1')
    setHash('#sso_ticket=ticket-abc')
    exchangeSSOTicketMock.mockResolvedValue({
      login: { mfa_required: true, pending_token: 'pending-jwt' },
    })

    const wrapper = mountLogin()
    await vi.waitFor(() => expect(wrapper.find('.mfa-panel').exists()).toBe(true))

    expect(localStorage.getItem('token')).toBeNull()
    expect(pushMock).not.toHaveBeenCalled()
  })

  it('跨分頁（讀不到綁定原值）給可行動訊息與重新發起入口，且不打兌換 API', async () => {
    setHash('#sso_ticket=ticket-abc')
    // sessionStorage 為空＝在別的分頁完成 callback

    const wrapper = mountLogin()
    await flushPromises()

    expect(exchangeSSOTicketMock).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('登入未在原本的分頁完成')
    expect(wrapper.text()).toContain('請回到原分頁完成登入')
    // 泛用錯誤不算數：必須看得到「重新發起」出口
    expect(wrapper.find('.sso-restart-btn').exists()).toBe(true)
    // fragment 仍須已被抹除
    expect(window.location.hash).toBe('')
  })

  it('唯一 provider 時按重新發起直接重走該 provider', async () => {
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: [PROVIDERS[0]] })
    setHash('#sso_ticket=ticket-abc')

    const wrapper = mountLogin()
    await flushPromises()

    await wrapper.find('.sso-restart-btn').trigger('click')
    await vi.waitFor(() => expect(buildOIDCBeginURLMock).toHaveBeenCalledTimes(1))
    expect(buildOIDCBeginURLMock.mock.calls[0][0]).toBe(3)
    expect(assignSpy).toHaveBeenCalled()
  })

  it('sso_error 依 slug 分流呈現（准入未通過／帳號衝突），fragment 一併抹除', async () => {
    setHash('#sso_error=oidc_admission_denied')
    const wrapper = mountLogin()
    await flushPromises()

    expect(wrapper.text()).toContain('您的帳號不符合此登入方式的准入條件')
    expect(wrapper.text()).toContain('請聯繫管理員確認')
    expect(window.location.hash).toBe('')
    // 准入不通過不可重試（重試也不會過），不給重新發起按鈕
    expect(wrapper.find('.sso-restart-btn').exists()).toBe(false)
    expect(exchangeSSOTicketMock).not.toHaveBeenCalled()

    setHash('#sso_error=oidc_username_conflict')
    const wrapper2 = mountLogin()
    await flushPromises()
    expect(wrapper2.text()).toContain('帳號名稱衝突，需由管理員處理')
  })

  it('未知 sso_error slug 降級為流程失效文案（前後端版本錯位不炸）', async () => {
    setHash('#sso_error=some_future_slug')
    const wrapper = mountLogin()
    await flushPromises()

    expect(wrapper.text()).toContain('登入流程已失效')
    expect(wrapper.find('.sso-restart-btn').exists()).toBe(true)
  })

  it('兌換失敗顯示可重試訊息且不存 token', async () => {
    sessionStorage.setItem(SSO_SECRET_KEY, 'browser-secret-1')
    setHash('#sso_ticket=ticket-abc')
    exchangeSSOTicketMock.mockRejectedValue({
      response: { status: 401, data: { code: 'AUTH_OIDC_FLOW_INVALID' } },
    })

    const wrapper = mountLogin()
    await vi.waitFor(() => expect(wrapper.text()).toContain('登入流程已失效，請重新登入'))
    expect(localStorage.getItem('token')).toBeNull()
    expect(pushMock).not.toHaveBeenCalled()
  })

  it('無 fragment 的一般進站不觸發任何 SSO 動作', async () => {
    mountLogin()
    await flushPromises()

    expect(exchangeSSOTicketMock).not.toHaveBeenCalled()
    expect(replaceStateSpy).not.toHaveBeenCalled()
  })
})
