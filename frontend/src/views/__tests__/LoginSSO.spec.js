// Login.vue 的 SSO（OIDC）區塊與交棒流程。
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
import { getAccessToken, resetSessionForTests, setAccessToken } from '@/utils/session'
import { login as loginApi } from '@/api/auth'
import { SSO_SECRET_KEY } from '@/utils/sso'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
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

// 登入前告示端點：本檔不驗告示，一律走「未設定」以免掛載時打真的網路請求
const getLoginBannerMock = vi.fn()
vi.mock('@/api/loginBanner', () => ({
  getLoginBanner: (...args) => getLoginBannerMock(...args),
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
    resetSessionForTests()
    sessionStorage.clear()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: PROVIDERS })
    getLoginBannerMock.mockResolvedValue({ enabled: false })
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
    expect(getAccessToken()).toBe('sso-jwt')
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

    expect(getAccessToken()).toBe('')
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
    expect(wrapper.text()).toContain('請聯絡管理員確認')
    expect(window.location.hash).toBe('')
    // 准入不通過不可重試（重試也不會過），不給重新發起按鈕
    expect(wrapper.find('.sso-restart-btn').exists()).toBe(false)
    expect(exchangeSSOTicketMock).not.toHaveBeenCalled()

    setHash('#sso_error=oidc_username_conflict')
    const wrapper2 = mountLogin()
    await flushPromises()
    expect(wrapper2.text()).toContain('帳號名稱衝突，需由管理員處理')
  })

  it.each([
    ['oidc_account_removed', '您在本系統的帳號已被管理者刪除', '請聯絡管理者重新建立帳號並綁定您的外部身分'],
    ['oidc_user_inactive', '您的帳號已停用', '請聯絡管理者重新啟用帳號'],
    ['oidc_code_exchange_failed', '無法向身分提供者完成登入', '常見原因是用戶端密碼錯誤或已過期，請通知系統管理員'],
  ])('sso_error=%s 顯示專屬標題與提示，且不給重新發起（重試不會改變結果）', async (slug, title, hint) => {
    setHash(`#sso_error=${slug}`)
    const wrapper = mountLogin()
    await flushPromises()

    expect(wrapper.find('.sso-alert').exists()).toBe(true)
    expect(wrapper.text()).toContain(title)
    expect(wrapper.text()).toContain(hint)
    // 不得被降級為通用的「流程失效」文案
    expect(wrapper.text()).not.toContain('登入流程已失效')
    expect(wrapper.find('.sso-restart-btn').exists()).toBe(false)
    expect(window.location.hash).toBe('')
    expect(exchangeSSOTicketMock).not.toHaveBeenCalled()
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
    expect(getAccessToken()).toBe('')
    expect(pushMock).not.toHaveBeenCalled()
  })

  it('無 fragment 的一般進站不觸發任何 SSO 動作', async () => {
    mountLogin()
    await flushPromises()

    expect(exchangeSSOTicketMock).not.toHaveBeenCalled()
    expect(replaceStateSpy).not.toHaveBeenCalled()
  })
})

// 登入測試連結（?source=）：只標示、不自動發起；格式不符一律忽略；
// 已登入時不掛載任何登入操作，避免在同一個瀏覽器換掉目前的登入
describe('Login 登入測試標示', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    sessionStorage.clear()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: PROVIDERS, ldap: [{ id: 1 }] })
    getLoginBannerMock.mockResolvedValue({ enabled: false })
    assignSpy = vi.spyOn(window.location, 'assign').mockImplementation(() => {})
  })

  afterEach(() => {
    assignSpy.mockRestore()
    window.history.replaceState({}, '', '/login')
  })

  const mountWithSource = async (source) => {
    window.history.replaceState({}, '', `/login?source=${source}`)
    const wrapper = mountLogin()
    await flushPromises()
    return wrapper
  }

  it('oidc:<在清單>：該按鈕排第一並加標示，不自動發起', async () => {
    const wrapper = await mountWithSource('oidc:7')
    const buttons = wrapper.findAll('.sso-btn')
    expect(buttons[0].text()).toContain('使用 Google Workspace 登入')
    expect(buttons[0].classes()).toContain('sso-btn--testing')
    expect(buttons[0].find('.sso-test-badge').text()).toBe('測試中的登入方式')
    expect(wrapper.findAll('.sso-test-badge')).toHaveLength(1)
    expect(assignSpy).not.toHaveBeenCalled()
  })

  it('oidc:<不在清單>：說明要測的方式不在登入頁', async () => {
    const wrapper = await mountWithSource('oidc:99')
    expect(wrapper.find('[data-test="login-test-notListed"]').exists()).toBe(true)
    expect(wrapper.findAll('.sso-test-badge')).toHaveLength(0)
  })

  it('ldap:1：帳密表單上方說明這是目錄帳號的測試', async () => {
    const wrapper = await mountWithSource('ldap:1')
    expect(wrapper.find('[data-test="login-test-ldap"]').text()).toContain('這是目錄帳號的登入測試')
    expect(wrapper.find('input').attributes('placeholder')).toBe('目錄帳號')
  })

  it('ldap:<不在清單>（停用、已刪除或不存在）：說明不在登入頁，不提示輸入目錄帳號', async () => {
    const wrapper = await mountWithSource('ldap:4')
    expect(wrapper.find('[data-test="login-test-notListed"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="login-test-ldap"]').exists()).toBe(false)
    expect(wrapper.find('input').attributes('placeholder')).toBe('使用者名稱')
  })

  it('格式不符（oidc:abc、x:1）：沒有任何標示', async () => {
    for (const source of ['oidc:abc', 'x:1']) {
      const wrapper = await mountWithSource(source)
      expect(wrapper.find('[data-test^="login-test-"]').exists(), source).toBe(false)
      expect(wrapper.findAll('.sso-test-badge'), source).toHaveLength(0)
      wrapper.unmount()
    }
  })

  it('已登入且帶 source：沒有帳密輸入框與任何單一登入按鈕，只顯示說明，不發起任何登入', async () => {
    setAccessToken('abc')
    const wrapper = await mountWithSource('oidc:7')
    expect(wrapper.find('[data-test="login-test-authed"]').exists()).toBe(true)
    expect(wrapper.find('input[type="password"]').exists()).toBe(false)
    expect(wrapper.findAll('input')).toHaveLength(0)
    expect(wrapper.findAll('.sso-btn')).toHaveLength(0)
    expect(assignSpy).not.toHaveBeenCalled()
    expect(loginApi).not.toHaveBeenCalled()
  })
})
