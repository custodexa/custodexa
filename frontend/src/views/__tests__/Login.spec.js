import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Login from '../Login.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const pushMock = vi.fn()
const loginMock = vi.fn()
const verifyMFAMock = vi.fn()
const changePasswordMock = vi.fn()
const enrollSetupMock = vi.fn()
const enrollConfirmMock = vi.fn()

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
}))

vi.mock('@/api/auth', () => ({
  login: (...args) => loginMock(...args),
  verifyMFA: (...args) => verifyMFAMock(...args),
  changePassword: (...args) => changePasswordMock(...args),
  mfaEnrollSetup: (...args) => enrollSetupMock(...args),
  mfaEnrollConfirm: (...args) => enrollConfirmMock(...args),
}))

// SSO 端點（idp-oidc-integration）：本檔案的既有案例一律走「無 provider」情境，
// SSO 專屬行為另見 LoginSSO.spec.js
const getAuthMethodsMock = vi.fn()
vi.mock('@/api/oidc', () => ({
  getAuthMethods: (...args) => getAuthMethodsMock(...args),
  buildOIDCBeginURL: () => '/api/v1/auth/oidc/1/begin?binding=x',
  exchangeSSOTicket: vi.fn(),
}))

// happy-dom 無 canvas 2d context——mock qrcode 讓強制註冊步驟的 QR 可測
const toCanvasMock = vi.fn().mockResolvedValue(undefined)
vi.mock('qrcode', () => ({
  default: { toCanvas: (...a) => toCanvasMock(...a) },
}))

const mountLogin = () =>
  mount(Login, { global: { plugins: [ElementPlus] } })

describe('Login', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    getAuthMethodsMock.mockResolvedValue({ local: true, oidc: [] })
  })

  it('blocks submission when fields are empty', async () => {
    const wrapper = mountLogin()
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()
    expect(loginMock).not.toHaveBeenCalled()
  })

  // —— i18n-foundation 2.2：登入前語言切換 ——

  it('pre-login language switch renders English immediately and persists ot-lang', async () => {
    const wrapper = mountLogin()
    expect(wrapper.find('.login-btn').text()).toBe('登入')

    const langDropdown = wrapper
      .findAllComponents({ name: 'ElDropdown' })
      .find((d) => d.find('.lang-switch-label').exists())
    expect(langDropdown, '登入頁應有語言切換入口').toBeTruthy()
    langDropdown.vm.$emit('command', 'en-US')
    await wrapper.vm.$nextTick()

    expect(wrapper.find('.login-btn').text()).toBe('Sign In')
    expect(wrapper.text()).toContain('Open-Source Bastion Host')
    expect(localStorage.getItem('ot-lang')).toBe('en-US')
  })

  it('stores credentials and redirects on successful login', async () => {
    loginMock.mockResolvedValue({
      token: 'jwt-token',
      refresh_token: 'refresh-1',
      user: { username: 'admin', full_name: 'Admin', roles: ['admin'] },
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('admin123')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    expect(loginMock).toHaveBeenCalledWith({
      username: 'admin',
      password: 'admin123',
    })
    expect(localStorage.getItem('token')).toBe('jwt-token')
    // 輪2b（D6）：refresh 憑證一併儲存，供攔截器透明續期
    expect(localStorage.getItem('refresh_token')).toBe('refresh-1')
    expect(JSON.parse(localStorage.getItem('user')).username).toBe('admin')
    expect(pushMock).toHaveBeenCalledWith('/dashboard')
  })

  it('does not store credentials when login fails', async () => {
    loginMock.mockRejectedValue(new Error('bad credentials'))

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('wrong')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    expect(localStorage.getItem('token')).toBeNull()
    expect(pushMock).not.toHaveBeenCalled()
  })

  const loginToMfaStep = async () => {
    loginMock.mockResolvedValue({
      mfa_required: true,
      pending_token: 'pending-jwt',
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('admin123')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()
    return wrapper
  }

  it('switches to MFA code screen when login responds mfa_required', async () => {
    const wrapper = await loginToMfaStep()

    expect(wrapper.find('.mfa-panel').exists()).toBe(true)
    expect(wrapper.find('.mfa-verify-btn').exists()).toBe(true)
    // 第一階段不得儲存 token 或導向
    expect(localStorage.getItem('token')).toBeNull()
    expect(pushMock).not.toHaveBeenCalled()
  })

  it('verifies MFA code, stores token and redirects', async () => {
    verifyMFAMock.mockResolvedValue({
      token: 'final-jwt',
      user: { username: 'admin', full_name: 'Admin', roles: ['admin'] },
    })

    const wrapper = await loginToMfaStep()
    await wrapper.find('.mfa-input input').setValue('123456')
    await wrapper.find('.mfa-verify-btn').trigger('click')
    await flushPromises()

    expect(verifyMFAMock).toHaveBeenCalledWith({
      pending_token: 'pending-jwt',
      code: '123456',
    })
    expect(localStorage.getItem('token')).toBe('final-jwt')
    expect(JSON.parse(localStorage.getItem('user')).username).toBe('admin')
    expect(pushMock).toHaveBeenCalledWith('/dashboard')
  })

  it('does not store token when MFA verification fails', async () => {
    verifyMFAMock.mockRejectedValue(new Error('invalid code'))

    const wrapper = await loginToMfaStep()
    await wrapper.find('.mfa-input input').setValue('000000')
    await wrapper.find('.mfa-verify-btn').trigger('click')
    await flushPromises()

    expect(localStorage.getItem('token')).toBeNull()
    expect(pushMock).not.toHaveBeenCalled()
    // 失敗後清空驗證碼供重試
    expect(wrapper.find('.mfa-input input').element.value).toBe('')
  })

  it('returns to credentials form from MFA screen', async () => {
    const wrapper = await loginToMfaStep()

    await wrapper.find('.mfa-back-btn').trigger('click')
    await flushPromises()

    expect(wrapper.find('.mfa-panel').exists()).toBe(false)
    expect(wrapper.findAll('input').length).toBeGreaterThanOrEqual(2)
  })

  // auth-hardening：強制改密步驟（8.3.5/2.2.2）
  const loginToChangeStep = async () => {
    loginMock.mockResolvedValue({
      password_change_required: true,
      change_token: 'change-jwt',
      policy_hint: '新密碼至少 12 字元，須同時包含字母與數字',
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('admin123')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()
    return wrapper
  }

  it('switches to password change step when login requires it', async () => {
    const wrapper = await loginToChangeStep()

    // 進入改密步驟：政策提示可見、不得儲存 token
    expect(wrapper.text()).toContain('設定新密碼')
    expect(wrapper.text()).toContain('新密碼至少 12 字元')
    expect(localStorage.getItem('token')).toBeNull()
    expect(pushMock).not.toHaveBeenCalled()
    // 目前密碼預填剛輸入的登入密碼
    const pwInputs = wrapper.findAll('input[type="password"]')
    expect(pwInputs[0].element.value).toBe('admin123')
  })

  // 強制改密原因分流（login-password-policy-gate D6）
  it('shows noncompliant reason title with detail from apiError code', async () => {
    loginMock.mockResolvedValue({
      password_change_required: true,
      change_token: 'change-jwt',
      policy_hint: '新密碼至少 12 字元，須同時包含字母與數字',
      password_change_reason: 'policy_noncompliant',
      reason_code: 'RULE_USER_PASSWORD_TOO_SHORT',
      reason_params: { min: 12 },
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('admin123')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('您目前的密碼不符合現行安全政策')
    // 具體違規走 apiError 既有譯文插值
    expect(wrapper.text()).toContain('密碼長度至少需 12 字元')
  })

  it('shows expired reason title; unknown reason falls back to default title', async () => {
    loginMock.mockResolvedValue({
      password_change_required: true,
      change_token: 'change-jwt',
      policy_hint: '',
      password_change_reason: 'password_expired',
    })
    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('admin123')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('密碼已超過最長使用期限')

    // 未知 reason（前後端版本錯位）降級既有 must_change 文案
    loginMock.mockResolvedValue({
      password_change_required: true,
      change_token: 'change-jwt',
      policy_hint: '',
      password_change_reason: 'some_future_reason',
    })
    const wrapper2 = mountLogin()
    const inputs2 = wrapper2.findAll('input')
    await inputs2[0].setValue('admin')
    await inputs2[1].setValue('admin123')
    await wrapper2.find('.login-btn').trigger('click')
    await flushPromises()
    expect(wrapper2.text()).toContain('首次登入或密碼已被重設')
  })

  it('changes password with change token and logs in directly', async () => {
    changePasswordMock.mockResolvedValue({
      token: 'fresh-jwt',
      user: { username: 'admin', full_name: 'Admin', roles: ['admin'] },
    })

    const wrapper = await loginToChangeStep()
    const pwInputs = wrapper.findAll('input[type="password"]')
    await pwInputs[1].setValue('my-new-pass-33')
    await pwInputs[2].setValue('my-new-pass-33')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    expect(changePasswordMock).toHaveBeenCalledWith(
      { old_password: 'admin123', new_password: 'my-new-pass-33' },
      'change-jwt'
    )
    // D12：改密成功直接換發正式 token，不重走登入
    expect(localStorage.getItem('token')).toBe('fresh-jwt')
    expect(pushMock).toHaveBeenCalledWith('/dashboard')
  })

  it('blocks mismatched confirmation and shows policy error inline', async () => {
    changePasswordMock.mockRejectedValue({
      response: { status: 400, data: { error: '密碼長度至少需 12 字元' } },
    })

    const wrapper = await loginToChangeStep()
    const pwInputs = wrapper.findAll('input[type="password"]')

    // 兩次輸入不一致：不打 API
    await pwInputs[1].setValue('my-new-pass-33')
    await pwInputs[2].setValue('different-pass')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()
    expect(changePasswordMock).not.toHaveBeenCalled()

    // 政策違規：錯誤就近顯示於表單內
    await pwInputs[2].setValue('my-new-pass-33')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('密碼長度至少需 12 字元')
    expect(localStorage.getItem('token')).toBeNull()
  })

  // auth-hardening 輪2：MFA 強制註冊步驟（8.4.2）
  it('enters enrollment step and completes binding to log in', async () => {
    loginMock.mockResolvedValue({
      mfa_enrollment_required: true,
      enrollment_token: 'enroll-jwt',
    })
    enrollSetupMock.mockResolvedValue({
      secret: 'JBSWY3DPEHPK3PXP',
      otpauth_url: 'otpauth://totp/x',
    })
    enrollConfirmMock.mockResolvedValue({
      token: 'final-jwt',
      user: { username: 'alice', full_name: 'Alice', roles: ['user'] },
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('alice')
    await inputs[1].setValue('right-pass-1')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    // 進入註冊步驟：拉到 secret 並顯示，不得儲存 token
    expect(enrollSetupMock).toHaveBeenCalledWith('enroll-jwt')
    expect(wrapper.text()).toContain('啟用兩步驟驗證')
    expect(wrapper.text()).toContain('JBSWY3DPEHPK3PXP')
    expect(localStorage.getItem('token')).toBeNull()
    // QR code 以 otpauth URL 渲染（文案「掃描或手動輸入」自此為真）
    expect(wrapper.find('.mfa-qr').exists()).toBe(true)
    expect(toCanvasMock.mock.calls[0][1]).toBe('otpauth://totp/x')

    // 輸入碼完成綁定 → 直接換發正式 token
    await wrapper.find('.mfa-input input').setValue('123456')
    await wrapper.find('.mfa-verify-btn').trigger('click')
    await flushPromises()

    expect(enrollConfirmMock).toHaveBeenCalledWith('123456', 'enroll-jwt')
    expect(localStorage.getItem('token')).toBe('final-jwt')
    expect(pushMock).toHaveBeenCalledWith('/dashboard')
  })

  it('shows enrollment error inline on invalid code', async () => {
    loginMock.mockResolvedValue({
      mfa_enrollment_required: true,
      enrollment_token: 'enroll-jwt',
    })
    enrollSetupMock.mockResolvedValue({ secret: 'SECRET123', otpauth_url: 'x' })
    enrollConfirmMock.mockRejectedValue({
      response: { status: 400, data: { error: 'MFA 驗證碼錯誤' } },
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('alice')
    await inputs[1].setValue('right-pass-1')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    await wrapper.find('.mfa-input input').setValue('000000')
    await wrapper.find('.mfa-verify-btn').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('MFA 驗證碼錯誤')
    expect(localStorage.getItem('token')).toBeNull()
  })

  it('shows lockout alert inside the card on 423', async () => {
    loginMock.mockRejectedValue({
      response: {
        status: 423,
        data: { error: '嘗試次數過多，帳號已暫時鎖定，請稍後再試或聯繫管理員' },
      },
    })

    const wrapper = mountLogin()
    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('admin')
    await inputs[1].setValue('wrong')
    await wrapper.find('.login-btn').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('帳號已暫時鎖定')
    expect(localStorage.getItem('token')).toBeNull()
  })
})
