import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Profile from '../Profile.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const getCurrentUserMock = vi.fn()
const getMFASetupMock = vi.fn()
const enableMFAMock = vi.fn()
const disableMFAMock = vi.fn()
const changePasswordMock = vi.fn()
const updateProfileDisplayNameMock = vi.fn()

vi.mock('@/api/auth', () => ({
  getCurrentUser: (...a) => getCurrentUserMock(...a),
  getMFASetup: (...a) => getMFASetupMock(...a),
  enableMFA: (...a) => enableMFAMock(...a),
  disableMFA: (...a) => disableMFAMock(...a),
  changePassword: (...a) => changePasswordMock(...a),
  updateProfileDisplayName: (...a) => updateProfileDisplayNameMock(...a),
}))

// happy-dom 無 canvas 2d context——mock qrcode 讓 MfaQrCode 渲染成功路徑可測
const toCanvasMock = vi.fn().mockResolvedValue(undefined)
vi.mock('qrcode', () => ({
  default: { toCanvas: (...a) => toCanvasMock(...a) },
}))

const accountInfo = {
  id: 5,
  username: 'carol',
  email: 'carol@example.com',
  roles: ['user', 'approver'],
  totp_enabled: false,
}

const mountView = () =>
  mount(Profile, {
    global: { plugins: [ElementPlus] },
  })

describe('Profile 個人資料頁（navigation-ia D3）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getCurrentUserMock.mockResolvedValue(accountInfo)
  })

  it('渲染基本資料：帳號、Email、角色中文、MFA 狀態', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('carol')
    expect(text).toContain('carol@example.com')
    expect(text).toContain('一般使用者')
    expect(text).toContain('審核人員')
    expect(text).toContain('未啟用')
  })

  it('自助改密成功：呼叫既有端點並以回應新 token 組續存', async () => {
    changePasswordMock.mockResolvedValue({
      token: 'new-token',
      user: { username: 'carol', roles: ['user'] },
    })
    const wrapper = mountView()
    await flushPromises()

    Object.assign(wrapper.vm.pwdForm, {
      oldPassword: 'old-pass-123',
      newPassword: 'New-pass-456',
      confirmPassword: 'New-pass-456',
    })
    await wrapper.vm.handleChangePassword()
    await flushPromises()

    expect(changePasswordMock).toHaveBeenCalledWith({
      old_password: 'old-pass-123',
      new_password: 'New-pass-456',
    })
    // 改密撤銷舊 refresh：以新 access token 續存不中斷會話；
    // 新的 refresh 憑證由後端以 httpOnly cookie 換發，前端不經手
    expect(localStorage.getItem('token')).toBe('new-token')
    expect(localStorage.getItem('refresh_token')).toBeNull()
  })

  it('自助改密政策違規：就近顯示錯誤，不寫入 token', async () => {
    const err = new Error('policy')
    err.response = { data: { error: '新密碼不符合密碼政策：至少 12 碼' } }
    changePasswordMock.mockRejectedValue(err)
    const wrapper = mountView()
    await flushPromises()

    Object.assign(wrapper.vm.pwdForm, {
      oldPassword: 'old-pass-123',
      newPassword: 'weak',
      confirmPassword: 'weak',
    })
    await wrapper.vm.handleChangePassword()
    await flushPromises()

    expect(wrapper.text()).toContain('新密碼不符合密碼政策：至少 12 碼')
    expect(localStorage.getItem('token')).toBeNull()
  })

  it('兩次新密碼不一致：表單驗證擋下不打 API', async () => {
    const wrapper = mountView()
    await flushPromises()

    Object.assign(wrapper.vm.pwdForm, {
      oldPassword: 'old-pass-123',
      newPassword: 'New-pass-456',
      confirmPassword: 'Different-789',
    })
    await wrapper.vm.handleChangePassword()
    await flushPromises()

    expect(changePasswordMock).not.toHaveBeenCalled()
  })

  it('LDAP 影子帳號：隱藏改密表單、顯示目錄服務管理提示（ux-consistency D5）', async () => {
    getCurrentUserMock.mockResolvedValue({ ...accountInfo, is_ldap: true })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('此帳號由 LDAP 目錄服務管理')
    expect(wrapper.text()).not.toContain('目前密碼')
    expect(wrapper.findAll('button').some((b) => b.text().includes('更新密碼'))).toBe(false)
  })

  // idp-oidc-integration D14.6：判定自 is_ldap 泛化為 external_credential。
  // 只認 is_ldap 會讓 OIDC 供應帳號（is_ldap=false）看到一個必被後端擋的改密表單
  it('OIDC 外部帳號：改密卡整卡換說明 alert，不出現改密表單', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      is_ldap: false,
      external_credential: true,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('此帳號由外部身分提供者管理')
    expect(wrapper.text()).not.toContain('目前密碼')
    expect(wrapper.findAll('button').some((b) => b.text().includes('更新密碼'))).toBe(false)
    // 身分欄位說明亦走外部提供者措辭（非目錄服務）
    expect(wrapper.text()).toContain('身分欄位由外部身分提供者管理')
  })

  it('LDAP 帳號即使已回 external_credential 仍沿用目錄服務措辭', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      is_ldap: true,
      external_credential: true,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('此帳號由 LDAP 目錄服務管理')
    expect(wrapper.text()).not.toContain('此帳號由外部身分提供者管理')
  })

  it('本地帳號（兩旗標皆假）仍提供改密表單', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      is_ldap: false,
      external_credential: false,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('目前密碼')
    expect(wrapper.findAll('button').some((b) => b.text().includes('更新密碼'))).toBe(true)
  })

  it('MFA 啟用流程：產生金鑰顯示 secret，6 碼確認後轉為已啟用', async () => {
    getMFASetupMock.mockResolvedValue({
      secret: 'ABCDEF123456',
      otpauth_url: 'otpauth://totp/Custodexa:carol?secret=ABCDEF123456',
    })
    enableMFAMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    await wrapper.vm.handleGenerateMFASetup()
    await flushPromises()
    expect(wrapper.text()).toContain('ABCDEF123456')
    // QR code 以 otpauth URL 本地渲染（掃碼為主、手輸為輔）
    expect(wrapper.find('.mfa-qr').exists()).toBe(true)
    expect(toCanvasMock).toHaveBeenCalled()
    expect(toCanvasMock.mock.calls[0][1]).toBe('otpauth://totp/Custodexa:carol?secret=ABCDEF123456')

    wrapper.vm.enableCode = '654321'
    await wrapper.vm.handleEnableMFA()
    await flushPromises()

    expect(enableMFAMock).toHaveBeenCalledWith({ code: '654321' })
    expect(wrapper.vm.mfaEnabled).toBe(true)
    expect(wrapper.text()).toContain('已啟用')
  })

  // —— 自助顯示名（profile-display-name）——

  it('基本資料露出 full_name 並標示身分權威唯讀', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      full_name: 'Carol Chen',
      display_name: 'Carol Chen',
      local_display_name: null,
    })
    const wrapper = mountView()
    await flushPromises()
    const text = wrapper.text()
    expect(text).toContain('全名')
    expect(text).toContain('Carol Chen') // full_name 露出（原本完全沒顯示）
    expect(text).toContain('顯示名稱')
    expect(text).toContain('使用者名稱與全名為權威身分，唯讀。')
  })

  it('編輯顯示名：送 PATCH、更新 localStorage、廣播側欄事件', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      full_name: 'Carol Chen',
      display_name: 'Carol Chen',
      local_display_name: null,
    })
    updateProfileDisplayNameMock.mockResolvedValue({
      ...accountInfo,
      full_name: 'Carol Chen',
      local_display_name: '小卡',
      display_name: '小卡',
    })
    const eventSpy = vi.fn()
    window.addEventListener('ot-user-updated', eventSpy)
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.displayNameInput = '小卡'
    await wrapper.vm.handleSaveDisplayName()
    await flushPromises()

    expect(updateProfileDisplayNameMock).toHaveBeenCalledWith('小卡')
    const cached = JSON.parse(localStorage.getItem('user'))
    expect(cached.local_display_name).toBe('小卡')
    expect(cached.display_name).toBe('小卡')
    expect(eventSpy).toHaveBeenCalled()
    window.removeEventListener('ot-user-updated', eventSpy)
  })

  it('清除顯示名：送空字串（後端寫回 NULL 回退 full_name）', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      full_name: 'Carol Chen',
      local_display_name: '小卡',
      display_name: '小卡',
    })
    updateProfileDisplayNameMock.mockResolvedValue({
      ...accountInfo,
      full_name: 'Carol Chen',
      local_display_name: null,
      display_name: 'Carol Chen',
    })
    const wrapper = mountView()
    await flushPromises()

    await wrapper.vm.handleClearDisplayName()
    await flushPromises()

    expect(updateProfileDisplayNameMock).toHaveBeenCalledWith('')
    const cached = JSON.parse(localStorage.getItem('user'))
    expect(cached.local_display_name).toBeNull()
    expect(cached.display_name).toBe('Carol Chen')
  })

  it('超長顯示名：本地驗證擋下不打 API', async () => {
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.displayNameInput = 'a'.repeat(101)
    await wrapper.vm.handleSaveDisplayName()
    await flushPromises()
    expect(updateProfileDisplayNameMock).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('長度上限 100')
  })

  it('控制字元顯示名：本地驗證擋下不打 API', async () => {
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.displayNameInput = 'bad\nname'
    await wrapper.vm.handleSaveDisplayName()
    await flushPromises()
    expect(updateProfileDisplayNameMock).not.toHaveBeenCalled()
  })

  it('LDAP 帳號：身分欄位提示「由目錄服務管理」，顯示名仍可自助編輯', async () => {
    getCurrentUserMock.mockResolvedValue({
      ...accountInfo,
      is_ldap: true,
      full_name: 'LDAP User',
      display_name: 'LDAP User',
      local_display_name: null,
    })
    const wrapper = mountView()
    await flushPromises()
    const text = wrapper.text()
    // LDAP 身分提示（非一般唯讀提示）
    expect(text).toContain('身分欄位由目錄服務管理，唯讀。')
    // 顯示名編輯仍可用（LDAP 帳號 local_display_name 為本地欄位，不參與目錄同步）
    expect(text).toContain('自訂顯示名')
    expect(wrapper.findAll('button').some((b) => b.text() === '儲存')).toBe(true)
  })
})
