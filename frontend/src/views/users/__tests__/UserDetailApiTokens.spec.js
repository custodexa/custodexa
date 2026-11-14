import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserApiTokensTab from '../components/UserApiTokensTab.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { standardTokens, tokenExpired, tokenProdApply, tokenRevoked } from '@/__fixtures__/apiTokens'

enableAutoUnmount(afterEach)

const getUserApiTokensMock = vi.fn()
const revokeUserApiTokenMock = vi.fn()
const revokeAllUserApiTokensMock = vi.fn()
const successMock = vi.fn()

vi.mock('@/api/apiTokens', () => ({
  getUserApiTokens: (...a) => getUserApiTokensMock(...a),
  revokeUserApiToken: (...a) => revokeUserApiTokenMock(...a),
  revokeAllUserApiTokens: (...a) => revokeAllUserApiTokensMock(...a),
}))
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, ElMessage: { ...actual.ElMessage, success: (...a) => successMock(...a), error: vi.fn() } }
})

const response = (over = {}) => ({ data: standardTokens(), can_revoke: true, protected: false, account_active: true, ...over })

const mountTab = async (props = {}) => {
  const w = mount(UserApiTokensTab, {
    props: { userId: 57, username: 'ops-chen', ...props },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}

describe('使用者詳情的 API token 分頁', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })
  afterEach(() => vi.restoreAllMocks())

  it('可撤銷：說明、清單、撤銷全部鈕', async () => {
    getUserApiTokensMock.mockResolvedValue(response())
    const w = await mountTab()
    expect(getUserApiTokensMock).toHaveBeenCalledWith(57)
    expect(w.text()).toContain('這是 ops-chen 本人建立的 API token')
    expect(w.text()).toContain('你可以撤銷')
    expect(w.find('[data-test="user-api-tokens-revoke-all"]').exists()).toBe(true)
    expect(w.find('[data-test="user-api-tokens-protected"]').exists()).toBe(false)
  })

  it('受保護帳號：黃框說明只有超級管理者能撤銷，沒有撤銷全部鈕', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ can_revoke: false, protected: true }))
    const w = await mountTab({ holder: 'super' })
    const box = w.get('[data-test="user-api-tokens-protected"]').text()
    expect(box).toContain('只有超級管理者能撤銷 ops-chen 的 API token')
    expect(box).toContain('請聯絡其他超級管理者')
    expect(w.text()).not.toContain('你可以撤銷')
    expect(w.find('[data-test="user-api-tokens-revoke-all"]').exists()).toBe(false)
  })

  it('受保護帳號但檢視者能撤銷（超級管理者）：不出現「只有超級管理者能撤銷」的說明，照常可撤銷', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ can_revoke: true, protected: true }))
    const w = await mountTab()
    expect(w.find('[data-test="user-api-tokens-protected"]').exists()).toBe(false)
    expect(w.find('[data-test="user-api-tokens-revoke-all"]').exists()).toBe(true)
  })

  it('受保護的系統安全管理員：換成聯絡超級管理者的說法', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ can_revoke: false, protected: true }))
    const w = await mountTab({ holder: 'security' })
    expect(w.get('[data-test="user-api-tokens-protected"]').text()).toContain('持有系統安全管理員角色')
  })

  it('帳號已停用：黃框說明目前都不能使用，摘要標示帳號停用中', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ account_active: false }))
    const w = await mountTab()
    expect(w.get('[data-test="user-api-tokens-disabled"]').text()).toContain('帳號已停用')
    expect(w.get('[data-test="summary-usable"]').text()).toContain('可用（帳號停用中）')
  })

  it('帳號已停用但 token 都已失效：不再提醒停用（沒有可恢復的 token）', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ account_active: false, data: [tokenExpired(), tokenRevoked()] }))
    const w = await mountTab()
    expect(w.find('[data-test="user-api-tokens-disabled"]').exists()).toBe(false)
  })

  it('撤銷被拒（對象已受保護）：重新載入清單，換成受保護的說明', async () => {
    getUserApiTokensMock.mockResolvedValueOnce(response())
    getUserApiTokensMock.mockResolvedValueOnce(response({ can_revoke: false, protected: true }))
    revokeUserApiTokenMock.mockRejectedValue(
      Object.assign(new Error('403'), {
        response: { status: 403, data: { code: 'AUTH_PROTECTED_ACCOUNT_OPERATION' } },
      })
    )
    const w = await mountTab({ holder: 'super' })
    await w.get('[data-test="revoke-1"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(getUserApiTokensMock).toHaveBeenCalledTimes(2)
    expect(w.find('[data-test="user-api-tokens-protected"]').exists()).toBe(true)
  })

  it('全部已失效：不顯示撤銷全部鈕', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ data: [tokenExpired(), tokenRevoked()] }))
    const w = await mountTab()
    expect(w.find('[data-test="user-api-tokens-revoke-all"]').exists()).toBe(false)
  })

  it('沒有任何 token：空狀態寫出本人名稱', async () => {
    getUserApiTokensMock.mockResolvedValue(response({ data: [] }))
    const w = await mountTab()
    expect(w.get('[data-test="user-api-tokens-empty"]').text()).toContain('ops-chen 還沒有建立任何 API token')
  })

  it('載入失敗：顯示錯誤，重新整理後恢復', async () => {
    getUserApiTokensMock.mockRejectedValueOnce(new Error('500')).mockResolvedValueOnce(response())
    const w = await mountTab()
    expect(w.find('[data-test="user-api-tokens-load-failed"]').exists()).toBe(true)
    await w.get('[data-test="user-api-tokens-reload"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="user-api-tokens-load-failed"]').exists()).toBe(false)
    expect(w.text()).toContain('terraform-prod-apply')
  })

  it('撤銷單把：帶使用者與 token 編號送出，提示並重新讀取', async () => {
    getUserApiTokensMock.mockResolvedValue(response())
    revokeUserApiTokenMock.mockResolvedValue({})
    const w = await mountTab()
    await w.findComponent({ name: 'ApiTokenList' }).vm.$emit('revoke', tokenProdApply())
    await flushPromises()
    expect(w.get('[data-test="revoke-question"]').text()).toContain('ops-chen 的「terraform-prod-apply」')
    await w.get('[data-test="revoke-note"]').setValue('疑似外流')
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(revokeUserApiTokenMock).toHaveBeenCalledWith(57, 2, '疑似外流')
    expect(successMock.mock.calls[0][0]).toContain('terraform-prod-apply')
    expect(getUserApiTokensMock).toHaveBeenCalledTimes(2)
  })

  it('撤銷全部：以後端回傳的數量提示', async () => {
    getUserApiTokensMock.mockResolvedValue(response())
    revokeAllUserApiTokensMock.mockResolvedValue({ revoked: 3 })
    const w = await mountTab()
    await w.get('[data-test="user-api-tokens-revoke-all"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="revoke-question"]').text()).toContain('全部 3 個可用 API token')
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(revokeAllUserApiTokensMock).toHaveBeenCalledWith(57, '')
    expect(successMock).toHaveBeenCalledWith('已撤銷 3 個 API token')
  })
})
