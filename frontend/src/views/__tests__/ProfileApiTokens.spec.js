import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApiTokenSection from '@/components/api-token/ApiTokenSection.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import {
  eligibility,
  listResponse,
  roleAsset,
  standardTokens,
  tokenDrift,
  tokenExpired,
  tokenProdApply,
  tokenRevoked,
} from '@/__fixtures__/apiTokens'

enableAutoUnmount(afterEach)

const getMyApiTokensMock = vi.fn()
const revokeMyApiTokenMock = vi.fn()
const getMyAgentsMock = vi.fn()
const successMock = vi.fn()

vi.mock('@/api/apiTokens', () => ({
  getMyApiTokens: (...a) => getMyApiTokensMock(...a),
  createMyApiToken: vi.fn(),
  revokeMyApiToken: (...a) => revokeMyApiTokenMock(...a),
  API_TOKEN_VERIFY_PATH: '/api/v1/api-tokens/verify',
}))
const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...a) => getCurrentUserMock(...a),
}))
vi.mock('@/api/agents', () => ({
  getMyAgents: (...a) => getMyAgentsMock(...a),
}))
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, ElMessage: { ...actual.ElMessage, success: (...a) => successMock(...a), error: vi.fn() } }
})

const account = { id: 57, username: 'ops-chen', roles: ['asset_admin'] }

const mountSection = async () => {
  const w = mount(ApiTokenSection, {
    props: { account },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}

describe('個人資料頁的 API token 區塊', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    resetCapabilities()
    getMyAgentsMock.mockResolvedValue({ data: [] })
  })
  afterEach(() => {
    vi.restoreAllMocks()
    resetCapabilities()
  })

  it('有資格且有 token：顯示清單與可按的建立鈕', async () => {
    getMyApiTokensMock.mockResolvedValue(listResponse())
    const w = await mountSection()
    expect(w.get('[data-test="api-token-create"]').attributes('disabled')).toBeUndefined()
    expect(w.text()).toContain('terraform-prod-apply')
    expect(w.find('[data-test="api-token-empty"]').exists()).toBe(false)
    expect(w.find('[data-test="api-token-no-permission"]').exists()).toBe(false)
  })

  it('有資格但沒有任何 token：顯示空狀態', async () => {
    getMyApiTokensMock.mockResolvedValue(listResponse([]))
    const w = await mountSection()
    expect(w.find('[data-test="api-token-empty"]').exists()).toBe(true)
    expect(w.find('[data-test="api-token-create"]').exists()).toBe(true)
  })

  it('沒有管理角色也沒有 token：只剩說明，不顯示建立鈕', async () => {
    getMyApiTokensMock.mockResolvedValue(
      listResponse([], eligibility({ can_create: false, reason: 'no_management_role', grantable_roles: [] })),
    )
    const w = await mountSection()
    expect(w.find('[data-test="api-token-no-permission"]').exists()).toBe(true)
    expect(w.text()).toContain('一般使用者')
    expect(w.find('[data-test="api-token-create"]').exists()).toBe(false)
    expect(w.find('[data-test="api-token-empty"]').exists()).toBe(false)
  })

  it('管理角色被收回：黃框說明哪些角色不在、幾把暫停，建立鈕停用', async () => {
    const lost = roleAsset({ effective: false })
    getMyApiTokensMock.mockResolvedValue(
      listResponse(
        [tokenProdApply({ status: 'suspended_roles_revoked', granted_roles: [lost] }), tokenDrift({ status: 'suspended_roles_revoked', granted_roles: [lost] })],
        eligibility({ can_create: false, reason: 'no_management_role', grantable_roles: [] }),
      ),
    )
    const w = await mountSection()
    const box = w.get('[data-test="api-token-roles-revoked"]').text()
    expect(box).toContain('資產管理員')
    expect(box).toContain('2')
    expect(w.get('[data-test="api-token-create"]').attributes('disabled')).toBeDefined()
  })

  it('系統還原後尚未建立新的：顯示還原提示', async () => {
    getMyApiTokensMock.mockResolvedValue(
      listResponse(
        [tokenProdApply({ status: 'invalidated_by_restore' })],
        eligibility(),
        { invalidated_count: 1, restored_at: '2026-11-10T02:00:00Z' },
      ),
    )
    const w = await mountSection()
    expect(w.find('[data-test="api-token-restored"]').exists()).toBe(true)
    expect(w.find('[data-test="api-token-all-inactive"]').exists()).toBe(false)
  })

  it('還原後已建立新的：還原提示不再出現', async () => {
    getMyApiTokensMock.mockResolvedValue(
      listResponse(
        [tokenProdApply({ status: 'invalidated_by_restore' }), tokenDrift({ created_at: '2026-11-12T08:40:03Z' })],
        eligibility(),
        { invalidated_count: 1, restored_at: '2026-11-10T02:00:00Z' },
      ),
    )
    const w = await mountSection()
    expect(w.find('[data-test="api-token-restored"]').exists()).toBe(false)
  })

  it('全部都已失效：提示請建立新的', async () => {
    getMyApiTokensMock.mockResolvedValue(listResponse([tokenExpired(), tokenRevoked()]))
    const w = await mountSection()
    expect(w.find('[data-test="api-token-all-inactive"]').exists()).toBe(true)
  })

  it('載入失敗：顯示錯誤與重新整理，按下後重新讀取', async () => {
    getMyApiTokensMock.mockRejectedValueOnce(new Error('500')).mockResolvedValueOnce(listResponse())
    const w = await mountSection()
    expect(w.find('[data-test="api-token-load-failed"]').exists()).toBe(true)
    expect(w.get('[data-test="api-token-create"]').attributes('disabled')).toBeDefined()
    await w.get('[data-test="api-token-reload"]').trigger('click')
    await flushPromises()
    expect(getMyApiTokensMock).toHaveBeenCalledTimes(2)
    expect(w.find('[data-test="api-token-load-failed"]').exists()).toBe(false)
    expect(w.text()).toContain('terraform-prod-apply')
  })

  it('建立完成：明文關閉後才提示已建立並重新讀取清單', async () => {
    getMyApiTokensMock.mockResolvedValue(listResponse())
    const w = await mountSection()
    const dialog = w.findComponent({ name: 'ApiTokenCreateDialog' })
    await dialog.vm.$emit('update:modelValue', true)
    await dialog.vm.$emit('created', tokenDrift({ id: 9, name: 'new-token' }))
    await flushPromises()
    expect(getMyApiTokensMock).toHaveBeenCalledTimes(2)
    expect(successMock).not.toHaveBeenCalled()
    await dialog.vm.$emit('update:modelValue', false)
    await flushPromises()
    expect(successMock).toHaveBeenCalledTimes(1)
    expect(successMock.mock.calls[0][0]).toContain('new-token')
  })

  it('撤銷：送出本人撤銷，成功後提示並重新讀取', async () => {
    getMyApiTokensMock.mockResolvedValue(listResponse(standardTokens()))
    revokeMyApiTokenMock.mockResolvedValue({})
    const w = await mountSection()
    const list = w.findComponent({ name: 'ApiTokenList' })
    await list.vm.$emit('revoke', tokenProdApply())
    await flushPromises()
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(revokeMyApiTokenMock).toHaveBeenCalledWith(2, '')
    expect(successMock.mock.calls[0][0]).toContain('terraform-prod-apply')
    expect(getMyApiTokensMock).toHaveBeenCalledTimes(2)
  })

  it('撤銷被拒（對象已不存在）：不提示成功，重新讀取清單', async () => {
    getMyApiTokensMock.mockResolvedValue(listResponse(standardTokens()))
    revokeMyApiTokenMock.mockRejectedValue(
      Object.assign(new Error('404'), { response: { status: 404, data: { error: 'not found' } } })
    )
    const w = await mountSection()
    await w.findComponent({ name: 'ApiTokenList' }).vm.$emit('revoke', tokenProdApply())
    await flushPromises()
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(successMock).not.toHaveBeenCalled()
    expect(getMyApiTokensMock).toHaveBeenCalledTimes(2)
  })

  it('是 AI agent 的負責人：底部提示 agent 用自己的鑰匙', async () => {
    setCapabilitiesForTests(['ui:my-agents'])
    getMyAgentsMock.mockResolvedValue({ data: [{ id: 1 }] })
    getMyApiTokensMock.mockResolvedValue(listResponse())
    const w = await mountSection()
    expect(w.find('[data-test="api-token-agent-hint"]').exists()).toBe(true)
  })

  it('直接開網址（權限還沒載入）：等權限載入後仍會查詢並顯示提示', async () => {
    let resolveMe
    getCurrentUserMock.mockReturnValue(new Promise((r) => { resolveMe = r }))
    getMyAgentsMock.mockResolvedValue({ data: [{ id: 1 }] })
    getMyApiTokensMock.mockResolvedValue(listResponse())
    const w = await mountSection()
    expect(getMyAgentsMock).not.toHaveBeenCalled()
    resolveMe({ id: 57, permissions: ['ui:my-agents'] })
    await flushPromises()
    expect(getMyAgentsMock).toHaveBeenCalledTimes(1)
    expect(w.find('[data-test="api-token-agent-hint"]').exists()).toBe(true)
  })

  it('沒有 agent 頁權限：不查詢也不顯示提示', async () => {
    getCurrentUserMock.mockResolvedValue({ id: 57, permissions: [] })
    getMyApiTokensMock.mockResolvedValue(listResponse())
    const w = await mountSection()
    expect(getMyAgentsMock).not.toHaveBeenCalled()
    expect(w.find('[data-test="api-token-agent-hint"]').exists()).toBe(false)
  })
})
