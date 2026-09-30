import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import i18n from '@/i18n'
import ExternalGroupMappings from '../ExternalGroupMappings.vue'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.mock('vue-router', () => ({ useRoute: () => ({ params: { type: 'oidc', id: '7' } }) }))
const api = vi.hoisted(() => ({ createGroup: vi.fn(), updateGroup: vi.fn(), updateRole: vi.fn(), getSources: vi.fn() }))
const confirmWarningsMock = vi.hoisted(() => vi.fn(async () => true))
vi.mock('@/utils/mappingRiskGate', () => ({ confirmWarnings: (...a) => confirmWarningsMock(...a) }))
vi.mock('@/api/identitySources', () => ({
  getIdentitySources: (...a) => api.getSources(...a),
  getRoleMappings: vi.fn(async () => ({ data: [{ id: 9, match_value: 'CN=Ops,OU=Long,DC=example,DC=test', role: 'user', enabled: true, affected_user_count: 1 }] })),
  getUserGroupMappings: vi.fn(async () => ({ data: [] })),
  getExternalGroups: vi.fn(async () => ({ data: [] })),
  getUserGroupMappingUsage: vi.fn(async () => ({ data: { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 } })),
  createUserGroupMapping: (...a) => api.createGroup(...a),
  updateUserGroupMapping: (...a) => api.updateGroup(...a), deleteUserGroupMapping: vi.fn(),
  createRoleMapping: vi.fn(), updateRoleMapping: (...a) => api.updateRole(...a), deleteRoleMapping: vi.fn(),
  updateExternalGroupNote: vi.fn(),
  errorCode: error => error?.response?.data?.code || error?.response?.data?.error?.code || '',
}))
vi.mock('@/api/user', () => ({ getRoleList: vi.fn(async () => ({ data: [{ name: 'user' }] })) }))
vi.mock('@/api/userGroups', () => ({ getUserGroups: vi.fn(async () => ({ data: [{ id: 3, name: 'operators' }] })) }))

const open = async () => {
  const wrapper = mount(ExternalGroupMappings, { global: { plugins: [ElementPlus], stubs: { 'router-link': { template: '<a><slot /></a>' } } } })
  await flushPromises()
  return wrapper
}

describe('ExternalGroupMappings fix2 interactions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    confirmWarningsMock.mockResolvedValue(true)
    api.getSources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: false, group_attribute_configured: false }] })
    api.createGroup.mockResolvedValue({ data: { id: 11 } })
    api.updateGroup.mockResolvedValue({ data: { id: 11 } })
    api.updateRole.mockResolvedValue({ data: { id: 19 } })
  })

  it('409 updates real usage and requires an explicit checkbox before HTTP retry', async () => {
    api.createGroup
      .mockRejectedValueOnce({ response: { status: 409, data: { code: 'MAPPING_USAGE_ACK_REQUIRED', meta: { usage: { asset_authorizations: 3, approver_scopes: 1, requester_scopes: 2 } } } } })
      .mockRejectedValueOnce({ response: { status: 422, data: { code: 'MAPPING_ACK_REQUIRED', meta: { warnings: [{ code: 'MAPPING_SOURCE_ATTR_UNSET' }] } } } })
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    wrapper.vm.openCreate()
    wrapper.vm.draft.match_value = 'ops'
    wrapper.vm.draft.user_group_id = 3
    await wrapper.vm.save()
    await flushPromises()
    expect(wrapper.vm.usage).toEqual({ asset_authorizations: 3, approver_scopes: 1, requester_scopes: 2 })
    expect(wrapper.vm.usageConfirmed).toBe(false)
    expect(api.createGroup).toHaveBeenCalledTimes(1)
    expect(confirm).not.toHaveBeenCalled()
    wrapper.vm.usageConfirmed = true
    await wrapper.vm.save()
    expect(api.createGroup).toHaveBeenCalledTimes(3)
    expect(api.createGroup.mock.calls[1][2].risk_acknowledged).toBe(true)
    expect(api.createGroup.mock.calls[1][2].source_config_acknowledged).toBe(false)
    expect(api.createGroup.mock.calls[2][2].source_config_acknowledged).toBe(true)
    expect(confirmWarningsMock).toHaveBeenCalledWith(['MAPPING_SOURCE_ATTR_UNSET'])
    confirm.mockRestore()
  })

  it('shows the missing-source hint and a neutral disabled status', async () => {
    api.getSources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: 'false', group_attribute_configured: false }] })
    const wrapper = await open()
    expect(wrapper.text()).toContain('登入時不會同步')
    expect(wrapper.text()).toContain('若登入時無法確認使用者所屬的外部群組，會保留其既有映射權限。')
    const disabled = wrapper.find('.source-summary .el-tag--info')
    expect(disabled.exists()).toBe(true)
    expect(disabled.text()).toBe(i18n.global.t('common.disabled'))
  })

  it.each([
    ['zh-TW', '若登入時無法確認使用者所屬的外部群組，會保留其既有映射權限。'],
    ['en-US', "If sign-in cannot confirm a user’s groups, their existing mapped access is kept."],
    ['ja-JP', 'ログイン時にユーザーの外部グループを確認できない場合、既存のマッピング権限を維持します。'],
  ])('shows a neutral standing rule, not a current observation alert: %s', async (locale, expected) => {
    const previous = i18n.global.locale.value
    try {
      i18n.global.locale.value = locale
      const wrapper = await open()
      expect(wrapper.find('.observation-rule').exists()).toBe(true)
      const rule = wrapper.get('.observation-rule')
      expect(rule.text()).toBe(expected)
      expect(wrapper.find('.el-alert--info').exists()).toBe(false)
    } finally {
      i18n.global.locale.value = previous
    }
  })

  it('copies the unabridged external group identifier and expands a long value', async () => {
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    const wrapper = await open()
    await wrapper.get('[data-test="copy-group-value"]').trigger('click')
    expect(writeText).toHaveBeenCalledWith('CN=Ops,OU=Long,DC=example,DC=test')
    await wrapper.get('[data-test="expand-group-value"]').trigger('click')
    expect(wrapper.text()).toContain('CN=Ops,OU=Long,DC=example,DC=test')
  })

  it('keeps the visual active tab aligned after switching to user groups', async () => {
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    await flushPromises()
    const active = wrapper.find('.el-tabs__item.is-active')
    expect(active.text()).toContain(i18n.global.t('identityGroupMappings.tabs.userGroups'))
    expect(wrapper.find('.el-tabs__active-bar').exists()).toBe(true)
    expect(wrapper.find('.mapping-tabs').element.style.getPropertyValue('--el-transition-duration')).toBe('0s')
  })

  it('shows effective role and member losses in the rule revocation confirmation', async () => {
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = await open()
    await wrapper.vm.confirmRevocation({ affected_user_count: 4, effective_role_loss_count: 2, effective_member_loss_count: 1 }, '停用')
    expect(confirm.mock.calls.at(-1)[0]).toContain('2 筆有效角色指派')
    expect(confirm.mock.calls.at(-1)[0]).toContain('1 筆有效群組成員關係')
    confirm.mockRestore()
  })

  it('records source warning acknowledgement only after confirmation on a toggle', async () => {
    api.updateGroup.mockRejectedValueOnce({ response: { status: 422, data: { code: 'MAPPING_ACK_REQUIRED', meta: { warnings: [{ code: 'MAPPING_SOURCE_ATTR_UNSET' }] } } } })
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    await wrapper.vm.toggle({ id: 11, enabled: true, match_value: 'ops', user_group_id: 3, affected_user_count: 1 })
    expect(api.updateGroup).toHaveBeenCalledTimes(2)
    expect(api.updateGroup.mock.calls[0][3].source_config_acknowledged).toBe(false)
    expect(api.updateGroup.mock.calls[1][3].source_config_acknowledged).toBe(true)
    expect(confirmWarningsMock).toHaveBeenCalledWith(['MAPPING_SOURCE_ATTR_UNSET'])
    confirm.mockRestore()
  })

  it('requires an explicit warning confirmation before re-enabling an admin role mapping', async () => {
    const warning = { response: { status: 422, data: { code: 'MAPPING_ACK_REQUIRED', meta: { warnings: [{ code: 'MAPPING_TARGETS_ADMIN_ROLE' }] } } } }
    api.updateRole.mockImplementation(async (_type, _sourceId, _ruleId, payload) => {
      if (!payload.risk_acknowledged) throw warning
      return { data: { id: 19 } }
    })
    const wrapper = await open()
    const row = { id: 19, enabled: false, match_value: 'admin-group', role: 'admin' }

    confirmWarningsMock.mockResolvedValueOnce(false)
    await wrapper.vm.toggle(row)
    expect(api.updateRole).toHaveBeenCalledTimes(1)
    expect(api.updateRole.mock.calls[0][3].risk_acknowledged).toBe(false)
    expect(confirmWarningsMock).toHaveBeenCalledWith(['MAPPING_TARGETS_ADMIN_ROLE'])

    confirmWarningsMock.mockResolvedValueOnce(true)
    await wrapper.vm.toggle(row)
    expect(api.updateRole).toHaveBeenCalledTimes(3)
    expect(api.updateRole.mock.calls[1][3].risk_acknowledged).toBe(false)
    expect(api.updateRole.mock.calls[2][3].risk_acknowledged).toBe(true)
  })

  it('does not acknowledge a usage conflict on a toggle until its confirmation is accepted', async () => {
    const conflict = { response: { status: 409, data: { code: 'MAPPING_USAGE_ACK_REQUIRED', meta: { usage: { asset_authorizations: 1, approver_scopes: 0, requester_scopes: 0 } } } } }
    api.updateGroup.mockImplementation(async (_type, _sourceId, _ruleId, payload) => {
      if (!payload.risk_acknowledged) throw conflict
      return { data: { id: 11 } }
    })
    const confirm = vi.spyOn(ElMessageBox, 'confirm')
      .mockRejectedValueOnce('cancel')
      .mockResolvedValueOnce('confirm')
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    const row = { id: 11, enabled: false, match_value: 'ops', user_group_id: 3 }

    await wrapper.vm.toggle(row)
    expect(api.updateGroup).toHaveBeenCalledTimes(1)
    expect(api.updateGroup.mock.calls[0][3].risk_acknowledged).toBe(false)
    expect(confirm.mock.calls[0][0]).toContain('資產授權 1 筆')

    await wrapper.vm.toggle(row)
    expect(api.updateGroup).toHaveBeenCalledTimes(3)
    expect(api.updateGroup.mock.calls[1][3].risk_acknowledged).toBe(false)
    expect(api.updateGroup.mock.calls[2][3].risk_acknowledged).toBe(true)
    confirm.mockRestore()
  })
})
