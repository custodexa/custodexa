import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import i18n from '@/i18n'
import ExternalGroupMappings from '../ExternalGroupMappings.vue'
import { roleLabel } from '@/constants/roles'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const routeState = vi.hoisted(() => ({ params: { type: 'oidc', id: '7' } }))
vi.mock('vue-router', () => ({ useRoute: () => routeState }))
const api = vi.hoisted(() => ({ createGroup: vi.fn(), updateGroup: vi.fn(), updateRole: vi.fn(), createRole: vi.fn(), deleteRole: vi.fn(), deleteGroup: vi.fn(), getRoles: vi.fn(), getGroupRules: vi.fn(), updateNote: vi.fn(), getSources: vi.fn(), getExternalGroups: vi.fn() }))
const confirmWarningsMock = vi.hoisted(() => vi.fn(async () => true))
vi.mock('@/utils/mappingRiskGate', () => ({ confirmWarnings: (...a) => confirmWarningsMock(...a) }))
vi.mock('@/api/identitySources', () => ({
  getIdentitySources: (...a) => api.getSources(...a),
  getRoleMappings: (...a) => api.getRoles(...a),
  getUserGroupMappings: (...a) => api.getGroupRules(...a),
  getExternalGroups: (...a) => api.getExternalGroups(...a),
  getUserGroupMappingUsage: vi.fn(async () => ({ data: { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 } })),
  createUserGroupMapping: (...a) => api.createGroup(...a),
  updateUserGroupMapping: (...a) => api.updateGroup(...a), deleteUserGroupMapping: (...a) => api.deleteGroup(...a),
  createRoleMapping: (...a) => api.createRole(...a), updateRoleMapping: (...a) => api.updateRole(...a), deleteRoleMapping: (...a) => api.deleteRole(...a),
  updateExternalGroupNote: (...a) => api.updateNote(...a),
  errorCode: error => error?.response?.data?.code || error?.response?.data?.error?.code || '',
}))
const defs = vi.hoisted(() => ({
  list: vi.fn(),
  preview: vi.fn(),
  bindings: vi.fn(),
  groups: vi.fn(),
  options: vi.fn(),
}))
vi.mock('@/api/roleDefinitions', () => ({
  listRoleDefinitions: (...a) => defs.list(...a),
  previewRoleAssignment: (...a) => defs.preview(...a),
  getRoleAssignmentOptions: (...a) => defs.options(...a),
}))
const policyApi = vi.hoisted(() => ({ getSecurityPolicies: vi.fn(), can: vi.fn(() => true) }))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: (...a) => policyApi.getSecurityPolicies(...a) }))
vi.mock('@/composables/useCapabilities', () => ({
  can: (...a) => policyApi.can(...a),
  canAll: (perms) => Array.isArray(perms) && perms.length > 0 && perms.every((p) => policyApi.can(p)),
}))
const revalidationPolicy = (value) => ({ data: [{ key: 'mapping_revalidation_hours', value, unit: '小時', unit_key: 'hours' }] })
vi.mock('@/api/userGroups', () => ({
  getUserGroups: (...a) => defs.groups(...a),
  getUserGroupRoleBindings: (...a) => defs.bindings(...a),
}))
const DEFS = [
  { id: 1, name: 'user', assignment_state: 'open', direct_mappable: true, management_class: false },
  { id: 2, name: 'auditor', assignment_state: 'open', direct_mappable: true, management_class: false },
  { id: 3, name: 'security_admin', assignment_state: 'protected', direct_mappable: true, management_class: true },
  { id: 4, name: 'asset_manager', assignment_state: 'open', direct_mappable: true, management_class: true },
  { id: 6, name: 'identity_admin', assignment_state: 'not_open', direct_mappable: true, management_class: true },
  { id: 5, name: 'custom_ops', assignment_state: 'open', direct_mappable: false, management_class: false },
]
const NO_COMBO = { total: 0, matched: 0, truncated: false, subjects: [], operation: { marks: [], evaluated: 0 } }

const open = async () => {
  const wrapper = mount(ExternalGroupMappings, { global: { plugins: [ElementPlus], stubs: { 'router-link': { template: '<a><slot /></a>' } } } })
  await flushPromises()
  return wrapper
}

describe('ExternalGroupMappings fix2 interactions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    defs.list.mockResolvedValue({ data: DEFS })
    defs.preview.mockResolvedValue(NO_COMBO)
    defs.groups.mockResolvedValue({ data: [{ id: 3, name: 'operators' }] })
    defs.bindings.mockResolvedValue({ data: [] })
    defs.options.mockResolvedValue({ nodes: [], node_assignable_role_ids: [], node_range_no_effect_role_ids: [], node_range_no_effect_reasons: {} })
    api.getRoles.mockResolvedValue({ data: [{ id: 9, match_value: 'CN=Ops,OU=Long,DC=example,DC=test', role: 'user', enabled: true, affected_user_count: 1 }] })
    api.getGroupRules.mockResolvedValue({ data: [] })
    routeState.params = { type: 'oidc', id: '7' }
    confirmWarningsMock.mockResolvedValue(true)
    api.getSources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: false, group_attribute_configured: false }] })
    api.createGroup.mockResolvedValue({ data: { id: 11 } })
    api.updateGroup.mockResolvedValue({ data: { id: 11 } })
    api.updateRole.mockResolvedValue({ data: { id: 19 } })
    api.updateNote.mockResolvedValue({ data: {} })
    api.getExternalGroups.mockResolvedValue({ data: [] })
    policyApi.can.mockReturnValue(true)
    policyApi.getSecurityPolicies.mockResolvedValue(revalidationPolicy('12'))
  })

  it('updates a changed note once after saving an existing group rule', async () => {
    api.getExternalGroups.mockResolvedValue({ data: [{ id: 44, match_value: 'ops', note: 'Old note' }] })
    const wrapper = await open()
    wrapper.vm.openEdit({ id: 9, match_value: 'ops', note: 'Old note', role: 'user', enabled: true })
    await flushPromises()
    const sel = 'input[data-test="rule-note-input"], [data-test="rule-note-input"] input'
    const noteInput = wrapper.element.querySelector(sel) || document.body.querySelector(sel)
    expect(noteInput).not.toBeNull()
    expect(noteInput.disabled).toBe(false)
    noteInput.value = 'New note'
    noteInput.dispatchEvent(new Event('input', { bubbles: true }))
    await flushPromises()
    expect(wrapper.vm.draft.note).toBe('New note')
    await wrapper.vm.save()
    expect(api.updateRole).toHaveBeenCalledTimes(1)
    expect(api.updateRole.mock.calls[0][3]).not.toHaveProperty('note')
    expect(api.updateNote).toHaveBeenCalledTimes(1)
    expect(api.updateNote).toHaveBeenCalledWith('oidc', '7', 44, 'New note')
  })

  it('does not update an unchanged note when saving an existing group rule', async () => {
    api.getExternalGroups.mockResolvedValue({ data: [{ id: 44, match_value: 'ops', note: 'Old note' }] })
    const wrapper = await open()
    wrapper.vm.openEdit({ id: 9, match_value: 'ops', note: 'Old note', role: 'user', enabled: true })
    await flushPromises()
    await wrapper.vm.save()
    expect(api.updateRole).toHaveBeenCalledTimes(1)
    expect(api.updateNote).not.toHaveBeenCalled()
  })

  it('reports a note failure while keeping a successfully saved rule closed', async () => {
    api.getExternalGroups.mockResolvedValue({ data: [{ id: 44, match_value: 'ops', note: 'Old note' }] })
    api.updateNote.mockRejectedValue(new Error('note update failed'))
    const message = vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
    const wrapper = await open()
    wrapper.vm.openEdit({ id: 9, match_value: 'ops', note: 'Old note', role: 'user', enabled: true })
    await flushPromises()
    wrapper.vm.draft.note = 'New note'
    await wrapper.vm.save()
    expect(api.updateRole).toHaveBeenCalledTimes(1)
    expect(api.updateNote).toHaveBeenCalledTimes(1)
    expect(wrapper.vm.dialogOpen).toBe(false)
    expect(message).toHaveBeenCalledWith(i18n.global.t('identityGroupMappings.ruleSavedNoteFailed'))
    message.mockRestore()
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
    const disabled = wrapper.find('.source-summary .el-tag--info')
    expect(disabled.exists()).toBe(true)
    expect(disabled.text()).toBe(i18n.global.t('common.disabled'))
  })

  // 映射頁的常駐句要照實說明重新驗證時限：超過時限讀不到群組會收回，
  // 不得寫成「讀不到群組就保留既有映射權限」
  const KEEPS_ACCESS = ['會保留其既有映射權限', 'existing mapped access is kept', '既存のマッピング権限を維持します']

  it.each([
    ['zh-TW', '12 小時', '收回'],
    ['en-US', '12 hours', 'withdrawn'],
    ['ja-JP', '12 時間', '取り消します'],
  ])('states the current revalidation limit and that access is withdrawn past it: %s', async (locale, limit, withdrawn) => {
    const previous = i18n.global.locale.value
    try {
      i18n.global.locale.value = locale
      const wrapper = await open()
      const rule = wrapper.get('.observation-rule')
      expect(rule.text()).toBe(i18n.global.t('identityGroupMappings.revalidation.limited', { limit }))
      expect(rule.text()).toContain(limit)
      expect(rule.text()).toContain(withdrawn)
      for (const phrase of KEEPS_ACCESS) expect(rule.text()).not.toContain(phrase)
      expect(wrapper.find('.el-alert--info').exists()).toBe(false)
    } finally {
      i18n.global.locale.value = previous
    }
  })

  it('states the no-limit behaviour when the limit is 0', async () => {
    policyApi.getSecurityPolicies.mockResolvedValue(revalidationPolicy('0'))
    const wrapper = await open()
    expect(wrapper.get('.observation-rule').text()).toBe(i18n.global.t('identityGroupMappings.revalidation.unlimited'))
  })

  it('falls back to the value-free rule without reading policies when the viewer cannot manage them', async () => {
    policyApi.can.mockReturnValue(false)
    const wrapper = await open()
    expect(policyApi.getSecurityPolicies).not.toHaveBeenCalled()
    const text = wrapper.get('.observation-rule').text()
    expect(text).toBe(i18n.global.t('identityGroupMappings.revalidation.unknown'))
    expect(text).toContain('收回')
    expect(text).not.toContain('12')
  })

  it('falls back to the value-free rule when reading the policies fails', async () => {
    policyApi.getSecurityPolicies.mockRejectedValue(new Error('forbidden'))
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = await open()
    expect(wrapper.get('.observation-rule').text()).toBe(i18n.global.t('identityGroupMappings.revalidation.unknown'))
    errorLog.mockRestore()
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

// 舊詳情頁內嵌清單的說明搬到這裡的對話框：比對方式、Entra 物件識別碼位置、
// 管理員與審核者角色。詳情頁不再有規則編輯處，這些提示若沒跟過來就等於遺失
describe('ExternalGroupMappings 新增／編輯對話框的群組值與角色說明', () => {
  beforeEach(() => {
    api.getRoles.mockResolvedValue({ data: [] })
    api.getGroupRules.mockResolvedValue({ data: [] })
    defs.list.mockResolvedValue({ data: DEFS })
    defs.preview.mockResolvedValue(NO_COMBO)
    defs.groups.mockResolvedValue({ data: [{ id: 3, name: 'operators' }] })
    defs.bindings.mockResolvedValue({ data: [] })
  })

  const ENTRA_ISSUER = 'https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0'
  const t = (key) => i18n.global.t(key)
  // el-dialog 依環境可能 teleport 到 body，也可能留在元件內；兩處都找
  let current = null
  const inDialog = (selector) => current.element.querySelector(selector) || document.body.querySelector(selector)
  const dialogText = () => current.element.textContent + document.body.textContent
  const matchInput = () => inDialog('.el-autocomplete input')

  const openDialog = async ({ type, address, tab = 'roles' }) => {
    routeState.params = { type, id: '7' }
    api.getSources.mockResolvedValue({ data: [{ id: 7, type, name: 'src', enabled: true, group_attribute_configured: true, address }] })
    const wrapper = await open()
    current = wrapper
    wrapper.vm.tab = tab
    wrapper.vm.openCreate()
    await flushPromises()
    return wrapper
  }

  beforeEach(() => {
    vi.clearAllMocks()
    api.getExternalGroups.mockResolvedValue({ data: [] })
    policyApi.can.mockReturnValue(true)
    policyApi.getSecurityPolicies.mockResolvedValue(revalidationPolicy('12'))
  })

  it('目錄來源：見 DN 比對說明與 placeholder，不見 Entra 提示', async () => {
    await openDialog({ type: 'ldap', address: 'ldap://ldap.example.test:389' })
    expect(inDialog('[data-test="mapping-match-hint"]').textContent.trim()).toBe(t('identitySources.mapping.matchDnHint'))
    expect(matchInput().getAttribute('placeholder')).toBe(t('identitySources.mapping.matchDnPlaceholder'))
    expect(inDialog('[data-test="mapping-entra-hint"]')).toBeNull()
    expect(dialogText()).not.toContain(t('identitySources.mapping.entraMatchHint'))
  })

  it('Entra issuer 的提供者：見宣告值比對說明與 Entra 物件識別碼提示', async () => {
    await openDialog({ type: 'oidc', address: ENTRA_ISSUER })
    expect(inDialog('[data-test="mapping-match-hint"]').textContent.trim()).toBe(t('identitySources.mapping.matchClaimValueHint'))
    expect(matchInput().getAttribute('placeholder')).toBe(t('identitySources.mapping.matchClaimValuePlaceholder'))
    expect(inDialog('[data-test="mapping-entra-hint"]').textContent.trim()).toBe(t('identitySources.mapping.entraMatchHint'))
  })

  it('非 Entra 的提供者：見宣告值比對說明，不見 Entra 提示', async () => {
    await openDialog({ type: 'oidc', address: 'https://idp.example.com' })
    expect(inDialog('[data-test="mapping-match-hint"]').textContent.trim()).toBe(t('identitySources.mapping.matchClaimValueHint'))
    expect(inDialog('[data-test="mapping-entra-hint"]')).toBeNull()
  })

  it('角色分頁見管理員與審核者角色說明，使用者群組分頁不見', async () => {
    const wrapper = await openDialog({ type: 'oidc', address: 'https://idp.example.com' })
    expect(inDialog('[data-test="mapping-admin-note"]').textContent.trim()).toBe(t('identitySources.mapping.adminNote'))
    wrapper.vm.dialogOpen = false
    wrapper.vm.tab = 'userGroups'
    wrapper.vm.openCreate()
    await flushPromises()
    expect(inDialog('[data-test="mapping-admin-note"]')).toBeNull()
    expect(dialogText()).not.toContain(t('identitySources.mapping.adminNote'))
  })
})


// 映射頁的指派呈現：依舊目標鎖定、依新目標停用、只列可直接映射的角色、儲存前預覽
describe('ExternalGroupMappings 指派呈現與儲存前預覽', () => {
  const t = (key, args) => i18n.global.t(key, args)
  const q = (wrapper, selector) => wrapper.element.querySelector(selector) || document.body.querySelector(selector)
  const GROUPS = [{ id: 3, name: 'operators' }, { id: 4, name: 'secops' }, { id: 5, name: 'assets' }, { id: 6, name: 'nobody' }]
  const BINDINGS = {
    3: [{ role_id: 1, role_name: 'user' }],
    4: [{ role_id: 3, role_name: 'security_admin' }],
    5: [{ role_id: 4, role_name: 'asset_manager' }],
  }
  const ROLE_ROWS = [
    { id: 9, match_value: 'ops', role: 'user', enabled: true, affected_user_count: 1 },
    { id: 10, match_value: 'sec', role: 'security_admin', enabled: true, affected_user_count: 1 },
  ]
  const GROUP_ROWS = [
    { id: 21, match_value: 'g-ops', user_group_id: 3, user_group_name: 'operators', enabled: true, affected_user_count: 1, usage: {} },
    { id: 22, match_value: 'g-sec', user_group_id: 4, user_group_name: 'secops', enabled: true, affected_user_count: 1, usage: {} },
    { id: 23, match_value: 'g-empty', user_group_id: 6, user_group_name: 'nobody', enabled: false, affected_user_count: 0, usage: {} },
  ]
  const HIT = {
    total: 3,
    matched: 3,
    truncated: false,
    subjects: [{ user_id: 1, new_combos: ['identity_with_security'] }],
    operation: { marks: ['management_grant'], evaluated: 3, self_direction: 'none' },
  }

  beforeEach(() => {
    vi.clearAllMocks()
    routeState.params = { type: 'oidc', id: '7' }
    confirmWarningsMock.mockResolvedValue(true)
    api.getSources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: true, group_attribute_configured: true }] })
    api.getExternalGroups.mockResolvedValue({ data: [] })
    api.getRoles.mockResolvedValue({ data: ROLE_ROWS })
    api.getGroupRules.mockResolvedValue({ data: GROUP_ROWS })
    api.createRole.mockResolvedValue({ data: { id: 30 } })
    api.updateRole.mockResolvedValue({ data: { id: 9 } })
    api.deleteRole.mockResolvedValue({})
    api.deleteGroup.mockResolvedValue({})
    api.createGroup.mockResolvedValue({ data: { id: 31 } })
    api.updateGroup.mockResolvedValue({ data: { id: 21 } })
    defs.list.mockResolvedValue({ data: DEFS })
    defs.preview.mockResolvedValue(NO_COMBO)
    defs.groups.mockResolvedValue({ data: GROUPS })
    defs.bindings.mockImplementation(async (id) => ({ data: BINDINGS[id] || [] }))
    policyApi.can.mockReturnValue(true)
    policyApi.getSecurityPolicies.mockResolvedValue(revalidationPolicy('12'))
  })

  const rowOf = (wrapper, text) => wrapper.findAll('.el-table__body tr').find(tr => tr.text().includes(text))
  const rowButton = (row, name) => row.find(`[data-test="${name}"]`)

  it('目標群組帶系統安全管理員角色：該列對非超管顯示只有超級管理者能修改，編輯、啟用／停用、刪除停用，共用備註修改仍可用', async () => {
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    await flushPromises()
    const secRow = rowOf(wrapper, 'g-sec')
    expect(secRow.text()).toContain(t('identityGroupMappings.protectedRow'))
    for (const name of ['mapping-edit', 'mapping-toggle', 'mapping-remove']) {
      expect(rowButton(secRow, name).attributes('disabled')).toBeDefined()
    }
    const plainRow = rowOf(wrapper, 'g-ops')
    expect(plainRow.text()).not.toContain(t('identityGroupMappings.protectedRow'))
    for (const name of ['mapping-edit', 'mapping-toggle', 'mapping-remove']) {
      expect(rowButton(plainRow, name).attributes('disabled')).toBeUndefined()
    }
    // 共用備註仍可改
    const noteButton = secRow.findAll('button').find(b => b.text() === t('identityGroupMappings.editNote'))
    expect(noteButton.attributes('disabled')).toBeUndefined()
    await noteButton.trigger('click')
    expect(wrapper.vm.noteOpen).toBe(true)
    // 角色分頁：目標為保護角色的列同樣鎖定
    wrapper.vm.tab = 'roles'
    await flushPromises()
    const roleSec = rowOf(wrapper, 'sec')
    expect(roleSec.text()).toContain(t('identityGroupMappings.protectedRow'))
    expect(rowButton(roleSec, 'mapping-toggle').attributes('disabled')).toBeDefined()
    // 鎖定的列即使直接呼叫也不送出
    await wrapper.vm.toggle(ROLE_ROWS[1])
    await wrapper.vm.remove(ROLE_ROWS[1])
    expect(api.updateRole).not.toHaveBeenCalled()
    expect(api.deleteRole).not.toHaveBeenCalled()
  })

  it('目標欄顯示群組的角色行；沒有角色的群組顯示沒有角色；角色都讀到時不出現讀不到的說明', async () => {
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    await flushPromises()
    expect(rowOf(wrapper, 'g-ops').find('[data-test="mapping-target-roles"]').text()).toBe(t('identityGroupMappings.targetRoles', { roles: '一般使用者' }))
    expect(rowOf(wrapper, 'g-empty').find('[data-test="mapping-target-roles"]').text()).toBe(t('identityGroupMappings.targetNoRoles'))
    expect(wrapper.find('[data-test="mapping-group-roles-unavailable"]').exists()).toBe(false)
  })

  it('讀不到各群組角色：選項不預先停用並說明；群組清單失敗：就地錯誤與重試', async () => {
    defs.bindings.mockRejectedValue(new Error('forbidden'))
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    await flushPromises()
    expect(wrapper.find('[data-test="mapping-group-roles-unavailable"]').text()).toContain(t('identityGroupMappings.groupRolesUnavailable'))
    expect(wrapper.vm.protectedRoleOfGroup(4)).toBe('')
    defs.groups.mockRejectedValue(new Error('down'))
    await wrapper.vm.loadGroupData()
    await flushPromises()
    expect(wrapper.find('[data-test="mapping-group-list-failed"]').text()).toContain(t('identityGroupMappings.groupListFailed'))
    wrapper.vm.openCreate()
    wrapper.vm.draft.match_value = 'x'
    await flushPromises()
    expect(wrapper.vm.canSave).toBeFalsy()
    errorLog.mockRestore()
  })

  it('對話框：帶保護角色的群組與保護角色選項停用', async () => {
    const wrapper = await open()
    wrapper.vm.tab = 'userGroups'
    wrapper.vm.openCreate()
    await flushPromises()
    const groupOptions = wrapper.findAllComponents({ name: 'ElOption' })
    expect(groupOptions.length).toBeGreaterThan(0)
    // 工具列的篩選選單也有同名選項，只有對話框裡的才帶停用
    const withLabel = (list, label) => list.filter(o => o.props('label') === label)
    expect(withLabel(groupOptions, 'secops').some(o => o.props('disabled'))).toBe(true)
    expect(withLabel(groupOptions, 'operators').some(o => o.props('disabled'))).toBe(false)
    expect(wrapper.vm.protectedRoleOfGroup(4)).toBe('security_admin')
    wrapper.vm.dialogOpen = false
    wrapper.vm.tab = 'roles'
    wrapper.vm.openCreate()
    await flushPromises()
    const roleOptions = wrapper.findAllComponents({ name: 'ElOption' })
    // 選項與表格都顯示中文名，值仍是角色名
    expect(withLabel(roleOptions, 'security_admin')).toHaveLength(0)
    expect(withLabel(roleOptions, '系統安全管理員').some(o => o.props('disabled'))).toBe(true)
    expect(withLabel(roleOptions, '一般使用者').some(o => o.props('disabled'))).toBe(false)
    expect(withLabel(roleOptions, '系統安全管理員').map(o => o.props('value'))).toContain('security_admin')
    // 伺服器標為尚未開放的角色也停用，說明與群組下拉相同
    const notOpen = withLabel(roleOptions, '身分管理員')
    expect(notOpen.some(o => o.props('disabled'))).toBe(true)
    expect(document.body.textContent + wrapper.text()).toContain(t('roles.assignState.notOpen'))
  })

  it('角色分頁目標選單只含可直接映射的角色，選項之後有固定說明', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    await flushPromises()
    // 選項集合等於 direct_mappable 為真的角色：不含資產管理員、授權管理員、自訂角色
    expect(wrapper.vm.directRoles.map(r => r.name)).toEqual(['user', 'auditor', 'security_admin', 'asset_manager', 'identity_admin'])
    expect(wrapper.vm.directRoles.map(r => r.name)).not.toContain('custom_ops')
    const footer = q(wrapper, '[data-test="mapping-direct-hint"]')
    expect(footer.textContent).toContain(t('identityGroupMappings.directMapHint'))
    expect(footer.textContent).toContain(t('identityGroupMappings.directMapHintTitle', { roles: `${roleLabel('asset_admin')}、${roleLabel('authz_admin')}` }))
    // 說明在最後一個選項之後
    const options = Array.from(document.body.querySelectorAll('.el-select-dropdown__item'))
    expect(options.length).toBeGreaterThan(0)
    expect(options.every(o => Boolean(o.compareDocumentPosition(footer) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true)
  })

  it.each(['zh-TW', 'en-US', 'ja-JP'])('角色分頁說明區三步以 1. 2. 3. 起首並點名兩個角色與連線另需資產授權：%s', async (locale) => {
    const previous = i18n.global.locale.value
    try {
      i18n.global.locale.value = locale
      const wrapper = await open()
      const hint = wrapper.get('[data-test="mapping-roles-tab-hint"]')
      expect(hint.text()).toContain(roleLabel('asset_admin'))
      expect(hint.text()).toContain(roleLabel('authz_admin'))
      expect(hint.text()).toContain(t('userGroups.detail.tabs.roles'))
      expect(hint.text()).toContain(t('identityGroupMappings.rolesTabHintConnection'))
      for (const n of [1, 2, 3]) {
        expect(hint.get(`[data-test="mapping-roles-hint-step-${n}"]`).text().startsWith(`${n}.`)).toBe(true)
      }
    } finally {
      i18n.global.locale.value = previous
    }
  })

  it('角色分頁說明區的前往使用者群組連結只在能進該頁時出現', async () => {
    const withLink = await open()
    expect(withLink.find('[data-test="mapping-roles-hint-go-groups"]').exists()).toBe(true)
    policyApi.can.mockImplementation(perm => perm !== 'usergroup:manage')
    const withoutLink = await open()
    expect(withoutLink.find('[data-test="mapping-roles-hint-go-groups"]').exists()).toBe(false)
    expect(withoutLink.find('[data-test="mapping-roles-tab-hint"]').exists()).toBe(true)
    // 角色規則對話框的選單底部說明同樣依能進入與否呈現連結
    withoutLink.vm.openCreate()
    await flushPromises()
    expect(q(withoutLink, '[data-test="mapping-direct-go-groups"]')).toBeNull()
  })

  it('點「改到群組 → 使用者群組」：分頁切到 userGroups，新增規則對話框開啟並沿用外部群組與備註，不送請求', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    wrapper.vm.draft.match_value = 'CN=Ops'
    wrapper.vm.draft.note = '維運'
    await flushPromises()
    const writesBefore = [api.createRole, api.createGroup, api.updateRole, api.updateGroup].map(f => f.mock.calls.length)
    q(wrapper, '[data-test="mapping-switch-to-groups"]').click()
    await flushPromises()
    expect(wrapper.vm.tab).toBe('userGroups')
    expect(wrapper.vm.dialogOpen).toBe(true)
    expect(wrapper.vm.editing).toBeNull()
    expect(wrapper.vm.draft.match_value).toBe('CN=Ops')
    expect(wrapper.vm.draft.note).toBe('維運')
    expect(wrapper.vm.draft.user_group_id).toBeNull()
    expect([api.createRole, api.createGroup, api.updateRole, api.updateGroup].map(f => f.mock.calls.length)).toEqual(writesBefore)
  })

  it('選到管理類目標：出現通知提示與外部目錄提示；一般目標不出現', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    wrapper.vm.draft.role = 'user'
    await flushPromises()
    expect(q(wrapper, '[data-test="mapping-management-hint"]')).toBeNull()
    expect(q(wrapper, '[data-test="mapping-directory-hint"]')).toBeNull()
    wrapper.vm.draft.role = 'asset_manager'
    await flushPromises()
    expect(q(wrapper, '[data-test="mapping-management-hint"]').textContent.trim()).toBe(t('identityGroupMappings.managementRoleTarget', { role: 'asset_manager' }))
    expect(q(wrapper, '[data-test="mapping-directory-hint"]').textContent).toContain(t('identityGroupMappings.externalDirectoryDecides', { role: 'asset_manager' }))
    wrapper.vm.dialogOpen = false
    wrapper.vm.tab = 'userGroups'
    wrapper.vm.openCreate()
    wrapper.vm.draft.user_group_id = 5
    await flushPromises()
    expect(q(wrapper, '[data-test="mapping-management-hint"]').textContent.trim()).toBe(t('identityGroupMappings.managementTarget', { role: 'asset_manager' }))
  })

  it('頁尾規則與時效說明各出現一次', async () => {
    const wrapper = await open()
    expect(wrapper.get('[data-test="mapping-footer-rule"]').text()).toBe(t('identityGroupMappings.footerRule'))
    expect(wrapper.findAll('[data-test="mapping-timing-notice"]')).toHaveLength(1)
    expect(wrapper.findAllComponents({ name: 'MappingTimingNotice' })).toHaveLength(1)
  })

  const keysOf = (call) => Object.keys(call[0]).sort()

  it('新增、修改、停用、刪除四種儲存前各預覽一次：kind 為 mapping_rule_change，既有規則帶 rule_id、新增不帶，本文都不含 subject_ids', async () => {
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = await open()
    // 新增
    wrapper.vm.openCreate()
    wrapper.vm.draft.match_value = ' new-group '
    wrapper.vm.draft.role = 'auditor'
    await wrapper.vm.save()
    expect(defs.preview).toHaveBeenCalledTimes(1)
    expect(defs.preview.mock.calls[0][0]).toEqual({ kind: 'mapping_rule_change', rule_type: 'role', source_type: 'oidc', source_id: 7, match_value: 'new-group', role_id: 2, enabled: true })
    expect(api.createRole).toHaveBeenCalledTimes(1)
    // 修改
    defs.preview.mockClear()
    wrapper.vm.openEdit(ROLE_ROWS[0])
    wrapper.vm.draft.role = 'auditor'
    await wrapper.vm.save()
    expect(defs.preview).toHaveBeenCalledTimes(1)
    expect(defs.preview.mock.calls[0][0]).toEqual({ kind: 'mapping_rule_change', rule_type: 'role', source_type: 'oidc', source_id: 7, rule_id: 9, match_value: 'ops', role_id: 2, enabled: true })
    expect(api.updateRole).toHaveBeenCalledTimes(1)
    // 停用
    defs.preview.mockClear()
    await wrapper.vm.toggle(ROLE_ROWS[0])
    expect(defs.preview).toHaveBeenCalledTimes(1)
    expect(defs.preview.mock.calls[0][0]).toEqual({ kind: 'mapping_rule_change', rule_type: 'role', source_type: 'oidc', source_id: 7, rule_id: 9, enabled: false })
    // 刪除
    defs.preview.mockClear()
    await wrapper.vm.remove(ROLE_ROWS[0])
    expect(defs.preview).toHaveBeenCalledTimes(1)
    expect(defs.preview.mock.calls[0][0]).toEqual({ kind: 'mapping_rule_change', rule_type: 'role', source_type: 'oidc', source_id: 7, rule_id: 9, delete: true })
    expect(api.deleteRole).toHaveBeenCalledTimes(1)
    // 使用者群組分頁用 group_id
    defs.preview.mockClear()
    wrapper.vm.tab = 'userGroups'
    wrapper.vm.openCreate()
    wrapper.vm.draft.match_value = 'ug'
    wrapper.vm.draft.user_group_id = 3
    await wrapper.vm.save()
    expect(defs.preview.mock.calls[0][0]).toEqual({ kind: 'mapping_rule_change', rule_type: 'user_group', source_type: 'oidc', source_id: 7, match_value: 'ug', group_id: 3, enabled: true })
    for (const call of defs.preview.mock.calls) expect(keysOf(call)).not.toContain('subject_ids')
    confirm.mockRestore()
  })

  it('命中時經確認框：返回修改不送出，仍要儲存才送出；通知句帶新目標與管理角色，舊目標收回句出現在底部', async () => {
    defs.preview.mockResolvedValue(HIT)
    const wrapper = await open()
    wrapper.vm.openEdit(ROLE_ROWS[0])
    wrapper.vm.draft.role = 'asset_manager'
    const saving = wrapper.vm.save()
    await flushPromises()
    expect(q(wrapper, '[data-test="danger-combo-confirm"]')).not.toBeNull()
    expect(q(wrapper, '[data-test="danger-notify"]').textContent).toContain(t('dangerConfirm.notify.mappingRule', { target: 'asset_manager', role: 'asset_manager' }))
    expect(q(wrapper, '[data-test="danger-footnote"]').textContent).toContain(t('dangerConfirm.oldTargetRevoked', { target: 'user' }))
    expect(api.updateRole).not.toHaveBeenCalled()
    q(wrapper, '[data-test="danger-back"]').click()
    await saving
    await flushPromises()
    expect(api.updateRole).not.toHaveBeenCalled()
    expect(wrapper.vm.confirmOpen).toBe(false)
    // 再來一次，這次仍要儲存
    const again = wrapper.vm.save()
    await flushPromises()
    q(wrapper, '[data-test="danger-proceed"]').click()
    await again
    expect(api.updateRole).toHaveBeenCalledTimes(1)
    expect(api.updateRole.mock.calls[0][3]).toMatchObject({ role: 'asset_manager', risk_acknowledged: false, source_config_acknowledged: false })
  })

  it('預覽失敗或回 403：標示暫時無法取得，仍可儲存', async () => {
    for (const failure of [new Error('boom'), { response: { status: 403 } }]) {
      defs.preview.mockRejectedValue(failure)
      api.createRole.mockClear()
      const wrapper = await open()
      wrapper.vm.openCreate()
      wrapper.vm.draft.match_value = 'x'
      wrapper.vm.draft.role = 'user'
      const saving = wrapper.vm.save()
      await flushPromises()
      expect(q(wrapper, '[data-test="danger-preview-failed"]')).not.toBeNull()
      expect(api.createRole).not.toHaveBeenCalled()
      q(wrapper, '[data-test="danger-proceed"]').click()
      await saving
      expect(api.createRole).toHaveBeenCalledTimes(1)
      wrapper.unmount()
    }
  })

  it('確認框通過後仍走既有的 risk_acknowledged 重送協定', async () => {
    defs.preview.mockResolvedValue(HIT)
    api.createRole
      .mockRejectedValueOnce({ response: { status: 422, data: { code: 'MAPPING_ACK_REQUIRED', meta: { warnings: [{ code: 'MAPPING_TARGETS_ADMIN_ROLE' }] } } } })
      .mockResolvedValueOnce({ data: { id: 40 } })
    const wrapper = await open()
    wrapper.vm.openCreate()
    wrapper.vm.draft.match_value = 'adm'
    wrapper.vm.draft.role = 'asset_manager'
    const saving = wrapper.vm.save()
    await flushPromises()
    q(wrapper, '[data-test="danger-proceed"]').click()
    await saving
    expect(defs.preview).toHaveBeenCalledTimes(1)
    expect(api.createRole).toHaveBeenCalledTimes(2)
    expect(api.createRole.mock.calls[0][2].risk_acknowledged).toBe(false)
    expect(api.createRole.mock.calls[1][2].risk_acknowledged).toBe(true)
    expect(confirmWarningsMock).toHaveBeenCalledWith(['MAPPING_TARGETS_ADMIN_ROLE'])
  })
})
