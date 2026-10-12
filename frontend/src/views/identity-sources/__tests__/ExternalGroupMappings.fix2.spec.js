import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import i18n from '@/i18n'
import ExternalGroupMappings from '../ExternalGroupMappings.vue'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const routeState = vi.hoisted(() => ({ params: { type: 'oidc', id: '7' } }))
vi.mock('vue-router', () => ({ useRoute: () => routeState }))
const api = vi.hoisted(() => ({ createGroup: vi.fn(), updateGroup: vi.fn(), updateRole: vi.fn(), updateNote: vi.fn(), getSources: vi.fn(), getExternalGroups: vi.fn() }))
const confirmWarningsMock = vi.hoisted(() => vi.fn(async () => true))
vi.mock('@/utils/mappingRiskGate', () => ({ confirmWarnings: (...a) => confirmWarningsMock(...a) }))
vi.mock('@/api/identitySources', () => ({
  getIdentitySources: (...a) => api.getSources(...a),
  getRoleMappings: vi.fn(async () => ({ data: [{ id: 9, match_value: 'CN=Ops,OU=Long,DC=example,DC=test', role: 'user', enabled: true, affected_user_count: 1 }] })),
  getUserGroupMappings: vi.fn(async () => ({ data: [] })),
  getExternalGroups: (...a) => api.getExternalGroups(...a),
  getUserGroupMappingUsage: vi.fn(async () => ({ data: { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 } })),
  createUserGroupMapping: (...a) => api.createGroup(...a),
  updateUserGroupMapping: (...a) => api.updateGroup(...a), deleteUserGroupMapping: vi.fn(),
  createRoleMapping: vi.fn(), updateRoleMapping: (...a) => api.updateRole(...a), deleteRoleMapping: vi.fn(),
  updateExternalGroupNote: (...a) => api.updateNote(...a),
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
    routeState.params = { type: 'oidc', id: '7' }
    confirmWarningsMock.mockResolvedValue(true)
    api.getSources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: false, group_attribute_configured: false }] })
    api.createGroup.mockResolvedValue({ data: { id: 11 } })
    api.updateGroup.mockResolvedValue({ data: { id: 11 } })
    api.updateRole.mockResolvedValue({ data: { id: 19 } })
    api.updateNote.mockResolvedValue({ data: {} })
    api.getExternalGroups.mockResolvedValue({ data: [] })
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

// 舊詳情頁內嵌清單的說明搬到這裡的對話框：比對方式、Entra 物件識別碼位置、
// 管理員與審核者角色。詳情頁不再有規則編輯處，這些提示若沒跟過來就等於遺失
describe('ExternalGroupMappings 新增／編輯對話框的群組值與角色說明', () => {
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
