import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import { roleLabel } from '@/constants/roles'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import ExternalGroupMappings from '../ExternalGroupMappings.vue'

enableAutoUnmount(afterEach)

vi.stubGlobal('MutationObserver', class {
  observe() {}
  disconnect() {}
  takeRecords() { return [] }
})

const t = (key, args) => i18n.global.t(key, args)

const routeState = vi.hoisted(() => ({ params: { type: 'oidc', id: '7' } }))
vi.mock('vue-router', () => ({ useRoute: () => routeState }))

const api = vi.hoisted(() => ({
  sources: vi.fn(), roleRules: vi.fn(), groupRules: vi.fn(), externalGroups: vi.fn(), usage: vi.fn(),
  defs: vi.fn(), groups: vi.fn(), bindings: vi.fn(), options: vi.fn(), policies: vi.fn(), caps: new Set(),
}))
vi.mock('@/api/identitySources', () => ({
  getIdentitySources: (...a) => api.sources(...a),
  getRoleMappings: (...a) => api.roleRules(...a),
  getUserGroupMappings: (...a) => api.groupRules(...a),
  getExternalGroups: (...a) => api.externalGroups(...a),
  getUserGroupMappingUsage: (...a) => api.usage(...a),
  createUserGroupMapping: vi.fn(), updateUserGroupMapping: vi.fn(), deleteUserGroupMapping: vi.fn(),
  createRoleMapping: vi.fn(), updateRoleMapping: vi.fn(), deleteRoleMapping: vi.fn(),
  updateExternalGroupNote: vi.fn(),
  errorCode: () => '',
}))
vi.mock('@/api/roleDefinitions', () => ({
  listRoleDefinitions: (...a) => api.defs(...a),
  previewRoleAssignment: vi.fn(async () => ({ total: 0, matched: 0, truncated: false, subjects: [], operation: { marks: [], evaluated: 0 } })),
  getRoleAssignmentOptions: (...a) => api.options(...a),
}))
vi.mock('@/api/userGroups', () => ({
  getUserGroups: (...a) => api.groups(...a),
  getUserGroupRoleBindings: (...a) => api.bindings(...a),
}))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: (...a) => api.policies(...a) }))
vi.mock('@/composables/useCapabilities', () => ({
  can: (perm) => api.caps.has(perm),
  canAll: (perms) => Array.isArray(perms) && perms.length > 0 && perms.every((p) => api.caps.has(p)),
}))

// 上游真實讀取形狀：節點範圍列帶 scope=nodes 與 node_ids；全系統列 scope=global 且無 node_ids
const DEFS = [
  { id: 1, name: 'asset_admin', builtin_key: 'asset_admin', assignment_state: 'open', direct_mappable: false, management_class: true, scopable: true, node_range_no_effect: false },
  { id: 2, name: 'user', builtin_key: 'user', assignment_state: 'open', direct_mappable: true, management_class: false, scopable: true, node_range_no_effect: true },
  { id: 3, name: 'security_admin', builtin_key: 'security_admin', assignment_state: 'protected', direct_mappable: true, management_class: true, scopable: false, node_range_no_effect: false },
  { id: 4, name: 'custom_ops', builtin_key: null, assignment_state: 'open', direct_mappable: false, management_class: false, scopable: true, node_range_no_effect: false },
]
const NODES = [11, 12, 13, 14, 15].map((id) => ({ id, name: `n${id}`, path: `公司/區${id}`, subtree_asset_count: id }))
const MISSING_ID = 987654
const GROUPS = [
  { id: 1, name: 'g-all' }, // 資產管理員全系統、系統安全管理員全系統
  { id: 2, name: 'g-one' }, // 資產管理員一個節點、一般使用者全系統
  { id: 3, name: 'g-five' }, // 資產管理員五個節點
  { id: 4, name: 'g-stale' }, // 資產管理員：一個存活節點、一個已不存在
  { id: 5, name: 'g-empty-range' }, // 資產管理員：節點範圍但 node_ids 為空
  { id: 6, name: 'g-custom' }, // 自訂可限範圍角色兩個節點、一般使用者全系統
  { id: 7, name: 'g-none' }, // 沒有角色
  { id: 8, name: 'g-ops' }, // 資產管理員全系統，保護列檢查之外的一般群組
  { id: 9, name: 'g-all-stale' }, // 資產管理員：節點範圍且全數失效
]
const BINDINGS = {
  1: [{ role_id: 1, role_name: 'asset_admin', scope: 'global' }, { role_id: 3, role_name: 'security_admin', scope: 'global' }],
  2: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes', node_ids: [11] }, { role_id: 2, role_name: 'user', scope: 'global' }],
  3: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes', node_ids: [11, 12, 13, 14, 15] }],
  4: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes', node_ids: [11, MISSING_ID] }],
  5: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes' }],
  6: [{ role_id: 4, role_name: 'custom_ops', scope: 'nodes', node_ids: [11, 12] }, { role_id: 2, role_name: 'user', scope: 'global' }],
  7: [],
  8: [{ role_id: 1, role_name: 'asset_admin', scope: 'global' }],
  9: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes', node_ids: [MISSING_ID] }],
}
const ruleRows = GROUPS.map((g) => ({
  id: 100 + g.id, match_value: `ext-${g.id}`, user_group_id: g.id, user_group_name: g.name, enabled: true,
  usage: { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 },
}))
const OPTIONS = { nodes: NODES, node_assignable_role_ids: [1, 2, 4], node_range_no_effect_role_ids: [2], node_range_no_effect_reasons: { 2: 'builtin_global_only' } }
const ZERO = { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 }

const setCaps = (...perms) => { api.caps.clear(); perms.forEach((p) => api.caps.add(p)) }
const open = async () => {
  const wrapper = mount(ExternalGroupMappings, {
    attachTo: document.body,
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub, 'router-link': { template: '<a><slot /></a>' } } },
  })
  await flushPromises()
  wrapper.vm.tab = 'userGroups'
  await flushPromises()
  return wrapper
}
const rolesLine = (wrapper, groupName) => {
  const tr = wrapper.findAll('.el-table__body tr').find((row) => row.text().includes(groupName))
  return tr.get('[data-test="mapping-target-roles"]').text()
}
const q = (selector) => document.body.querySelector(selector)

beforeEach(() => {
  vi.clearAllMocks()
  document.body.innerHTML = ''
  setCaps('role:assign', 'usergroup:manage', 'authorization:manage')
  routeState.params = { type: 'oidc', id: '7' }
  api.sources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: true, group_attribute_configured: true }] })
  api.roleRules.mockResolvedValue({ data: [{ id: 9, match_value: 'ext-role', role: 'asset_admin', enabled: true }] })
  api.groupRules.mockResolvedValue({ data: ruleRows })
  api.externalGroups.mockResolvedValue({ data: [] })
  api.usage.mockResolvedValue({ data: { ...ZERO } })
  api.defs.mockResolvedValue({ data: DEFS })
  api.groups.mockResolvedValue({ data: GROUPS })
  api.bindings.mockImplementation(async (id) => ({ data: BINDINGS[id] || [] }))
  api.options.mockResolvedValue(OPTIONS)
  api.policies.mockResolvedValue({ data: [{ key: 'mapping_revalidation_hours', value: '12', unit: '小時', unit_key: 'hours' }] })
})

describe('映射頁目標欄的管理範圍', () => {
  it('能指派角色者：資產管理員全系統寫管理範圍，系統安全管理員之後沒有管理範圍', async () => {
    const wrapper = await open()
    const line = rolesLine(wrapper, 'g-all')
    expect(line).toContain(`${roleLabel('asset_admin')}・管理範圍 全系統`)
    const afterSecurity = line.split(roleLabel('security_admin'))[1]
    expect(afterSecurity).toBeDefined()
    expect(afterSecurity).not.toContain('管理範圍')
  })

  it('資產管理員一個節點寫出路徑與管理範圍，一般使用者之後沒有管理範圍也沒有全系統', async () => {
    const wrapper = await open()
    const line = rolesLine(wrapper, 'g-one')
    expect(line).toContain('管理範圍')
    expect(line).toContain('公司/區11')
    const afterUser = line.split(roleLabel('user'))[1]
    expect(afterUser).toBeDefined()
    expect(afterUser).not.toContain('管理範圍')
    expect(afterUser).not.toContain('全系統')
    expect(line).not.toContain('全系統')
  })

  it('五個節點列前三個路徑並含「等 2 個」', async () => {
    const wrapper = await open()
    const line = rolesLine(wrapper, 'g-five')
    expect(line).toContain('公司/區11、公司/區12、公司/區13')
    expect(line).not.toContain('公司/區14')
    expect(line).toContain('等 2 個')
  })

  it('node_ids 含失效 ID：顯示節點已不存在，渲染 HTML 不含該 ID', async () => {
    const wrapper = await open()
    const line = rolesLine(wrapper, 'g-stale')
    expect(line).toContain(t('roleNodePicker.nodeMissing'))
    expect(line).toContain('公司/區11')
    expect(wrapper.html()).not.toContain(String(MISSING_ID))
  })

  it('node_ids 為空陣列或只含失效節點時不含全系統', async () => {
    const wrapper = await open()
    expect(rolesLine(wrapper, 'g-empty-range')).not.toContain('全系統')
    expect(rolesLine(wrapper, 'g-all-stale')).not.toContain('全系統')
    expect(rolesLine(wrapper, 'g-all-stale')).toContain(t('roleNodePicker.nodeMissing'))
  })

  it('「群組 → 角色」分頁的目標欄不含管理範圍', async () => {
    const wrapper = await open()
    wrapper.vm.tab = 'roles'
    await flushPromises()
    const body = wrapper.find('.el-table__body').text()
    expect(body).toContain(roleLabel('asset_admin'))
    expect(body).not.toContain('管理範圍')
  })
})

describe('映射頁的讀取', () => {
  it('能指派角色時節點清單 API 在頁面載入呼叫一次', async () => {
    await open()
    expect(api.options).toHaveBeenCalledTimes(1)
  })

  it('不能指派角色時不呼叫節點清單，節點範圍顯示限定 2 個節點，全系統仍寫管理範圍', async () => {
    setCaps('usergroup:manage')
    const wrapper = await open()
    expect(api.options).toHaveBeenCalledTimes(0)
    expect(rolesLine(wrapper, 'g-custom')).toContain('限定 2 個節點')
    expect(rolesLine(wrapper, 'g-custom')).not.toContain('公司/區')
    expect(rolesLine(wrapper, 'g-ops')).toContain(`${roleLabel('asset_admin')}・管理範圍 全系統`)
  })

  it('節點清單 API 失敗時同樣顯示限定 N 個節點，表格與按鈕照常，沒有錯誤框', async () => {
    api.options.mockRejectedValue(new Error('down'))
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = await open()
    expect(rolesLine(wrapper, 'g-custom')).toContain('限定 2 個節點')
    expect(wrapper.findAll('[data-test="mapping-edit"]').length).toBe(GROUPS.length)
    expect(wrapper.findAll('[data-test="mapping-toggle"]').length).toBe(GROUPS.length)
    expect(wrapper.findAll('[data-test="mapping-remove"]').length).toBe(GROUPS.length)
    expect(wrapper.find('.el-alert--error').exists()).toBe(false)
    expect(wrapper.find('[data-test="mapping-group-list-failed"]').exists()).toBe(false)
    errorLog.mockRestore()
  })
})

describe('新增規則對話框的目標群組選單', () => {
  const optionTexts = () => Array.from(document.body.querySelectorAll('[data-test^="mapping-option-roles-"]')).map((el) => el.textContent.trim())

  it('每個群組旁列出角色與管理範圍，沒有角色者標示沒有角色，受保護群組停用並說明', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    await flushPromises()
    const asset = roleLabel('asset_admin')
    const byGroup = Object.fromEntries(GROUPS.map((g) => [g.id, q(`[data-test="mapping-option-roles-${g.id}"]`)?.textContent.trim()]))
    expect(byGroup[8]).toBe(`${asset}・全系統`)
    expect(byGroup[2]).toBe(`${asset}・公司/區11、${roleLabel('user')}`)
    expect(byGroup[6]).toBe(`custom_ops・2 個節點、${roleLabel('user')}`)
    expect(byGroup[7]).toBe(t('identityGroupMappings.targetNoRoles'))
    // 帶系統安全管理員角色的群組：停用並附說明，其角色後無管理範圍
    expect(byGroup[1]).toBe(`${asset}・全系統、${roleLabel('security_admin')}`)
    const protectedOption = wrapper.findAllComponents({ name: 'ElOption' }).find((o) => o.props('label') === 'g-all' && o.props('disabled'))
    expect(protectedOption).toBeTruthy()
    expect(protectedOption.text()).toContain(t('identityGroupMappings.protectedOption'))
    expect(byGroup[1].split(roleLabel('security_admin'))[1]).not.toContain('管理範圍')
    expect(optionTexts().length).toBe(GROUPS.length)
  })

  it('不能指派角色者：節點範圍的選項寫限定 1 個節點', async () => {
    setCaps('usergroup:manage')
    const wrapper = await open()
    wrapper.vm.openCreate()
    await flushPromises()
    expect(q('[data-test="mapping-option-roles-2"]').textContent.trim()).toContain('限定 1 個節點')
  })

  it('能進使用者群組頁時選單末尾有前往連結，不能進時沒有；點連結不會選定任何群組', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    await flushPromises()
    const link = q('[data-test="mapping-create-group-link"]')
    expect(link).not.toBeNull()
    expect(link.getAttribute('href')).toBe('/user-groups')
    link.addEventListener('click', (e) => e.preventDefault())
    link.click()
    await flushPromises()
    expect(wrapper.vm.draft.user_group_id).toBeNull()

    wrapper.unmount()
    setCaps('role:assign', 'authorization:manage')
    const without = await open()
    without.vm.openCreate()
    await flushPromises()
    expect(without.vm.canGoUserGroups).toBe(false)
  })
})

describe('選定目標後的說明', () => {
  const select = async (wrapper, id) => {
    wrapper.vm.draft.user_group_id = id
    await wrapper.vm.loadUsage()
    await flushPromises()
  }
  const summary = () => q('[data-test="mapping-target-summary"]')

  it('全系統資產管理員、用途 0 筆：寫群組名、角色、管理範圍、完整連線說明與目前沒有資產授權', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    await select(wrapper, 8)
    const text = summary().textContent
    expect(text).toContain('g-ops')
    expect(text).toContain(`${roleLabel('asset_admin')}・管理範圍 全系統`)
    expect(text).toContain(t('userDetail.change.connectionFixed'))
    expect(text).toContain(t('identityGroupMappings.targetSummaryNoAuthz'))
  })

  it('用途為 2 時改寫目前有 2 筆', async () => {
    api.usage.mockResolvedValue({ data: { ...ZERO, asset_authorizations: 2 } })
    const wrapper = await open()
    wrapper.vm.openCreate()
    await select(wrapper, 8)
    expect(summary().textContent).toContain(t('identityGroupMappings.targetSummaryAuthzCount', { n: 2 }))
    expect(summary().textContent).not.toContain(t('identityGroupMappings.targetSummaryNoAuthz'))
  })

  it('用途尚未回應時寫正在讀取；回錯誤時寫暫時無法取得；兩者都不寫沒有資產授權，角色與連結照常', async () => {
    let settle
    api.usage.mockImplementation(() => new Promise((resolve, reject) => { settle = { resolve, reject } }))
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = await open()
    wrapper.vm.openCreate()
    wrapper.vm.draft.user_group_id = 8
    const pending = wrapper.vm.loadUsage()
    await flushPromises()
    expect(summary().textContent).toContain(t('identityGroupMappings.targetSummaryAuthzLoading'))
    expect(summary().textContent).not.toContain(t('identityGroupMappings.targetSummaryNoAuthz'))
    settle.reject(new Error('usage down'))
    await pending
    await flushPromises()
    expect(summary().textContent).toContain(t('identityGroupMappings.targetSummaryAuthzUnavailable'))
    expect(summary().textContent).not.toContain(t('identityGroupMappings.targetSummaryNoAuthz'))
    expect(summary().textContent).toContain(`${roleLabel('asset_admin')}・管理範圍 全系統`)
    expect(q('[data-test="summary-go-group-roles"]')).not.toBeNull()
    expect(q('[data-test="summary-go-authorizations"]')).not.toBeNull()
    errorLog.mockRestore()
  })

  it('先選甲（回應延後、回 0）再選乙（立即回 2）：甲較晚回來後摘要與目前用途方框仍是乙的數字', async () => {
    let resolveFirst
    api.usage
      .mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve }))
      .mockImplementationOnce(async () => ({ data: { ...ZERO, asset_authorizations: 2 } }))
    const wrapper = await open()
    wrapper.vm.openCreate()
    wrapper.vm.draft.user_group_id = 8
    const first = wrapper.vm.loadUsage()
    wrapper.vm.draft.user_group_id = 2
    await wrapper.vm.loadUsage()
    await flushPromises()
    resolveFirst({ data: { ...ZERO } })
    await first
    await flushPromises()
    expect(summary().textContent).toContain(t('identityGroupMappings.targetSummaryAuthzCount', { n: 2 }))
    expect(summary().textContent).not.toContain(t('identityGroupMappings.targetSummaryNoAuthz'))
    expect(q('.usage-box').textContent).toContain(t('identityGroupMappings.currentUsage', { asset_authorizations: 2, approver_scopes: 0, requester_scopes: 0 }))
  })

  it('能進入時有兩個新分頁連結，不能進入時各自不出現', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    await select(wrapper, 8)
    const groupLink = q('[data-test="summary-go-group-roles"]')
    const authzLink = q('[data-test="summary-go-authorizations"]')
    expect(groupLink.getAttribute('href')).toBe('/user-groups/8?tab=roles')
    expect(authzLink.getAttribute('href')).toBe('/authorizations?user_group_id=8')
    for (const link of [groupLink, authzLink]) {
      expect(link.getAttribute('target')).toBe('_blank')
      expect(link.getAttribute('rel')).toContain('noopener')
    }
    wrapper.unmount()
    setCaps('role:assign', 'authorization:manage')
    const noGroups = await open()
    noGroups.vm.openCreate()
    await select(noGroups, 8)
    expect(noGroups.vm.canGoUserGroups).toBe(false)
    expect(q('[data-test="summary-go-group-roles"]')).toBeNull()
    expect(q('[data-test="summary-go-authorizations"]')).not.toBeNull()
    noGroups.unmount()
    setCaps('role:assign', 'usergroup:manage')
    const noAuthz = await open()
    noAuthz.vm.openCreate()
    await select(noAuthz, 8)
    expect(q('[data-test="summary-go-authorizations"]')).toBeNull()
    expect(q('[data-test="summary-go-group-roles"]')).not.toBeNull()
  })

  it('管理類通知與外部目錄提示的文字與改動前相同，每次選定只讀一次用途', async () => {
    const wrapper = await open()
    wrapper.vm.openCreate()
    api.usage.mockClear()
    await select(wrapper, 8)
    expect(q('[data-test="mapping-management-hint"]').textContent.trim())
      .toBe(t('identityGroupMappings.managementTarget', { role: roleLabel('asset_admin') }))
    expect(q('[data-test="mapping-directory-hint"]').textContent.trim())
      .toBe(t('identityGroupMappings.externalDirectoryDecides', { role: roleLabel('asset_admin') }))
    expect(api.usage).toHaveBeenCalledTimes(1)
    expect(api.options).toHaveBeenCalledTimes(1)
  })
})

describe('目前用途方框與彈層寬', () => {
  it('用途讀取失敗時目前用途方框不寫 0 筆，改寫暫時無法取得；讀取成功時照寫數字', async () => {
    api.usage.mockRejectedValue(new Error('usage down'))
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = await open()
    wrapper.vm.openCreate()
    wrapper.vm.draft.user_group_id = 8
    await wrapper.vm.loadUsage()
    await flushPromises()
    const failedText = q('.usage-box').textContent
    expect(failedText).toContain(t('identityGroupMappings.currentUsageUnavailable'))
    expect(failedText).not.toContain(t('identityGroupMappings.currentUsage', ZERO))
    expect(failedText).not.toContain('0 筆')
    api.usage.mockResolvedValue({ data: { ...ZERO, asset_authorizations: 2 } })
    await wrapper.vm.loadUsage()
    await flushPromises()
    expect(q('.usage-box').textContent).toContain(t('identityGroupMappings.currentUsage', { ...ZERO, asset_authorizations: 2 }))
    expect(q('.usage-box').textContent).not.toContain(t('identityGroupMappings.currentUsageUnavailable'))
    errorLog.mockRestore()
  })

  it('對話框與兩個目標選單的彈層限在視窗內（樣式規則存在，寬螢幕不變）', async () => {
    const src = readFileSync(resolve(__dirname, '../ExternalGroupMappings.vue'), 'utf8')
    expect(src).toContain('width="min(560px, calc(100vw - 16px))"')
    expect(src.match(/popper-class="mapping-select-popper"/g)).toHaveLength(2)
    expect(src).toMatch(/:global\(\.mapping-select-popper\)\s*\{[^}]*max-width:\s*calc\(100vw - 16px\)/)
    expect(src).toMatch(/mapping-select-popper \.el-select-dropdown__item\)\s*\{[^}]*white-space:\s*normal/)
  })
})
