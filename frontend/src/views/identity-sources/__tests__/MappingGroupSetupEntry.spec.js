import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
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
  defs: vi.fn(), groups: vi.fn(), bindings: vi.fn(), options: vi.fn(), preview: vi.fn(),
  createGroup: vi.fn(), putRoles: vi.fn(), createRule: vi.fn(), updateNote: vi.fn(), caps: new Set(),
}))
vi.mock('@/api/identitySources', () => ({
  getIdentitySources: (...a) => api.sources(...a),
  getRoleMappings: (...a) => api.roleRules(...a),
  getUserGroupMappings: (...a) => api.groupRules(...a),
  getExternalGroups: (...a) => api.externalGroups(...a),
  getUserGroupMappingUsage: (...a) => api.usage(...a),
  createUserGroupMapping: (...a) => api.createRule(...a),
  updateUserGroupMapping: vi.fn(), deleteUserGroupMapping: vi.fn(),
  createRoleMapping: vi.fn(), updateRoleMapping: vi.fn(), deleteRoleMapping: vi.fn(),
  updateExternalGroupNote: (...a) => api.updateNote(...a),
  errorCode: () => '',
}))
vi.mock('@/api/roleDefinitions', () => ({
  listRoleDefinitions: (...a) => api.defs(...a),
  previewRoleAssignment: (...a) => api.preview(...a),
  getRoleAssignmentOptions: (...a) => api.options(...a),
}))
vi.mock('@/api/userGroups', () => ({
  getUserGroups: (...a) => api.groups(...a),
  getUserGroupRoleBindings: (...a) => api.bindings(...a),
  createUserGroup: (...a) => api.createGroup(...a),
  replaceUserGroupRoleBindings: (...a) => api.putRoles(...a),
}))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: vi.fn(async () => ({ data: [] })) }))
vi.mock('@/composables/useCapabilities', () => ({
  can: (perm) => api.caps.has(perm),
  canAll: (perms) => Array.isArray(perms) && perms.length > 0 && perms.every((p) => api.caps.has(p)),
}))

const ElDrawerStub = {
  name: 'ElDrawer',
  props: { modelValue: Boolean, title: { type: String, default: '' } },
  emits: ['update:modelValue'],
  template: '<div v-if="modelValue" class="drawer-stub"><slot /><div class="drawer-footer"><slot name="footer" /></div></div>',
}

const defsWith = (assetAdmin = {}) => [
  { id: 1, name: 'asset_admin', builtin_key: 'asset_admin', assignment_state: 'open', direct_mappable: false, management_class: true, scopable: true, node_range_no_effect: false, group_bindable: true, ...assetAdmin },
  { id: 2, name: 'user', builtin_key: 'user', assignment_state: 'open', direct_mappable: true, management_class: false, scopable: true, node_range_no_effect: true, group_bindable: true },
]
const NODES = [{ id: 11, name: 'n11', path: '公司/區11', subtree_asset_count: 11 }]
const OPTIONS = { nodes: NODES, node_assignable_role_ids: [1, 2], node_range_no_effect_role_ids: [2], node_range_no_effect_reasons: { 2: 'builtin_global_only' } }
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const noHit = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp }
const DICT = [{ id: 21, match_value: 'cn=ops', note: '維運組' }]
const ALL3 = ['usergroup:manage', 'role:assign', 'identity_source:manage', 'authorization:manage']

const setCaps = (...perms) => { api.caps.clear(); perms.forEach((p) => api.caps.add(p)) }
const q = (selector) => document.body.querySelector(selector)
const qa = (selector) => [...document.body.querySelectorAll(selector)]

// 以只記錄 open 呼叫的替身取代抽屜，用來看入口傳了什麼
const opened = []
const DrawerSpy = {
  name: 'GroupSetupDrawer',
  template: '<div data-test="drawer-spy" />',
  methods: { open(arg) { opened.push(arg) } },
}

const mountPage = async ({ spy = false } = {}) => {
  const w = mount(ExternalGroupMappings, {
    attachTo: document.body,
    global: {
      plugins: [ElementPlus],
      stubs: {
        ElDialog: ElDialogStub,
        ElDrawer: ElDrawerStub,
        'router-link': { template: '<a><slot /></a>' },
        ...(spy ? { GroupSetupDrawer: DrawerSpy } : {}),
      },
    },
  })
  await flushPromises()
  return w
}
const toGroupTab = async (w) => {
  w.vm.tab = 'userGroups'
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  opened.length = 0
  document.body.innerHTML = ''
  setCaps(...ALL3)
  i18n.global.locale.value = 'zh-TW'
  routeState.params = { type: 'oidc', id: '7' }
  api.sources.mockResolvedValue({ data: [{ id: 7, type: 'oidc', name: 'demo', enabled: true, group_attribute_configured: true }] })
  api.roleRules.mockResolvedValue({ data: [] })
  api.groupRules.mockResolvedValue({ data: [] })
  api.externalGroups.mockResolvedValue({ data: DICT })
  api.usage.mockResolvedValue({ data: { asset_authorizations: 0, approver_scopes: 0, requester_scopes: 0 } })
  api.defs.mockResolvedValue({ data: defsWith() })
  api.groups.mockResolvedValue({ data: [{ id: 1, name: 'g1' }] })
  api.bindings.mockResolvedValue({ data: [] })
  api.options.mockResolvedValue(OPTIONS)
  api.preview.mockResolvedValue(noHit)
  api.createGroup.mockResolvedValue({ id: 31 })
  api.putRoles.mockResolvedValue({ data: [] })
  api.createRule.mockResolvedValue({ data: { id: 1 } })
})

describe('入口的可見性與既有前往連結並存', () => {
  const surface = async (w) => {
    // 角色規則分頁的說明區與角色規則對話框
    const hint = {
      entry: w.find('[data-test="mapping-setup-entry-hint"]').exists(),
      go: w.findAll('[data-test="mapping-roles-hint-go-groups"]').length,
      steps: [1, 2, 3].every((n) => w.find(`[data-test="mapping-roles-hint-step-${n}"]`).exists()),
    }
    w.vm.openCreate()
    await flushPromises()
    const roleMenu = {
      entry: qa('[data-test="mapping-setup-entry-roles-menu"]').length,
      go: qa('[data-test="mapping-direct-go-groups"]').length,
      sw: qa('[data-test="mapping-switch-to-groups"]').length,
    }
    // 使用者群組規則對話框
    await toGroupTab(w)
    w.vm.openCreate()
    await flushPromises()
    const groupMenu = {
      entry: qa('[data-test="mapping-setup-entry-group-menu"]').length,
      create: qa('[data-test="mapping-create-group-link"]').map((a) => a.getAttribute('href')),
    }
    return { hint, roleMenu, groupMenu }
  }

  it('(a) 三項皆持有：三個入口都在，且第一段的步驟說明、前往連結（說明區與角色選單底部各一）、切換分頁與選單末尾連結全部並存', async () => {
    const w = await mountPage()
    const s = await surface(w)
    expect(s.hint).toEqual({ entry: true, go: 1, steps: true })
    expect(s.roleMenu).toEqual({ entry: 1, go: 1, sw: 1 })
    expect(s.groupMenu).toEqual({ entry: 1, create: ['/user-groups'] })
    // 使用者群組規則選單的入口是第一項
    const firstOption = q('.mapping-select-popper .el-select-dropdown__item, [data-test="mapping-setup-entry-group-menu"]')
    expect(firstOption.getAttribute('data-test')).toBe('mapping-setup-entry-group-menu')
    expect(q('[data-test="mapping-setup-entry-group-menu"]').textContent).toContain(t('groupSetup.entry.option'))
  })

  it('(b) 缺角色指派能力：三個入口都不在，前往連結與選單末尾連結照常存在', async () => {
    setCaps('usergroup:manage', 'identity_source:manage', 'authorization:manage')
    const w = await mountPage()
    const s = await surface(w)
    expect(s.hint).toEqual({ entry: false, go: 1, steps: true })
    expect(s.roleMenu).toEqual({ entry: 0, go: 1, sw: 1 })
    expect(s.groupMenu).toEqual({ entry: 0, create: ['/user-groups'] })
  })

  it('(c) 缺使用者群組管理能力：入口與兩個前往連結、選單末尾連結都不在，步驟說明與切換分頁照常，點後切到使用者群組規則分頁', async () => {
    setCaps('role:assign', 'identity_source:manage', 'authorization:manage')
    const w = await mountPage()
    const s = await surface(w)
    expect(s.hint).toEqual({ entry: false, go: 0, steps: true })
    expect(s.roleMenu).toEqual({ entry: 0, go: 0, sw: 1 })
    expect(s.groupMenu).toEqual({ entry: 0, create: [] })
    w.vm.tab = 'roles'
    await flushPromises()
    w.vm.openCreate()
    await flushPromises()
    q('[data-test="mapping-switch-to-groups"]').click()
    await flushPromises()
    expect(w.vm.tab).toBe('userGroups')
  })

  it('(d) 缺身分來源管理能力：三個入口都不在，前往連結同 (b)', async () => {
    setCaps('usergroup:manage', 'role:assign', 'authorization:manage')
    const w = await mountPage()
    const s = await surface(w)
    expect(s.hint).toEqual({ entry: false, go: 1, steps: true })
    expect(s.roleMenu).toEqual({ entry: 0, go: 1, sw: 1 })
    expect(s.groupMenu).toEqual({ entry: 0, create: ['/user-groups'] })
  })
})

describe('入口帶入外部群組與預選', () => {
  it('角色規則對話框填不在字典的外部群組與備註後按選單底部入口：規則對話框關閉，抽屜收到帶入值與入口來源', async () => {
    const w = await mountPage({ spy: true })
    w.vm.openCreate()
    await flushPromises()
    w.vm.draft.match_value = 'cn=fresh'
    w.vm.draft.note = '新備註'
    await flushPromises()
    // 規則對話框的目標系統角色選單是頁面上最後一個選單
    const select = w.findAllComponents({ name: 'ElSelect' }).at(-1)
    select.vm.expanded = true
    await flushPromises()
    expect(select.vm.expanded).toBe(true)
    q('[data-test="mapping-setup-entry-roles-menu"]').click()
    await flushPromises()
    expect(select.vm.expanded).toBe(false)
    expect(w.vm.dialogOpen).toBe(false)
    expect(opened).toEqual([{ matchValue: 'cn=fresh', note: '新備註', entry: 'roleRuleMenu' }])
  })

  it('填字典中已有的外部群組時帶入字典的顯示名稱；說明區入口沒有帶入值', async () => {
    const w = await mountPage({ spy: true })
    await w.get('[data-test="mapping-setup-entry-hint"]').trigger('click')
    expect(opened).toEqual([{ matchValue: '', note: '', entry: 'rolesTabHint' }])
    opened.length = 0
    w.vm.openCreate()
    await flushPromises()
    w.vm.draft.match_value = 'cn=ops'
    await flushPromises()
    q('[data-test="mapping-setup-entry-roles-menu"]').click()
    await flushPromises()
    expect(opened).toEqual([{ matchValue: 'cn=ops', note: '維運組', entry: 'roleRuleMenu' }])
  })

  it('使用者群組選單選「建立新群組」：不成為 user_group_id，規則儲存沒有被呼叫，規則對話框關閉，入口來源為 groupRuleMenu', async () => {
    const w = await mountPage({ spy: true })
    await toGroupTab(w)
    w.vm.openCreate()
    await flushPromises()
    w.vm.draft.match_value = 'cn=fresh'
    await flushPromises()
    q('[data-test="mapping-setup-entry-group-menu"]').click()
    await flushPromises()
    expect(w.vm.draft.user_group_id).toBeNull()
    expect(api.createRule).not.toHaveBeenCalled()
    expect(w.vm.dialogOpen).toBe(false)
    expect(opened).toEqual([{ matchValue: 'cn=fresh', note: '', entry: 'groupRuleMenu' }])
  })

  const rolesInStep2 = async (w) => {
    // 抽屜第 1 步填名稱後到第 2 步
    await w.get('[data-test="setup-name"]').setValue('預選測試')
    await w.get('[data-test="setup-next"]').trigger('click')
    await flushPromises()
    return w.findAll('[data-test="group-role-editor"] tr.role-row')
  }

  it('從「群組 → 角色」兩個入口進入：第 2 步恰為內建資產管理員一個角色（改顯示名仍選中），可取消選取', async () => {
    api.defs.mockResolvedValue({ data: defsWith({ name: '總管角色' }) })
    const w = await mountPage()
    await w.get('[data-test="mapping-setup-entry-hint"]').trigger('click')
    await flushPromises()
    let rows = await rolesInStep2(w)
    expect(rows).toHaveLength(1)
    expect(w.find('[data-test="group-role-總管角色"]').exists()).toBe(true)
    await w.get('[data-test="remove-總管角色"]').trigger('click')
    expect(w.findAll('[data-test="group-role-editor"] tr.role-row')).toHaveLength(0)

    await w.get('[data-test="setup-cancel"]').trigger('click')
    await flushPromises()
    w.vm.openCreate()
    await flushPromises()
    q('[data-test="mapping-setup-entry-roles-menu"]').click()
    await flushPromises()
    rows = await rolesInStep2(w)
    expect(rows).toHaveLength(1)
    expect(w.find('[data-test="group-role-總管角色"]').exists()).toBe(true)
  })

  it('資產管理員在角色選單中為停用（尚未開放）時兩個入口都不預選；從「群組 → 使用者群組」選單進入時不預選', async () => {
    api.defs.mockResolvedValue({ data: defsWith({ assignment_state: 'not_open' }) })
    const w = await mountPage()
    await w.get('[data-test="mapping-setup-entry-hint"]').trigger('click')
    await flushPromises()
    expect(await rolesInStep2(w)).toHaveLength(0)

    api.defs.mockResolvedValue({ data: defsWith() })
    const w2 = await mountPage()
    await toGroupTab(w2)
    w2.vm.openCreate()
    await flushPromises()
    q('[data-test="mapping-setup-entry-group-menu"]').click()
    await flushPromises()
    expect(await rolesInStep2(w2)).toHaveLength(0)

    api.defs.mockResolvedValue({ data: defsWith({ assignment_state: 'not_open' }) })
    const w3 = await mountPage()
    w3.vm.openCreate()
    await flushPromises()
    q('[data-test="mapping-setup-entry-roles-menu"]').click()
    await flushPromises()
    expect(await rolesInStep2(w3)).toHaveLength(0)
  })

  it('帶入字典中已有的外部群組：第 3 步外部群組等於帶入值，顯示名稱為唯讀的字典值', async () => {
    const w = await mountPage()
    w.vm.openCreate()
    await flushPromises()
    w.vm.draft.match_value = 'cn=ops'
    await flushPromises()
    q('[data-test="mapping-setup-entry-roles-menu"]').click()
    await flushPromises()
    await w.get('[data-test="setup-name"]').setValue('帶入測試')
    await w.get('[data-test="setup-next"]').trigger('click')
    await w.get('[data-test="setup-next"]').trigger('click')
    await flushPromises()
    const match = w.get('[data-test="setup-match"]')
    const input = ['INPUT'].includes(match.element.tagName) ? match : match.get('input')
    expect(input.element.value).toBe('cn=ops')
    expect(w.get('[data-test="setup-note-readonly"]').element.value).toBe('維運組')
  })
})

describe('抽屜關閉後映射頁重新讀取', () => {
  const toSubmit = async (w) => {
    await w.get('[data-test="mapping-setup-entry-hint"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="setup-name"]').setValue('關閉測試')
    await w.get('[data-test="setup-next"]').trigger('click')
    await w.get('[data-test="setup-next"]').trigger('click')
    await flushPromises()
    const match = w.get('[data-test="setup-match"]')
    await (match.element.tagName === 'INPUT' ? match : match.get('input')).setValue('cn=close')
    await w.get('[data-test="setup-submit"]').trigger('click')
    for (let i = 0; i < 4; i++) await flushPromises()
  }

  it('完成後按完成與部分完成後關閉各使群組與規則清單再被讀取一次', async () => {
    const w = await mountPage()
    expect([api.groupRules.mock.calls.length, api.groups.mock.calls.length]).toEqual([1, 1])
    await toSubmit(w)
    await w.get('[data-test="setup-finish"]').trigger('click')
    await flushPromises()
    expect([api.groupRules.mock.calls.length, api.groups.mock.calls.length]).toEqual([2, 2])

    api.createRule.mockRejectedValue({ response: { status: 403, data: { error: { code: 'AUTH_PERMISSION_DENIED' } } } })
    await toSubmit(w)
    expect(w.get('[data-test="setup-row-3-state"]').attributes('data-state')).toBe('rejected')
    await w.get('[data-test="setup-close"]').trigger('click')
    await flushPromises()
    expect([api.groupRules.mock.calls.length, api.groups.mock.calls.length]).toEqual([3, 3])
  })

  it('第 2 步按取消：寫入 API 呼叫數為 0，仍重新讀取；從規則對話框進入後取消，規則對話框維持關閉', async () => {
    const w = await mountPage()
    w.vm.openCreate()
    await flushPromises()
    q('[data-test="mapping-setup-entry-roles-menu"]').click()
    await flushPromises()
    await w.get('[data-test="setup-name"]').setValue('取消測試')
    await w.get('[data-test="setup-next"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="setup-cancel"]').trigger('click')
    await flushPromises()
    expect(api.createGroup).not.toHaveBeenCalled()
    expect(api.putRoles).not.toHaveBeenCalled()
    expect(api.createRule).not.toHaveBeenCalled()
    expect(api.updateNote).not.toHaveBeenCalled()
    expect([api.groupRules.mock.calls.length, api.groups.mock.calls.length]).toEqual([2, 2])
    expect(w.vm.dialogOpen).toBe(false)
  })
})
