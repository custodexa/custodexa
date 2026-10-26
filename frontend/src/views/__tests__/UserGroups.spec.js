import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserGroups from '../UserGroups.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { roleLabel } from '@/constants/roles'
import i18n from '@/i18n'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容（同 MyConnections）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getUserGroupsMock = vi.fn()
const createUserGroupMock = vi.fn()
const updateUserGroupMock = vi.fn()
const deleteUserGroupMock = vi.fn()
const replaceUserGroupMembersMock = vi.fn()
const getUserGroupAuthorizationCountMock = vi.fn()
const getUserGroupRoleBindingsMock = vi.fn()

vi.mock('@/api/userGroups', () => ({
  getUserGroups: (...a) => getUserGroupsMock(...a),
  createUserGroup: (...a) => createUserGroupMock(...a),
  updateUserGroup: (...a) => updateUserGroupMock(...a),
  deleteUserGroup: (...a) => deleteUserGroupMock(...a),
  replaceUserGroupMembers: (...a) => replaceUserGroupMembersMock(...a),
  getUserGroupAuthorizationCount: (...a) => getUserGroupAuthorizationCountMock(...a),
  getUserGroupRoleBindings: (...a) => getUserGroupRoleBindingsMock(...a),
}))

const listRoleDefinitionsMock = vi.fn()
const getRoleAssignmentOptionsMock = vi.fn()
vi.mock('@/api/roleDefinitions', () => ({
  listRoleDefinitions: (...a) => listRoleDefinitionsMock(...a),
  getRoleAssignmentOptions: (...a) => getRoleAssignmentOptionsMock(...a),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

vi.mock('@/api/auth', () => ({
  getUsers: vi.fn().mockResolvedValue({
    data: [
      { id: 1, username: 'alice' },
      { id: 2, username: 'bob' },
    ],
  }),
}))

const sampleGroups = {
  data: [
    {
      id: 1,
      name: 'ops',
      description: '維運',
      users: [{ id: 1, username: 'alice' }],
    },
    { id: 2, name: 'dev', description: '', users: [] },
  ],
  total: 2,
}

const mountView = () =>
  mount(UserGroups, {
    global: { plugins: [ElementPlus] },
  })

describe('UserGroups 使用者群組管理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getUserGroupsMock.mockResolvedValue(sampleGroups)
    getUserGroupRoleBindingsMock.mockResolvedValue({ data: [] })
    listRoleDefinitionsMock.mockResolvedValue({ data: [] })
    getRoleAssignmentOptionsMock.mockResolvedValue({ nodes: [], node_range_no_effect_reasons: {} })
    resetCapabilities()
  })

  it('列表渲染群組與成員 tag', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('ops')
    expect(text).toContain('alice')
    expect(text).toContain('dev')
    expect(text).toContain('無成員')
  })

  it('建立群組送出正確 payload 並刷新列表', async () => {
    createUserGroupMock.mockResolvedValue({ id: 3, name: 'sec' })
    const wrapper = mountView()
    await flushPromises()
    getUserGroupsMock.mockClear()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    wrapper.vm.form.name = 'sec'
    wrapper.vm.form.description = '安全組'

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(createUserGroupMock).toHaveBeenCalledWith({ name: 'sec', description: '安全組' })
    expect(wrapper.vm.formDialogVisible).toBe(false)
    expect(getUserGroupsMock).toHaveBeenCalled()
  })

  it('編輯群組走 update 分支', async () => {
    updateUserGroupMock.mockResolvedValue({ id: 1, name: 'ops-renamed' })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openEditDialog({ id: 1, name: 'ops', description: '維運' })
    await flushPromises()
    wrapper.vm.form.name = 'ops-renamed'

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(updateUserGroupMock).toHaveBeenCalledWith(1, {
      name: 'ops-renamed',
      description: '維運',
    })
  })

  it('成員全量替換（穿梭框語義）', async () => {
    replaceUserGroupMembersMock.mockResolvedValue({ id: 1, users: [] })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openMembersDialog(sampleGroups.data[0])
    await flushPromises()
    // 預設帶入既有成員
    expect(wrapper.vm.memberIds).toEqual([1])

    wrapper.vm.memberIds = [1, 2]
    await wrapper.vm.submitMembers()
    await flushPromises()

    expect(replaceUserGroupMembersMock).toHaveBeenCalledWith(1, [1, 2])
    expect(wrapper.vm.membersDialogVisible).toBe(false)
  })

  it('建立失敗（重名 409）對話框保持開啟', async () => {
    createUserGroupMock.mockRejectedValue(new Error('使用者群組名稱已存在'))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    await flushPromises()
    wrapper.vm.form.name = 'ops'

    await wrapper.vm.submitForm()
    await flushPromises()

    expect(createUserGroupMock).toHaveBeenCalled()
    expect(wrapper.vm.formDialogVisible).toBe(true)
  })
})

// —— 角色與管理範圍欄（沿共用呈現工具；資料取自列表本來就逐群組讀的角色指派）——
describe('UserGroups 角色與管理範圍欄', () => {
  const t = (k, p) => i18n.global.t(k, p)
  const DEFS = [
    { id: 1, name: 'asset_admin', builtin_key: 'asset_admin', assignment_state: 'open', scopable: true, node_range_no_effect: false },
    { id: 2, name: 'user', builtin_key: 'user', assignment_state: 'open', scopable: true, node_range_no_effect: true },
    { id: 3, name: 'security_admin', builtin_key: 'security_admin', assignment_state: 'protected', scopable: false, node_range_no_effect: false },
  ]
  const GROUPS = {
    data: [
      { id: 11, name: 'alpha', description: '', users: [] },
      { id: 12, name: 'beta', description: '', users: [] },
      { id: 13, name: 'gamma', description: '', users: [] },
      { id: 14, name: 'delta', description: '', users: [] },
      { id: 15, name: 'epsilon', description: '', users: [] },
    ],
    total: 5,
  }
  const BINDINGS = {
    11: [{ role_id: 1, role_name: 'asset_admin', scope: 'global' }],
    12: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes', node_ids: [21] }],
    13: [{ role_id: 2, role_name: 'user', scope: 'global' }],
    14: [],
    15: [{ role_id: 3, role_name: 'security_admin', scope: 'global' }],
  }
  const OPTIONS = { nodes: [{ id: 21, name: 'n21', path: '公司/北區', subtree_asset_count: 3 }], node_range_no_effect_reasons: { 2: 'builtin_global_only' } }

  beforeEach(() => {
    getUserGroupsMock.mockResolvedValue(GROUPS)
    getUserGroupRoleBindingsMock.mockImplementation(async (id) => ({ data: BINDINGS[id] || [] }))
    listRoleDefinitionsMock.mockResolvedValue({ data: DEFS })
    getRoleAssignmentOptionsMock.mockResolvedValue(OPTIONS)
  })

  const cell = (wrapper, id) => wrapper.get(`[data-test="group-roles-${id}"]`).text()

  it('資產管理員全系統：欄內含資產管理員與全系統；一般使用者只列名稱不含全系統', async () => {
    setCapabilitiesForTests(['role:assign'])
    const wrapper = mountView()
    await flushPromises()
    expect(cell(wrapper, 11)).toContain(roleLabel('asset_admin'))
    expect(cell(wrapper, 11)).toContain('全系統')
    expect(cell(wrapper, 13)).toContain(roleLabel('user'))
    expect(cell(wrapper, 13)).not.toContain('全系統')
  })

  it('能指派角色者看到節點路徑；不能指派者看到限定 1 個節點且節點清單 API 呼叫 0 次', async () => {
    setCapabilitiesForTests(['role:assign'])
    const withPath = mountView()
    await flushPromises()
    expect(cell(withPath, 12)).toContain('公司/北區')
    expect(getRoleAssignmentOptionsMock).toHaveBeenCalledTimes(1)
    withPath.unmount()

    vi.clearAllMocks()
    getUserGroupsMock.mockResolvedValue(GROUPS)
    getUserGroupRoleBindingsMock.mockImplementation(async (id) => ({ data: BINDINGS[id] || [] }))
    listRoleDefinitionsMock.mockResolvedValue({ data: DEFS })
    setCapabilitiesForTests([])
    const countOnly = mountView()
    await flushPromises()
    expect(cell(countOnly, 12)).toContain('限定 1 個節點')
    expect(cell(countOnly, 12)).not.toContain('公司/北區')
    expect(getRoleAssignmentOptionsMock).toHaveBeenCalledTimes(0)
  })

  it('沒有角色的群組標示沒有角色並附設定角色連結；名稱連結都直達角色與範圍分頁', async () => {
    setCapabilitiesForTests(['role:assign'])
    const wrapper = mountView()
    await flushPromises()
    expect(cell(wrapper, 14)).toContain(t('identityGroupMappings.targetNoRoles'))
    expect(wrapper.get('[data-test="set-roles-14"]').attributes('href')).toBe('/user-groups/14?tab=roles')
    for (const id of [11, 12, 13, 14, 15]) {
      expect(wrapper.get(`[data-test="group-link-${id}"]`).attributes('href')).toBe(`/user-groups/${id}?tab=roles`)
    }
  })

  it('帶系統安全管理員角色的群組名旁有受保護標示，其他群組沒有；角色讀取次數等於群組數', async () => {
    setCapabilitiesForTests(['role:assign'])
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.get('[data-test="protected-badge-15"]').text()).toContain(t('userGroups.detail.roles.protectedBadge'))
    expect(wrapper.find('[data-test="protected-badge-11"]').exists()).toBe(false)
    expect(getUserGroupRoleBindingsMock).toHaveBeenCalledTimes(5)
  })

  it('節點清單讀取失敗時列表照常呈現、退回節點數，沒有錯誤框', async () => {
    setCapabilitiesForTests(['role:assign'])
    getRoleAssignmentOptionsMock.mockRejectedValue(new Error('down'))
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    const wrapper = mountView()
    await flushPromises()
    expect(cell(wrapper, 12)).toContain('限定 1 個節點')
    expect(cell(wrapper, 11)).toContain('全系統')
    expect(wrapper.find('.el-alert--error').exists()).toBe(false)
    errorLog.mockRestore()
  })
})

describe('UserGroups 讀不到角色定義時的角色欄', () => {
  const GROUPS = {
    data: [
      { id: 11, name: 'alpha', description: '', users: [] },
      { id: 12, name: 'beta', description: '', users: [] },
    ],
    total: 2,
  }
  const BINDINGS = {
    11: [{ role_id: 1, role_name: 'asset_admin', scope: 'global' }],
    12: [{ role_id: 1, role_name: 'asset_admin', scope: 'nodes', node_ids: [21] }, { role_id: 2, role_name: 'user', scope: 'global' }],
  }

  beforeEach(() => {
    getUserGroupsMock.mockResolvedValue(GROUPS)
    getUserGroupRoleBindingsMock.mockImplementation(async (id) => ({ data: BINDINGS[id] || [] }))
    listRoleDefinitionsMock.mockRejectedValue({ response: { status: 403 } })
    getRoleAssignmentOptionsMock.mockResolvedValue({ nodes: [], node_range_no_effect_reasons: {} })
  })

  it('角色定義讀取失敗：仍逐群組讀角色指派並列出角色名稱，不寫範圍說明，欄位不是「-」', async () => {
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => {})
    setCapabilitiesForTests(['usergroup:manage'])
    const wrapper = mountView()
    await flushPromises()
    expect(getUserGroupRoleBindingsMock).toHaveBeenCalledTimes(2)
    for (const id of [11, 12]) {
      const text = wrapper.get(`[data-test="group-roles-${id}"]`).text()
      expect(text).toContain(roleLabel('asset_admin'))
      expect(text).not.toBe('-')
      expect(text).not.toContain('全系統')
      expect(text).not.toContain('管理範圍')
    }
    expect(wrapper.get('[data-test="group-roles-12"]').text()).toContain(roleLabel('user'))
    errorLog.mockRestore()
  })
})
