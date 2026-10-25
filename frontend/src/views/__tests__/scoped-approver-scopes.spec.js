/* eslint-disable vue/one-component-per-file, vue/require-prop-types -- 測試替身元件 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApproverScopes from '../ApproverScopes.vue'
import ApproverScopeForm from '@/components/ApproverScopeForm.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import zhTW from '@/i18n/locales/zh-TW.json'

// 審核範圍總覽與新增對話框的精簡路徑：列表回應帶 coverage（非超級管理者）時，
// 只用列表與兩個選擇端點；夾具以伺服器回應契約的形狀從 API 模組層餵入。

class ObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

// 表格替身：樹狀資料攤平成列，每格標上列鍵，方便逐列檢查操作鈕
const STUB_ROWS = Symbol('approverScopeRows')
const flatten = (rows) => (rows || []).flatMap((r) => [r, ...flatten(r.children)])
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => flatten(this.data)) }
  },
  template: '<div class="table-stub"><slot /></div>',
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop', 'type'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const v = this.stubRows
      if (!v) return []
      return Array.isArray(v) ? v : v.value || []
    },
  },
  template: `<div class="col-stub" :data-label="label">
    <div v-for="(row, i) in rows" :key="i" class="cell-stub" :data-key="row.key"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const tooltipStub = { template: '<span class="tooltip-stub"><slot /></span>' }
const stubs = {
  ElTable: tableStub,
  ElTableColumn: tableColumnStub,
  'el-dialog': dialogStub,
  ElDialog: dialogStub,
  ElTooltip: tooltipStub,
}

const getApproverScopesMock = vi.fn()
const approverOptionsMock = vi.fn()
const targetOptionsMock = vi.fn()
const createApproverScopeMock = vi.fn()
const getUserListMock = vi.fn()
const addUserRoleMock = vi.fn()
const getUserGroupsMock = vi.fn()
const getAssetGroupsMock = vi.fn()
const getAssetListMock = vi.fn()
const getSecurityPoliciesMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getApproverScopes: (...a) => getApproverScopesMock(...a),
  createApproverScope: (...a) => createApproverScopeMock(...a),
  deleteApproverScope: vi.fn().mockResolvedValue({}),
  getApproverScopeApproverOptions: (...a) => approverOptionsMock(...a),
  getApproverScopeTargetOptions: (...a) => targetOptionsMock(...a),
}))
vi.mock('@/api/user', () => ({
  getUserList: (...a) => getUserListMock(...a),
  addUserRole: (...a) => addUserRoleMock(...a),
}))
vi.mock('@/api/userGroups', () => ({
  getUserGroups: (...a) => getUserGroupsMock(...a),
}))
vi.mock('@/api/assets', () => ({
  getAssetGroups: (...a) => getAssetGroupsMock(...a),
  getAssetList: (...a) => getAssetListMock(...a),
}))
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getSecurityPoliciesMock(...a),
}))

// —— 契約夾具（伺服器回應形狀）——
const row = (id, extra) => ({
  id,
  approver_id: 8,
  approver_group_id: null,
  asset_id: null,
  asset_group_id: null,
  subject_user_id: null,
  subject_group_id: null,
  granted_by: 1,
  created_at: '2026-10-01T00:00:00Z',
  approver: { id: 8, username: 'appr' },
  ...extra,
})

const APPROVER_OPTIONS = {
  users: [
    { id: 1, username: 'admin', display_name: 'admin', active: true, is_approver: false, selectable: false },
    { id: 7, username: 'carol', display_name: 'carol', active: true, is_approver: false, selectable: true },
    { id: 8, username: 'appr', display_name: '審核甲', active: true, is_approver: true, selectable: true },
    { id: 10, username: 'audit', display_name: 'audit', active: true, is_approver: true, selectable: false },
  ],
  groups: [{ id: 4, name: 'DBA' }],
}

// 管理範圍在 prod/db：prod 只作定位祖先
const LOCATOR_LIST = {
  data: [
    row(21, { asset_group_id: 2, asset_group: { id: 2, name: 'db' } }),
    row(22, { asset_id: 31, asset: { id: 31, name: 'db-1' } }),
  ],
  total: 2,
  coverage: [{ node_id: 2, approver_count: 3 }],
  min_approvals: 2,
  applicant_manageable: false,
  management_scope: 'nodes',
}
const LOCATOR_NODES = [
  { id: 1, name: 'prod', path: 'prod', selectable: false },
  { id: 2, name: 'db', path: 'prod / db', selectable: true },
]

// 審核範圍管理在 prod、節點管理在 sit（後者與審核範圍無關）
const K_PROD_LIST = {
  data: [row(23, { asset_group_id: 2, asset_group: { id: 2, name: 'db' } })],
  total: 1,
  coverage: [
    { node_id: 1, approver_count: 0 },
    { node_id: 2, approver_count: 1 },
    { node_id: 5, approver_count: 0 },
  ],
  min_approvals: 1,
  applicant_manageable: false,
  management_scope: 'nodes',
}
const K_PROD_NODES = [
  { id: 1, name: 'prod', path: 'prod', selectable: true },
  { id: 2, name: 'db', path: 'prod / db', selectable: true },
  { id: 5, name: 'web', path: 'prod / web', selectable: true },
]

// 全域審核範圍管理＋全域申請人型管理（非超級管理者）
const GLOBAL_LIST = {
  data: [
    row(24, { asset_group_id: 2, asset_group: { id: 2, name: 'db' } }),
    row(25, { subject_group_id: 4, subject_group: { id: 4, name: 'DBA' } }),
  ],
  total: 2,
  coverage: [
    { node_id: 1, approver_count: 0 },
    { node_id: 2, approver_count: 1 },
  ],
  min_approvals: 1,
  applicant_manageable: true,
}
const GLOBAL_NODES = [
  { id: 1, name: 'prod', path: 'prod', selectable: true },
  { id: 2, name: 'db', path: 'prod / db', selectable: true },
]

const ASSET_OPTIONS = [{ id: 31, name: 'db-1' }]

const useFixture = (list, nodes) => {
  getApproverScopesMock.mockResolvedValue(list)
  approverOptionsMock.mockResolvedValue(APPROVER_OPTIONS)
  targetOptionsMock.mockImplementation((p) =>
    Promise.resolve(
      p.kind === 'node'
        ? { kind: 'node', data: nodes, total: nodes.length, page: 1, page_size: 1000 }
        : { kind: 'asset', data: ASSET_OPTIONS, total: ASSET_OPTIONS.length, page: 1, page_size: 1000 }
    )
  )
}

const mountView = () => mount(ApproverScopes, { global: { plugins: [ElementPlus], stubs } })
const mountForm = (scoped) =>
  mount(ApproverScopeForm, { props: { scoped, showHelp: false }, global: { plugins: [ElementPlus], stubs } })

const cell = (wrapper, key) => wrapper.findAll(`.cell-stub[data-key="${key}"]`)
const subjectLabels = [zhTW.enum.scopeType.subject_user, zhTW.enum.scopeType.subject_group]

const expectNoListEndpoints = () => {
  expect(getUserListMock).toHaveBeenCalledTimes(0)
  expect(getUserGroupsMock).toHaveBeenCalledTimes(0)
  expect(getSecurityPoliciesMock).toHaveBeenCalledTimes(0)
  expect(getAssetGroupsMock).toHaveBeenCalledTimes(0)
}

describe('審核範圍總覽：精簡路徑', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetCapabilities()
    // 若誤走現行路徑，這些回應會帶出 sit 與其他使用者
    getUserListMock.mockResolvedValue({ data: [{ id: 99, username: 'leak-user', roles: [{ name: 'approver' }] }] })
    getUserGroupsMock.mockResolvedValue({ data: [] })
    getAssetGroupsMock.mockResolvedValue({ data: [{ id: 9, name: 'sit' }] })
    getAssetListMock.mockResolvedValue({ data: [{ id: 90, name: 'sit-1' }] })
    getSecurityPoliciesMock.mockResolvedValue({ data: [{ key: 'access_request_min_approvals', value: '5' }] })
  })

  it('列表帶 coverage 時只用列表與兩個選擇端點，可審人數與門檻取自列表回應', async () => {
    useFixture(LOCATOR_LIST, LOCATOR_NODES)
    const wrapper = mountView()
    await flushPromises()

    expectNoListEndpoints()
    expect(approverOptionsMock).toHaveBeenCalledTimes(1)
    expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'node' }))
    const tree = wrapper.vm.nodeTreeRows
    expect(tree.map((n) => n.name)).toEqual(['prod'])
    const db = tree[0].children[0]
    expect(db.name).toBe('db')
    expect(db.poolCount).toBe(3)
    expect(tree[0].poolCount).toBeNull()
    expect(wrapper.vm.quorumThreshold).toBe(2)
    expect(wrapper.text()).not.toContain('leak-user')
  })

  it('不在客體候選內的定位祖先列沒有新增與移除鈕', async () => {
    useFixture(LOCATOR_LIST, LOCATOR_NODES)
    const wrapper = mountView()
    await flushPromises()

    const prodCells = cell(wrapper, 'node-1')
    expect(prodCells.length).toBeGreaterThan(0)
    expect(prodCells.some((c) => c.find('.node-add').exists())).toBe(false)
    expect(prodCells.some((c) => c.find('.el-tag__close').exists())).toBe(false)
    expect(prodCells.some((c) => c.find(`.locator-ancestor[title="${zhTW.nodeTree.locatorAncestor}"]`).exists())).toBe(true)

    const dbCells = cell(wrapper, 'node-2')
    expect(dbCells.some((c) => c.find('.node-add').exists())).toBe(true)
    expect(dbCells.some((c) => c.find('.el-tag__close').exists())).toBe(true)
  })

  it('審核範圍管理在 prod、節點管理在 sit：只有 prod 子樹有操作，sit 不出現', async () => {
    useFixture(K_PROD_LIST, K_PROD_NODES)
    const wrapper = mountView()
    await flushPromises()

    expectNoListEndpoints()
    expect(wrapper.text()).not.toContain('sit')
    const withAdd = ['node-1', 'node-2', 'node-5'].filter((k) => cell(wrapper, k).some((c) => c.find('.node-add').exists()))
    expect(withAdd).toEqual(['node-1', 'node-2', 'node-5'])
    expect(wrapper.findAll('.node-add')).toHaveLength(3)
  })

  it('申請人型管理旗標為假：申請人側區塊與兩欄不存在、顯示說明；can() 兩鍵皆真也不改變', async () => {
    setCapabilitiesForTests(['approverscope:manage', 'approverscope:manage_applicant'])
    useFixture(LOCATOR_LIST, LOCATOR_NODES)
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.subject-routing').exists()).toBe(false)
    const titles = wrapper.findAll('.section-title').map((h) => h.text())
    expect(titles).not.toContain(zhTW.approverScopes.sectionSubjectRouting)
    expect(wrapper.text()).toContain(zhTW.approverScopes.applicantManagedGlobally)
    const columnLabels = wrapper.findAll('.col-stub').map((c) => c.attributes('data-label'))
    subjectLabels.forEach((label) => expect(columnLabels).not.toContain(label))
    // 範圍化檢視者：頁首與可審人數說明
    expect(wrapper.text()).toContain(zhTW.approverScopes.scopedNotice)
    expect(wrapper.text()).toContain(zhTW.approverScopes.poolScopedNote)
    // 新增對話框收到同一旗標
    wrapper.vm.openAdd()
    await flushPromises()
    expect(wrapper.findComponent(ApproverScopeForm).props('scoped')).toEqual({ applicantManageable: false })
  })

  it('申請人型管理旗標為真：申請人側區塊存在、沒有範圍化頁首', async () => {
    useFixture(GLOBAL_LIST, GLOBAL_NODES)
    const wrapper = mountView()
    await flushPromises()

    expectNoListEndpoints()
    expect(wrapper.find('.subject-routing').exists()).toBe(true)
    expect(wrapper.vm.subjectScopeRows.map((s) => s.id)).toEqual([25])
    expect(wrapper.text()).not.toContain(zhTW.approverScopes.applicantManagedGlobally)
    expect(wrapper.text()).not.toContain(zhTW.approverScopes.scopedNotice)
    expect(wrapper.text()).not.toContain(zhTW.approverScopes.poolScopedNote)
    const columnLabels = wrapper.findAll('.col-stub').map((c) => c.attributes('data-label'))
    subjectLabels.forEach((label) => expect(columnLabels).toContain(label))
  })

  it('按審核人員：列取自審核方目錄中具審核人員角色者', async () => {
    useFixture(LOCATOR_LIST, LOCATOR_NODES)
    const wrapper = mountView()
    await flushPromises()

    const users = wrapper.vm.actorRows.filter((r) => r.type === 'user')
    expect(users.map((r) => r.name)).toEqual(['appr', 'audit'])
    expect(users[0].fullName).toBe('審核甲')
    expect(users[0].byType.asset_group.map((s) => s.id)).toEqual([21])
    expect(users[0].byType.asset.map((s) => s.id)).toEqual([22])
  })
})

describe('新增審核範圍對話框：精簡路徑', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetCapabilities()
    useFixture(LOCATOR_LIST, LOCATOR_NODES)
    createApproverScopeMock.mockResolvedValue({ id: 99 })
    addUserRoleMock.mockResolvedValue({})
  })

  it('無指派角色能力：個人候選只含 is_approver 且 selectable 者、無代配標註，送出不呼叫角色指派', async () => {
    setCapabilitiesForTests(['approverscope:manage'])
    const wrapper = mountForm({ applicantManageable: false })
    await flushPromises()

    expect(getUserListMock).toHaveBeenCalledTimes(0)
    expect(getUserGroupsMock).toHaveBeenCalledTimes(0)
    expect(getAssetGroupsMock).toHaveBeenCalledTimes(0)
    expect(getAssetListMock).toHaveBeenCalledTimes(0)
    const actors = wrapper.vm.currentActorOptions
    expect(actors.map((o) => o.id)).toEqual([8])
    expect(actors.every((o) => !o.needsRole && o.label === 'appr')).toBe(true)
    expect(wrapper.text()).toContain(zhTW.approverScopeForm.approverRoleRequiredHint)

    wrapper.vm.form.actorId = 8
    wrapper.vm.form.targetId = 31
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(addUserRoleMock).toHaveBeenCalledTimes(0)
    expect(createApproverScopeMock).toHaveBeenCalledWith({ approver_id: 8, asset_id: 31 })
  })

  it('具指派角色能力：未具審核人員角色者帶代配標註，保留身分者不列', async () => {
    setCapabilitiesForTests(['approverscope:manage', 'user:manage', 'role:assign'])
    const wrapper = mountForm({ applicantManageable: false })
    await flushPromises()

    const actors = wrapper.vm.currentActorOptions
    expect(actors.map((o) => o.id)).toEqual([7, 8])
    const carol = actors.find((o) => o.id === 7)
    expect(carol.needsRole).toBe(true)
    expect(carol.label).toBe(zhTW.approverScopeForm.actorNeedsRoleLabel.replace('{username}', 'carol'))
    expect(actors.find((o) => o.id === 8).needsRole).toBe(false)
    expect(wrapper.text()).not.toContain(zhTW.approverScopeForm.approverRoleRequiredHint)
  })

  it('申請人型管理旗標為假：客體類型只有資產與節點；節點選項不含定位祖先', async () => {
    setCapabilitiesForTests(['approverscope:manage', 'approverscope:manage_applicant'])
    const wrapper = mountForm({ applicantManageable: false })
    await flushPromises()

    expect(Object.keys(wrapper.vm.visibleScopeTypes)).toEqual(['asset', 'asset_group'])
    subjectLabels.forEach((label) => expect(wrapper.text()).not.toContain(label))
    expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'asset' }))
    wrapper.vm.form.type = 'asset_group'
    await flushPromises()
    expect(wrapper.vm.currentOptions).toEqual([{ id: 2, label: 'prod / db' }])
  })

  it('申請人型管理旗標為真：四種客體類型都在，申請人選項取自審核方目錄', async () => {
    setCapabilitiesForTests(['approverscope:manage', 'approverscope:manage_applicant'])
    const wrapper = mountForm({ applicantManageable: true })
    await flushPromises()

    expect(Object.keys(wrapper.vm.visibleScopeTypes)).toEqual(['asset', 'asset_group', 'subject_user', 'subject_group'])
    wrapper.vm.form.type = 'subject_group'
    await flushPromises()
    expect(wrapper.vm.currentOptions).toEqual([{ id: 4, label: 'DBA' }])
  })
})
