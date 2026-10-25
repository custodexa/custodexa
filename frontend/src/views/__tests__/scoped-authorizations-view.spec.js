/* eslint-disable vue/one-component-per-file, vue/require-prop-types -- 測試替身元件 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed, defineComponent, h, ref, onMounted } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Authorizations from '../Authorizations.vue'
import AuthzBatchWizard from '@/components/AuthzBatchWizard.vue'
import AuthzEffectiveView from '@/components/AuthzEffectiveView.vue'
import AssetNodeTree from '@/components/AssetNodeTree.vue'
import { getEffectiveUsers } from '@/api/authorizations'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 授權畫面的範圍化呈現：餵伺服器回應契約的夾具，驗證選項來源、列動作依 actions、
// 精靈各來源分開載入與批次錯誤筆數、有效權限檢視的範圍外節點計數、節點樹的「授權此節點」。
// 範圍判斷只看伺服器的 actions、selectable 與選擇器結果。

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

const STUB_ROWS = Symbol('authzRows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
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
  template: `<div class="col-stub">
    <div v-for="(row, i) in rows" :key="i" class="cell-stub" :data-row="i"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const pageStubs = {
  ElTable: tableStub,
  ElTableColumn: tableColumnStub,
  'el-dialog': dialogStub,
  ElDialog: dialogStub,
}

const getAuthorizationsMock = vi.fn()
const subjectOptionsMock = vi.fn()
const targetOptionsMock = vi.fn()
const batchCreateMock = vi.fn()
const getEffectiveAssetsMock = vi.fn()
const getUsersMock = vi.fn()
const getAssetListMock = vi.fn()
const getAssetGroupsMock = vi.fn()
const getAssetTagsMock = vi.fn()
const getUserGroupsMock = vi.fn()
const getAssetNodeTreeMock = vi.fn()

vi.mock('@/api/authorizations', () => ({
  getAuthorizations: (...a) => getAuthorizationsMock(...a),
  getSelfSubjects: vi.fn().mockResolvedValue({ applies: false }),
  getAuthorizationSubjectOptions: (...a) => subjectOptionsMock(...a),
  getAuthorizationTargetOptions: (...a) => targetOptionsMock(...a),
  batchCreateAuthorizations: (...a) => batchCreateMock(...a),
  deleteAuthorization: vi.fn(),
  updateAuthorizationAccounts: vi.fn(),
  getEffectiveAssets: (...a) => getEffectiveAssetsMock(...a),
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))
vi.mock('@/api/accessRequests', () => ({ revokeAccessRequest: vi.fn() }))
vi.mock('@/api/auth', () => ({ getUsers: (...a) => getUsersMock(...a) }))
vi.mock('@/api/userGroups', () => ({ getUserGroups: (...a) => getUserGroupsMock(...a) }))
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAssetGroups: (...a) => getAssetGroupsMock(...a),
  getAssetTags: (...a) => getAssetTagsMock(...a),
  getAssetNodeTree: (...a) => getAssetNodeTreeMock(...a),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  moveAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
}))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))

const userRows = [
  { id: 2, username: 'alice', display_name: 'Alice', kind: 'human', active: true, roles: ['user'] },
  { id: 3, username: 'bob', display_name: 'bob', kind: 'human', active: true, roles: [] },
]
const groupRows = [{ id: 5, name: 'ops', description: '', member_count: 2 }]
const assetRows = [{ id: 1, name: 'srv', protocol: 'ssh', host: 'h', nodes: [{ id: 10, path: 'A' }] }]
const nodeRows = [
  { id: 10, name: 'A', path: 'A', selectable: true },
  { id: 11, name: 'B', path: 'A / B', selectable: false },
]
const tagRows = [{ name: 'prod', count: 1 }]

const selectorImpl = (rejectKinds = []) => ({
  subject: ({ kind }) =>
    rejectKinds.includes(kind)
      ? Promise.reject(new Error('selector down'))
      : Promise.resolve(
          kind === 'user' ? { total: 2, data: userRows } : { total: 1, data: groupRows }
        ),
  target: ({ kind }) =>
    rejectKinds.includes(kind)
      ? Promise.reject(new Error('selector down'))
      : Promise.resolve(
          kind === 'asset'
            ? { total: 1, data: assetRows }
            : kind === 'node'
              ? { total: 2, data: nodeRows }
              : { total: 1, data: tagRows }
        ),
})
const useSelectors = (rejectKinds = []) => {
  const impl = selectorImpl(rejectKinds)
  subjectOptionsMock.mockImplementation(impl.subject)
  targetOptionsMock.mockImplementation(impl.target)
}

const manualRow = (over) => ({
  id: 1, user_id: 3, username: 'bob', asset_id: 1, asset_name: 'srv', permission: 'connect',
  source: 'manual', accounts: ['@ALL'], validity_state: 'active', ...over,
})
const rowCell = (wrapper, text) =>
  wrapper.findAll('.cell-stub').filter((c) => c.text().includes(text))
const buttonByText = (cell, text) => cell.findAll('button').find((b) => b.text().includes(text))

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  useSelectors()
  getAuthorizationsMock.mockResolvedValue({ data: [], total: 0 })
  getUsersMock.mockResolvedValue({ data: [] })
  getAssetListMock.mockResolvedValue({ data: [], total: 0 })
  getAssetGroupsMock.mockResolvedValue({ data: [] })
  getAssetTagsMock.mockResolvedValue({ data: [] })
  getUserGroupsMock.mockResolvedValue({ data: [] })
  getAssetNodeTreeMock.mockResolvedValue({ data: [] })
})

const mountPage = () =>
  mount(Authorizations, { global: { plugins: [ElementPlus], stubs: pageStubs } })

describe('授權頁：選項來源與批次入口', () => {
  it('只有授權規則管理能力：看得到批次按鈕，頁面只呼叫選擇器、不呼叫使用者與資產管理端點', async () => {
    setCapabilitiesForTests(['authorization:manage'])
    const wrapper = mountPage()
    await flushPromises()

    expect(wrapper.text()).toContain(zhTW.authorizations.batchAuthorize)
    expect(subjectOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'user' }))
    expect(subjectOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'user_group' }))
    expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'asset' }))
    expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'node' }))
    expect(getUsersMock).not.toHaveBeenCalled()
    expect(getUserGroupsMock).not.toHaveBeenCalled()
    expect(getAssetListMock).not.toHaveBeenCalled()
    expect(getAssetGroupsMock).not.toHaveBeenCalled()
    expect(wrapper.vm.userList.map((u) => u.id)).toEqual([2, 3])
    expect(wrapper.vm.nodeOptions.map((n) => n.id)).toEqual([10, 11])
  })

  it('沒有授權規則管理能力：沒有批次按鈕', async () => {
    setCapabilitiesForTests(['asset:view'])
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).not.toContain(zhTW.authorizations.batchAuthorize)
  })

  it('任一來源失敗：就地提示，其餘清單仍有值', async () => {
    setCapabilitiesForTests(['authorization:manage'])
    useSelectors(['asset'])
    const wrapper = mountPage()
    await flushPromises()
    expect(wrapper.text()).toContain(zhTW.authorizations.selectorLoadFailed)
    expect(wrapper.vm.userList).toHaveLength(2)
    expect(wrapper.vm.userGroupList).toHaveLength(1)
    expect(wrapper.vm.assetList).toHaveLength(0)
  })
})

describe('授權頁：列動作依伺服器的 actions', () => {
  const rows = () => ({
    data: [
      manualRow({
        id: 31, user_id: undefined, username: undefined, user_group_id: 5, user_group_name: 'self-group',
        actions: {
          update_accounts: { allowed: false, reason: 'self_subject' },
          delete: { allowed: true },
        },
      }),
      manualRow({
        id: 32, username: 'narrow-user',
        actions: {
          update_accounts: { allowed: true, limit: 'narrow_only' },
          delete: { allowed: true },
        },
      }),
      manualRow({
        id: 33, username: 'ticket-ok', source: 'ticket', request_id: 7, revocable: true,
        actions: {
          update_accounts: { allowed: false, reason: 'ticket_bound' },
          delete: { allowed: false, reason: 'ticket_bound' },
          revoke: { allowed: true },
        },
      }),
      manualRow({
        id: 34, username: 'ticket-noeligible', source: 'ticket', request_id: 8, revocable: true,
        actions: {
          update_accounts: { allowed: false, reason: 'ticket_bound' },
          delete: { allowed: false, reason: 'ticket_bound' },
          revoke: { allowed: false, reason: 'revoke_not_eligible' },
        },
      }),
    ],
    total: 4,
  })

  const tooltipOf = (cell) => cell.findComponent({ name: 'ElTooltip' })

  it('self_subject 列：帳號範圍鈕 disabled 並帶 accountScopeSelfLocked，刪除可按', async () => {
    getAuthorizationsMock.mockResolvedValue(rows())
    const wrapper = mountPage()
    await flushPromises()
    const cell = rowCell(wrapper, zhTW.authorizations.accountScopeAction).find((c) => c.text().includes(zhTW.common.delete))
    const scope = buttonByText(cell, zhTW.authorizations.accountScopeAction)
    const del = buttonByText(cell, zhTW.common.delete)
    expect(scope.attributes('disabled')).toBeDefined()
    expect(del.attributes('disabled')).toBeUndefined()
    const tip = tooltipOf(cell)
    expect(tip.props('content')).toBe(zhTW.authorizations.accountScopeSelfLocked)
    expect(tip.props('disabled')).toBe(false)
  })

  it('narrow_only 列：帳號範圍鈕可按，對話框顯示只能縮小的說明', async () => {
    getAuthorizationsMock.mockResolvedValue(rows())
    const wrapper = mountPage()
    await flushPromises()
    const cells = wrapper.findAll('.cell-stub').filter((c) => c.text().includes(zhTW.authorizations.accountScopeAction))
    const cell = cells[1]
    const scope = buttonByText(cell, zhTW.authorizations.accountScopeAction)
    expect(scope.attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).not.toContain(zhTW.authorizations.actionLimit.narrow_only)
    await scope.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain(zhTW.authorizations.actionLimit.narrow_only)
  })

  it('ticket_bound 列只有撤銷：沒有帳號範圍與刪除；不具撤銷資格者撤銷鈕停用並說明', async () => {
    getAuthorizationsMock.mockResolvedValue(rows())
    const wrapper = mountPage()
    await flushPromises()

    const ok = wrapper.findAll('.cell-stub').find((c) => c.text().includes(zhTW.authorizations.revoke) && c.find('button'))
    expect(buttonByText(ok, zhTW.authorizations.revoke).attributes('disabled')).toBeUndefined()
    expect(buttonByText(ok, zhTW.authorizations.accountScopeAction)).toBeUndefined()
    expect(buttonByText(ok, zhTW.common.delete)).toBeUndefined()

    const revokeCells = wrapper.findAll('.cell-stub').filter((c) => c.text().includes(zhTW.authorizations.revoke))
    const blocked = revokeCells[1]
    expect(buttonByText(blocked, zhTW.authorizations.revoke).attributes('disabled')).toBeDefined()
    expect(tooltipOf(blocked).props('content')).toBe(zhTW.authorizations.actionReason.revoke_not_eligible)
  })

  it('沒有 actions（超級管理者）：沿現行邏輯，manual 列帳號範圍與刪除可按', async () => {
    getAuthorizationsMock.mockResolvedValue({ data: [manualRow({ id: 41 })], total: 1 })
    const wrapper = mountPage()
    await flushPromises()
    const cell = rowCell(wrapper, zhTW.authorizations.accountScopeAction)[0]
    expect(buttonByText(cell, zhTW.authorizations.accountScopeAction).attributes('disabled')).toBeUndefined()
    expect(buttonByText(cell, zhTW.common.delete).attributes('disabled')).toBeUndefined()
  })

})

describe('批次精靈：選擇器來源、批次錯誤與預填', () => {
  const mountWizard = (props = {}) =>
    mount(AuthzBatchWizard, {
      props: { modelValue: true, ...props },
      global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub, ElDialog: dialogStub } },
    })

  it('開啟時呼叫兩個選擇器（含 kind=tag），不呼叫使用者與資產管理端點', async () => {
    const wrapper = mountWizard()
    await flushPromises()
    for (const kind of ['user', 'user_group']) {
      expect(subjectOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind }))
    }
    for (const kind of ['asset', 'node', 'tag']) {
      expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind }))
    }
    expect(getUsersMock).not.toHaveBeenCalled()
    expect(getUserGroupsMock).not.toHaveBeenCalled()
    expect(getAssetListMock).not.toHaveBeenCalled()
    expect(getAssetGroupsMock).not.toHaveBeenCalled()
    expect(getAssetTagsMock).not.toHaveBeenCalled()
    expect(wrapper.vm.tagOptions).toEqual(tagRows)
  })

  it('任一選項來源失敗：其餘清單仍有值並就地提示', async () => {
    useSelectors(['tag'])
    const wrapper = mountWizard()
    await flushPromises()
    expect(wrapper.vm.userList).toHaveLength(2)
    expect(wrapper.vm.userGroupList).toHaveLength(1)
    expect(wrapper.vm.assetList).toHaveLength(1)
    expect(wrapper.vm.tagOptions).toHaveLength(0)
    expect(wrapper.text()).toContain(zhTW.authorizations.selectorLoadFailed)
  })

  it('批次回 NOTFOUND_BATCH_ITEMS_UNAVAILABLE：精靈內顯示通用譯文且含筆數', async () => {
    batchCreateMock.mockRejectedValue({
      response: { status: 404, data: { code: 'NOTFOUND_BATCH_ITEMS_UNAVAILABLE', params: { count: 3 } } },
    })
    const wrapper = mountWizard()
    await flushPromises()
    wrapper.vm.selectedUsers = [{ id: 2, username: 'alice' }]
    wrapper.vm.selectedAssets = [{ id: 1, name: 'srv' }]
    await wrapper.vm.handleBatchSubmit()
    await flushPromises()
    expect(wrapper.text()).toContain(zhTW.apiError.NOTFOUND_BATCH_ITEMS_UNAVAILABLE.replace('{count}', '3'))
  })

  it('深連結預填：不可授權的節點不預勾並說明，可授權的節點照預勾', async () => {
    const blocked = mountWizard({ prefillNodeId: 11 })
    await flushPromises()
    await flushPromises()
    expect(blocked.vm.selectedGroups).toEqual([])
    expect(blocked.text()).toContain(zhTW.nodeTree.authorizeNodeUnavailable)
    blocked.unmount()

    const allowed = mountWizard({ prefillNodeId: 10 })
    await flushPromises()
    await flushPromises()
    expect(allowed.vm.selectedGroups.map((g) => g.id)).toEqual([10])
    expect(allowed.text()).not.toContain(zhTW.nodeTree.authorizeNodeUnavailable)
  })

  it('節點候選依路徑組樹，祖先定位節點停用（只認 selectable）', async () => {
    const wrapper = mountWizard()
    await flushPromises()
    const roots = wrapper.vm.nodeTreeOptions
    expect(roots).toHaveLength(1)
    expect(roots[0].id).toBe(10)
    expect(roots[0].disabled).toBe(false)
    expect(roots[0].children.map((c) => [c.id, c.disabled])).toEqual([[11, true]])
  })
})

describe('有效權限檢視：選擇器與範圍外節點計數', () => {
  it('選項來自選擇器；溯因帶 out_of_scope_node_count 時只顯示計數、不顯示節點名', async () => {
    getEffectiveAssetsMock.mockResolvedValue({
      user_id: 2,
      assets: [
        {
          asset_id: 1, asset_name: 'srv', protocol: 'ssh', out_of_scope_node_count: 1,
          paths: [{ kind: 'asset_node', permission: 'view' }],
        },
      ],
    })
    const wrapper = mount(AuthzEffectiveView, {
      props: { mode: 'subject' },
      global: { plugins: [ElementPlus], stubs: pageStubs },
    })
    await flushPromises()
    expect(subjectOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'user' }))
    expect(getUsersMock).not.toHaveBeenCalled()
    expect(wrapper.vm.userList.map((u) => u.id)).toEqual([2, 3])

    wrapper.vm.selectedId = 2
    await wrapper.vm.fetchData()
    await flushPromises()
    expect(wrapper.text()).toContain(zhTW.assets.scopedOutOfScopeNodes.replace('{n}', '1'))
    expect(wrapper.text()).not.toContain('secret-node')
  })

  it('客體視角：每位使用者列的 out_of_scope_node_count 顯示計數、不顯示節點名', async () => {
    getEffectiveUsers.mockResolvedValueOnce({
      asset_id: 1,
      users: [
        {
          user_id: 2, username: 'alice', permission: 'view', out_of_scope_node_count: 3,
          paths: [{ kind: 'asset_node', permission: 'view' }],
        },
        { user_id: 3, username: 'bob', permission: 'view', paths: [{ kind: 'direct_user', permission: 'view' }] },
      ],
    })
    const wrapper = mount(AuthzEffectiveView, {
      props: { mode: 'object' },
      global: { plugins: [ElementPlus], stubs: pageStubs },
    })
    await flushPromises()
    wrapper.vm.selectedId = 1
    await wrapper.vm.fetchData()
    await flushPromises()
    expect(wrapper.text()).toContain(zhTW.assets.scopedOutOfScopeNodes.replace('{n}', '3'))
    expect(wrapper.findAll('.out-of-scope-hint')).toHaveLength(1)
  })
})

describe('節點樹：授權此節點', () => {
  const ElTreeStub = defineComponent({
    props: ['load'],
    setup(props, { slots }) {
      const items = ref([])
      onMounted(() => props.load({ level: 0, data: null }, (d) => (items.value = d)))
      return () =>
        h('div', { class: 'tree-stub' },
          items.value.map((d) => h('div', { class: 'row', 'data-id': d.id }, slots.default?.({ data: d }))))
    },
  })
  const ElDropdownStub = defineComponent({
    setup(_, { slots }) {
      return () => h('div', { class: 'dd' }, [slots.default?.(), slots.dropdown?.()])
    },
  })
  const passthrough = defineComponent({ setup: (_, { slots }) => () => h('div', slots.default?.()) })
  const ElDropdownItemStub = defineComponent({
    props: ['command', 'disabled'],
    setup(props, { slots }) {
      return () =>
        h('div', { class: 'dd-item', 'data-command': props.command, 'data-disabled': String(!!props.disabled) },
          slots.default?.())
    },
  })
  const treeStubs = {
    ElTree: ElTreeStub,
    ElDropdown: ElDropdownStub,
    ElDropdownMenu: passthrough,
    ElDropdownItem: ElDropdownItemStub,
  }
  const mountTree = async (caps) => {
    setCapabilitiesForTests(caps)
    getAssetNodeTreeMock.mockResolvedValue({
      data: [
        { id: 10, name: 'A', has_children: false },
        { id: 11, name: 'B', has_children: false },
      ],
    })
    const wrapper = mount(AssetNodeTree, { global: { plugins: [ElementPlus], stubs: treeStubs } })
    await flushPromises()
    return wrapper
  }
  const authorizeItem = (wrapper, id) =>
    wrapper.find(`.row[data-id="${id}"] .dd-item[data-command="authorize"]`)

  it('持有授權規則管理能力：候選內可授權的節點啟用，祖先定位節點停用並顯示說明', async () => {
    const wrapper = await mountTree(['authorization:manage'])
    expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'node' }))
    expect(authorizeItem(wrapper, 10).attributes('data-disabled')).toBe('false')
    expect(authorizeItem(wrapper, 10).text()).not.toContain(zhTW.nodeTree.authorizeNodeUnavailable)
    expect(authorizeItem(wrapper, 11).attributes('data-disabled')).toBe('true')
    expect(authorizeItem(wrapper, 11).text()).toContain(zhTW.nodeTree.authorizeNodeUnavailable)
  })

  it('掛載時能力尚未載入、之後才載入：載入後取節點候選並啟用可授權節點', async () => {
    const wrapper = await mountTree([])
    expect(targetOptionsMock).not.toHaveBeenCalled()
    setCapabilitiesForTests(['authorization:manage'])
    await flushPromises()
    expect(targetOptionsMock).toHaveBeenCalledWith(expect.objectContaining({ kind: 'node' }))
    expect(authorizeItem(wrapper, 10).attributes('data-disabled')).toBe('false')
    expect(authorizeItem(wrapper, 11).attributes('data-disabled')).toBe('true')
  })

  it('不持授權規則管理能力：選單項不出現，也不呼叫節點候選', async () => {
    const wrapper = await mountTree(['assetgroup:manage'])
    expect(authorizeItem(wrapper, 10).exists()).toBe(false)
    expect(targetOptionsMock).not.toHaveBeenCalled()
  })
})

describe('三語鍵集', () => {
  const keys = (o, pre = '') =>
    Object.entries(o).flatMap(([k, v]) =>
      v && typeof v === 'object' ? keys(v, `${pre}${k}.`) : [`${pre}${k}`]
    )
  it('新增鍵在 zh-TW、en-US、ja-JP 皆存在且鍵集相同', () => {
    const wanted = [
      'authorizations.actionReason.ticket_bound',
      'authorizations.actionReason.not_revocable',
      'authorizations.actionReason.revoke_not_eligible',
      'authorizations.actionLimit.narrow_only',
      'authorizations.selectorLoadFailed',
      'authzWizard.colDisplayName',
      'nodeTree.authorizeNodeUnavailable',
    ]
    const sets = [zhTW, enUS, jaJP].map((l) => new Set(keys(l)))
    for (const w of wanted) for (const s of sets) expect(s.has(w)).toBe(true)
    expect([...sets[0]].sort()).toEqual([...sets[1]].sort())
    expect([...sets[0]].sort()).toEqual([...sets[2]].sort())
  })
})
