import { computed } from 'vue'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import ManageScopeLine from '../ManageScopeLine.vue'
import Assets from '@/views/Assets.vue'
import Authorizations from '@/views/Authorizations.vue'
import CredentialLibrary from '@/views/CredentialLibrary.vue'
import { lineFromManagementScope, lineFromScopeSummary } from '@/composables/useManageScope'
import { resetCapabilities, setCapabilitiesForTests, applyCurrentUser } from '@/composables/useCapabilities'

// 頁首「你可管理」範圍行：每頁只取自己的伺服器投影，只作呈現。

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

const t = (k, p) => i18n.global.t(k, p)

const ROWS = Symbol('rows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [ROWS]: computed(() => this.data || []) }
  },
  template: '<div class="table-stub"><slot /></div>',
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop', 'type'],
  inject: { stubRows: { from: ROWS, default: null } },
  computed: {
    rows() {
      const v = this.stubRows
      return v ? (Array.isArray(v) ? v : v.value || []) : []
    },
  },
  template: '<div class="col-stub"><div v-for="(row, i) in rows" :key="i" class="cell-stub"><slot :row="row" :column="{}" :$index="i" /></div></div>',
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const stubs = {
  ElTable: tableStub,
  ElTableColumn: tableColumnStub,
  'el-dialog': dialogStub,
  ElDialog: dialogStub,
  'el-drawer': dialogStub,
  AssetPolicyTable: true,
}
const mountOpts = { global: { plugins: [ElementPlus, i18n], stubs } }

const listAssetsMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => listAssetsMock(...a),
  getAsset: vi.fn(),
  createAsset: vi.fn().mockResolvedValue({}),
  updateAsset: vi.fn().mockResolvedValue({}),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn().mockResolvedValue(null),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  moveAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
}))
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))
vi.mock('@/api/credentials', () => ({
  listCredentials: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getCredential: vi.fn(),
  rebindAccountCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
}))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/accessRequests', () => ({ createAccessRequest: vi.fn(), breakGlassConnect: vi.fn(), revokeAccessRequest: vi.fn() }))
vi.mock('@/api/authorizations', () => ({
  getAuthorizations: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getSelfSubjects: vi.fn().mockResolvedValue({ applies: false }),
  getAuthorizationSubjectOptions: vi.fn().mockResolvedValue({ total: 0, data: [] }),
  getAuthorizationTargetOptions: vi.fn().mockResolvedValue({ total: 0, data: [] }),
  batchCreateAuthorizations: vi.fn(),
  deleteAuthorization: vi.fn(),
  updateAuthorizationAccounts: vi.fn(),
  getEffectiveAssets: vi.fn(),
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))
vi.mock('@/api/auth', () => ({ getUsers: vi.fn().mockResolvedValue({ data: [] }), getCurrentUser: vi.fn() }))
vi.mock('@/api/userGroups', () => ({ getUserGroups: vi.fn().mockResolvedValue({ data: [] }) }))

const nodeEntry = (permission, ...paths) => ({
  permission,
  binding_scope: 'nodes',
  nodes: paths.map((p, i) => ({ id: i + 1, path: p })),
})
const globalEntry = (permission) => ({ permission, binding_scope: 'global' })
const grant = (perms, scope) => setCapabilitiesForTests(perms, { scope })

const emptyList = (ms) => ({ data: [], total: 0, page: 1, page_size: 20, ...(ms ? { management_scope: ms } : {}) })

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  listAssetsMock.mockResolvedValue(emptyList())
})

describe('ManageScopeLine 元件', () => {
  const mountLine = (props) => mount(ManageScopeLine, { props, global: { plugins: [i18n] } })

  it('路徑以「›」連接、多個節點以頓號分隔', () => {
    const w = mountLine({ nodes: [['台北機房', '核心資料庫'], ['高雄機房']] })
    const text = w.get('[data-test="manage-scope-line"]').text()
    expect(text).toContain(t('manageScope.label'))
    expect(text).toContain('台北機房 › 核心資料庫、高雄機房')
  })

  it('字串路徑（以「 / 」串接）也以「›」呈現', () => {
    const w = mountLine({ nodes: ['台北機房 / 核心資料庫'] })
    expect(w.text()).toContain('台北機房 › 核心資料庫')
  })

  it('五個節點時先顯示三個與「另 2 個」，展開後五個', async () => {
    const w = mountLine({ nodes: [['n1'], ['n2'], ['n3'], ['n4'], ['n5']] })
    expect(w.findAll('[data-test="manage-scope-node"]')).toHaveLength(3)
    const more = w.get('[data-test="manage-scope-more"]')
    expect(more.text()).toBe(t('manageScope.more', { n: 2 }))
    await more.trigger('click')
    expect(w.findAll('[data-test="manage-scope-node"]')).toHaveLength(5)
    expect(w.find('[data-test="manage-scope-more"]').exists()).toBe(false)
  })

  it('三個以內不顯示展開入口；尚未指派時只顯示說明', () => {
    expect(mountLine({ nodes: [['a'], ['b'], ['c']] }).find('[data-test="manage-scope-more"]').exists()).toBe(false)
    const w = mountLine({ nodes: [], notAssigned: true })
    expect(w.get('[data-test="manage-scope-empty"]').text()).toBe(t('manageScope.notAssigned'))
  })
})

describe('範圍行的來源解析', () => {
  it('scope_summary：只有節點條目才有結果，任一全域條目、缺條目、空節點都不顯示', () => {
    expect(lineFromScopeSummary([nodeEntry('x:y', ['A'])], 'x:y').nodes).toEqual([['A']])
    expect(lineFromScopeSummary([globalEntry('x:y')], 'x:y')).toBeNull()
    expect(lineFromScopeSummary([nodeEntry('x:y', ['A']), globalEntry('x:y')], 'x:y')).toBeNull()
    expect(lineFromScopeSummary([nodeEntry('x:z', ['A'])], 'x:y')).toBeNull()
    expect(lineFromScopeSummary([{ permission: 'x:y', binding_scope: 'nodes', nodes: [] }], 'x:y')).toBeNull()
    expect(lineFromScopeSummary(undefined, 'x:y')).toBeNull()
  })

  it('management_scope：有效節點為 0 是尚未指派；沒有物件不顯示', () => {
    expect(lineFromManagementScope({ effective_node_count: 0, inactive_node_count: 1, nodes: [] })).toEqual({ nodes: [], notAssigned: true })
    expect(lineFromManagementScope({ effective_node_count: 1, nodes: [{ id: 1, path: 'A / B' }] }).nodes).toEqual(['A / B'])
    expect(lineFromManagementScope(null)).toBeNull()
    expect(lineFromManagementScope(undefined)).toBeNull()
  })
})

describe('資產管理頁', () => {
  const mountAssets = async () => {
    const w = mount(Assets, mountOpts)
    await flushPromises()
    return w
  }

  it('資產檢視為全域、列表的管理範圍帶節點 A 時列出 A，既有說明仍在', async () => {
    grant(['asset:view'], [globalEntry('asset:view')])
    listAssetsMock.mockResolvedValue(emptyList({ effective_node_count: 1, inactive_node_count: 0, nodes: [{ id: 10, path: '根 / A' }] }))
    const w = await mountAssets()
    const line = w.get('[data-test="manage-scope-line"]').text()
    expect(line).toContain(t('manageScope.label'))
    expect(line).toContain('根 › A')
    expect(w.get('.page-header').text()).toContain(t('assets.headerDescUser'))
  })

  it('有效節點為 0 時顯示尚未指派', async () => {
    grant(['asset:view'], [])
    listAssetsMock.mockResolvedValue(emptyList({ effective_node_count: 0, inactive_node_count: 2, nodes: [] }))
    const w = await mountAssets()
    expect(w.get('[data-test="manage-scope-empty"]').text()).toBe(t('manageScope.notAssigned'))
  })

  it('回應只含有效節點：已刪除節點名不出現，也不呼叫節點樹以外的範圍計算', async () => {
    grant(['asset:view'], [])
    listAssetsMock.mockResolvedValue(emptyList({ effective_node_count: 1, inactive_node_count: 1, nodes: [{ id: 1, path: '存活節點' }] }))
    const w = await mountAssets()
    expect(w.get('[data-test="manage-scope-line"]').text()).toContain('存活節點')
    expect(w.text()).not.toContain('已刪除節點')
  })

  it('列表回應沒有管理範圍（全系統或超管）：不渲染此行與頁首附加區', async () => {
    grant(['asset:view'], [globalEntry('asset:view')])
    const w = await mountAssets()
    expect(w.find('[data-test="manage-scope-line"]').exists()).toBe(false)
    expect(w.find('.page-meta').exists()).toBe(false)
  })
})

describe('帳號憑證庫頁', () => {
  const mountCredentials = async () => {
    const w = mount(CredentialLibrary, mountOpts)
    await flushPromises()
    return w
  }

  it('憑證檢視為節點範圍時列出路徑；五個節點時摺疊', async () => {
    grant(['credential:view'], [nodeEntry('credential:view', ['A'], ['B'], ['C'], ['D'], ['E'])])
    const w = await mountCredentials()
    expect(w.findAll('[data-test="manage-scope-node"]')).toHaveLength(3)
    expect(w.get('[data-test="manage-scope-more"]').text()).toBe(t('manageScope.more', { n: 2 }))
    await w.get('[data-test="manage-scope-more"]').trigger('click')
    expect(w.findAll('[data-test="manage-scope-node"]')).toHaveLength(5)
  })

  it('全域、無該權限點的使用者不渲染此行', async () => {
    grant(['credential:view'], [globalEntry('credential:view')])
    let w = await mountCredentials()
    expect(w.find('[data-test="manage-scope-line"]').exists()).toBe(false)
    expect(w.find('.page-meta').exists()).toBe(false)
    w.unmount()
    grant(['asset:view'], [nodeEntry('asset:view', ['A'])])
    w = await mountCredentials()
    expect(w.find('[data-test="manage-scope-line"]').exists()).toBe(false)
  })
})

describe('資產授權管理頁', () => {
  const mountAuthz = async () => {
    const w = mount(Authorizations, mountOpts)
    await flushPromises()
    return w
  }
  const lineText = (w) => (w.find('[data-test="manage-scope-line"]').exists() ? w.get('[data-test="manage-scope-line"]').text() : null)

  it('授權規則與連線政策分頁各依自己的權限點', async () => {
    grant(['authorization:manage', 'access_policy:manage'], [nodeEntry('authorization:manage', ['節點A']), nodeEntry('access_policy:manage', ['節點B'])])
    const w = await mountAuthz()
    expect(lineText(w)).toContain('節點A')
    expect(lineText(w)).not.toContain('節點B')
    w.vm.activeTab = 'policy'
    await flushPromises()
    expect(lineText(w)).toContain('節點B')
    expect(lineText(w)).not.toContain('節點A')
    w.vm.activeTab = 'subject'
    await flushPromises()
    expect(lineText(w)).toContain('節點A')
  })

  it('授權規則為全域、連線政策為節點 B：授權規則分頁不渲染，連線政策分頁列 B', async () => {
    grant(['authorization:manage', 'access_policy:manage'], [globalEntry('authorization:manage'), nodeEntry('access_policy:manage', ['節點B'])])
    const w = await mountAuthz()
    expect(lineText(w)).toBeNull()
    expect(w.find('.page-meta').exists()).toBe(false)
    w.vm.activeTab = 'policy'
    await flushPromises()
    expect(lineText(w)).toContain('節點B')
  })

  it('不持任何管理權限點者不渲染', async () => {
    grant(['asset:view'], [globalEntry('asset:view')])
    const w = await mountAuthz()
    expect(lineText(w)).toBeNull()
  })
})

describe('隨共用能力狀態更新與清除', () => {
  it('整批替換後範圍行只剩其餘節點，登出後清除', async () => {
    grant(['credential:view'], [nodeEntry('credential:view', ['A'], ['B'])])
    const w = mount(CredentialLibrary, mountOpts)
    await flushPromises()
    expect(w.text()).toContain('B')
    applyCurrentUser({ id: 1, permissions: ['credential:view'], scope_summary: [nodeEntry('credential:view', ['A'])] })
    await flushPromises()
    expect(w.findAll('[data-test="manage-scope-node"]')).toHaveLength(1)
    resetCapabilities()
    await flushPromises()
    expect(w.find('[data-test="manage-scope-line"]').exists()).toBe(false)
  })
})
