import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'
import previewWrite from '@/directives/previewWrite'
import { setPreviewOverlay, clearPreviewOverlay } from '@/utils/previewOverlay'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 資產頁的主機帳號盤點入口：可見與停用規則、深連結、預覽中停用。

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

const STUB_ROWS = Symbol('invRows')
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
  props: ['label', 'prop'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const v = this.stubRows
      if (!v) return []
      return Array.isArray(v) ? v : v.value || []
    },
  },
  template: `<div class="col-stub"><th>{{ label }}</th>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
const stubs = {
  ElTable: tableStub,
  ElTableColumn: tableColumnStub,
  ElDropdown: { name: 'ElDropdown', emits: ['command'], template: '<div><slot /><slot name="dropdown" /></div>' },
  ElDropdownMenu: { template: '<div><slot /></div>' },
  ElDropdownItem: {
    props: ['disabled', 'command'],
    template: '<button type="button" :disabled="disabled"><slot /></button>',
  },
  'el-dialog': { props: ['modelValue'], template: '<div v-if="modelValue"><slot /><slot name="footer" /></div>' },
  'el-drawer': {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="drawer-stub"><slot name="header" /><slot /></div>',
  },
  'el-popover': { template: '<span><slot name="reference" /><span><slot /></span></span>' },
  'el-tooltip': { template: '<span><slot /></span>' },
  'el-collapse': { template: '<div><slot /></div>', props: ['modelValue'] },
  'el-collapse-item': { template: '<div><slot /></div>', props: ['title', 'name'] },
}

const getAssetListMock = vi.fn()
const getAssetMock = vi.fn()
const getInvMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAsset: (...a) => getAssetMock(...a),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn().mockResolvedValue(null),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
}))
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn().mockResolvedValue({ data: [{ id: 1, username: 'testuser', is_default: true }] }),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))
vi.mock('@/api/credentials', () => ({
  listCredentials: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  rebindAccountCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
}))
vi.mock('@/api/authorizations', () => ({ getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }) }))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/accessRequests', () => ({ createAccessRequest: vi.fn(), breakGlassConnect: vi.fn() }))
vi.mock('@/api/hostInventory', () => ({
  getAssetInventory: (...a) => getInvMock(...a),
  startInventoryScan: vi.fn(),
  reopenInventoryFinding: vi.fn(),
  ignoreInventoryFinding: vi.fn(),
}))

const allow = { allowed: true }
const deny = { allowed: false, reason: 'out_of_scope' }
const sshRow = (o = {}) => ({
  id: 1, name: 'web-01', protocol: 'ssh', host: 'h1', port: 22, username: 'u', active: true,
  effective_rotation_channel: 'posix_ssh', ...o,
})
const flagged = (discover, o = {}) =>
  sshRow({
    node_ids: [10], node_paths: ['根/A'], out_of_scope_node_count: 0,
    actions: { edit: allow, disable: allow, delete: allow, test_connection: allow, manage_accounts: allow, discover_accounts: discover },
    ...o,
  })
const body = (data) => ({
  data, total: data.length, page: 1, page_size: 20,
  management_scope: { effective_node_count: 1, inactive_node_count: 0, nodes: [] },
})

async function mountAt(url, perms, rows) {
  setCapabilitiesForTests(perms)
  getAssetListMock.mockResolvedValue(body(rows))
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/assets', component: { template: '<i />' } }] })
  router.push(url)
  await router.isReady()
  const w = mount(Assets, {
    global: { plugins: [ElementPlus, router], stubs, directives: { 'preview-write': previewWrite } },
  })
  await flushPromises()
  return { w, router }
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  getAssetMock.mockResolvedValue(sshRow())
  getInvMock.mockResolvedValue({ scan: null, coverage: [], fixed_notes: [], findings: [], total: 0, page: 1, page_size: 50 })
})
afterEach(() => resetCapabilities())

const BASE_PERMS = ['asset:view', 'asset:update', 'asset:test', 'ui:self-service-actions']

describe('資產頁的主機帳號盤點入口', () => {
  it('RDP 沒有入口', async () => {
    const { w } = await mountAt('/assets', [...BASE_PERMS, 'account:discover'], [sshRow({ protocol: 'rdp' })])
    expect(w.find('[data-test="row-inventory"]').exists()).toBe(false)
  })

  it('SSH 且改密通道為 windows_ssh：入口停用並說明', async () => {
    const { w } = await mountAt(
      '/assets', [...BASE_PERMS, 'account:discover'],
      [sshRow({ effective_rotation_channel: 'windows_ssh' })]
    )
    expect(w.find('[data-test="row-inventory"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="inventory-reason"]').text()).toContain('Linux')
  })

  it('一般使用者（無盤點權限點、非全域視角、列無旗標）沒有入口', async () => {
    const { w } = await mountAt('/assets', ['asset:view', 'ui:self-service-actions'], [sshRow()])
    expect(w.find('[data-test="row-inventory"]').exists()).toBe(false)
  })

  it('稽核（ui:assets-global）有入口，「更多」選單因此出現', async () => {
    const { w } = await mountAt('/assets', ['asset:view', 'ui:assets-global'], [sshRow()])
    const item = w.find('[data-test="row-inventory"]')
    expect(item.exists()).toBe(true)
    expect(item.attributes('disabled')).toBeUndefined()
  })

  it('帶旗標的列：旗標允許才有入口，旗標不允許且無全域能力時沒有', async () => {
    const yes = await mountAt('/assets', ['asset:view'], [flagged(allow)])
    expect(yes.w.find('[data-test="row-inventory"]').exists()).toBe(true)
    const no = await mountAt('/assets', ['asset:view'], [flagged(deny)])
    expect(no.w.find('[data-test="row-inventory"]').exists()).toBe(false)
  })

  it('帶旗標但旗標不可做的列，在持全域資產視角時入口可開（發起鈕由抽屜依詳情旗標停用）', async () => {
    const { w } = await mountAt('/assets', ['asset:view', 'ui:assets-global'], [flagged(deny)])
    expect(w.find('[data-test="row-inventory"]').attributes('disabled')).toBeUndefined()
  })

  it('深連結的資產不在目前列表頁：仍開抽屜，且發起鈕依詳情旗標不出現', async () => {
    getAssetMock.mockResolvedValue(
      sshRow({ id: 99, name: 'other', actions: { discover_accounts: deny, manage_accounts: deny, edit: deny } })
    )
    const { w } = await mountAt('/assets?inventory=99', ['asset:view', 'ui:assets-global'], [sshRow()])
    expect(getAssetMock).toHaveBeenCalledWith(99, expect.anything())
    expect(w.find('[data-test="inv-subtitle"]').text()).toContain('other')
    // 詳情旗標不可做：不出現發起鈕，只留唯讀說明
    expect(w.find('[data-test="inv-start"]').exists()).toBe(false)
    expect(w.find('[data-test="inv-never-readonly"]').exists()).toBe(true)
  })

  it('深連結開抽屜後，網址上的 inventory 參數被清除', async () => {
    const { router } = await mountAt('/assets?inventory=1', ['asset:view', 'ui:assets-global'], [sshRow()])
    expect(router.currentRoute.value.query.inventory).toBeUndefined()
  })

  it('點入口開抽屜並以該列識別讀取', async () => {
    const { w } = await mountAt('/assets', [...BASE_PERMS, 'account:discover'], [sshRow()])
    w.findComponent({ name: 'ElDropdown' }).vm.$emit('command', 'inventory')
    await flushPromises()
    expect(getInvMock).toHaveBeenCalledWith(1, expect.anything())
  })

  it('預覽中：開始盤點鈕帶寫入預覽標記（停用並附說明）', async () => {
    setPreviewOverlay({ roleId: 1, roleName: '預覽角色', permissions: new Set(['asset:view', 'account:discover']), entryStates: [], range: null })
    try {
      const { w } = await mountAt('/assets?inventory=1', [...BASE_PERMS, 'account:discover'], [sshRow()])
      const btn = w.find('[data-test="inv-start"]')
      expect(btn.exists()).toBe(true)
      expect(btn.attributes('aria-description')).toBeTruthy()
    } finally {
      clearPreviewOverlay()
    }
  })
})
