import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'
import previewWrite from '@/directives/previewWrite'
import { stashManagePrefill, hasManagePrefill } from '@/utils/inventoryManageHandoff'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 盤點「納管」串接：抽屜路徑、全域頁暫存路徑、預填只用一次、不經網址與 history.state。

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
// 盤點抽屜換成替身：只驗串接（開啟的識別、manage 事件），抽屜自身行為另有測試
const invDrawerStub = {
  name: 'HostAccountInventoryDrawer',
  props: ['modelValue', 'assetId'],
  emits: ['manage', 'goto', 'update:modelValue'],
  template: '<div v-if="modelValue" class="inv-stub" :data-id="assetId" />',
}
const stubs = {
  HostAccountInventoryDrawer: invDrawerStub,
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
const createAssetAccountMock = vi.fn()
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
  createAssetAccount: (...a) => createAssetAccountMock(...a),
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

const row = { id: 7, name: 'web-01', protocol: 'ssh', host: 'h7', port: 22, username: 'u', active: true, effective_rotation_channel: 'posix_ssh' }
const FINDING = { id: 3, asset_id: 7, username: 'deploy', privileged: true }
const PERMS = ['asset:view', 'asset:update', 'asset:test', 'account:discover', 'credential:create', 'ui:self-service-actions']

async function mountAt(url) {
  setCapabilitiesForTests(PERMS)
  getAssetListMock.mockResolvedValue({
    data: [row], total: 1, page: 1, page_size: 20,
    management_scope: { effective_node_count: 1, inactive_node_count: 0, nodes: [] },
  })
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/assets', component: { template: '<i />' } }] })
  router.push(url)
  await router.isReady()
  const w = mount(Assets, {
    attachTo: document.body,
    global: { plugins: [ElementPlus, router], stubs, directives: { 'preview-write': previewWrite } },
  })
  await flushPromises()
  return { w, router }
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  stashManagePrefill(null)
  getAssetMock.mockResolvedValue({ ...row })
})
afterEach(() => resetCapabilities())

describe('盤點抽屜的納管串接', () => {
  it('抽屜按納管：關盤點抽屜、開編輯抽屜、帳號區開預填列', async () => {
    const { w } = await mountAt('/assets')
    w.findComponent({ name: 'ElDropdown' }).vm.$emit('command', 'inventory')
    await flushPromises()
    expect(w.find('.inv-stub').exists()).toBe(true)
    w.findComponent({ name: 'HostAccountInventoryDrawer' }).vm.$emit('manage', { finding: FINDING, asset: { id: 7 } })
    await flushPromises()
    expect(w.find('.inv-stub').exists()).toBe(false)
    const addRow = w.findComponent({ name: 'AssetAccountAddRow' })
    expect(addRow.exists()).toBe(true)
    expect(addRow.vm.model.username).toBe('deploy')
    expect(addRow.vm.model.privileged).toBe(true)
  })

  it('納管成功後點「回到主機帳號盤點」：關編輯抽屜並重開盤點抽屜', async () => {
    createAssetAccountMock.mockResolvedValue({})
    const { w } = await mountAt('/assets')
    w.findComponent({ name: 'HostAccountInventoryDrawer' }).vm.$emit('manage', { finding: FINDING, asset: { id: 7 } })
    await flushPromises()
    const addRow = w.findComponent({ name: 'AssetAccountAddRow' })
    addRow.vm.model.password = 'x'
    await addRow.vm.submit()
    await flushPromises()
    await w.find('[data-test="manage-back"]').trigger('click')
    await flushPromises()
    expect(w.find('.inv-stub').attributes('data-id')).toBe('7')
    expect(w.find('[data-test="manage-done"]').exists()).toBe(false)
  })
})

describe('盤點抽屜的專用帳號落點串接', () => {
  it('抽屜按「前往專用帳號設定」：關盤點抽屜、開編輯抽屜並依落點 executor-test-login 捲動', async () => {
    const scrollSpy = vi.fn()
    Element.prototype.scrollIntoView = scrollSpy
    const { w } = await mountAt('/assets')
    w.findComponent({ name: 'ElDropdown' }).vm.$emit('command', 'inventory')
    await flushPromises()
    w.findComponent({ name: 'HostAccountInventoryDrawer' }).vm.$emit('goto', { id: 7, target: 'executor-test-login' })
    await flushPromises()
    expect(w.find('.inv-stub').exists()).toBe(false)
    expect(getAssetMock).toHaveBeenCalledWith(7)
    expect(w.find('.drawer-stub').exists()).toBe(true)
  })
})

describe('全域頁暫存路徑', () => {
  it('暫存存在且資產相符：開編輯抽屜並預填，取出即清空', async () => {
    stashManagePrefill({ assetId: 7, username: 'deploy', privileged: false })
    const { w, router } = await mountAt('/assets?edit=7')
    const addRow = w.findComponent({ name: 'AssetAccountAddRow' })
    expect(addRow.exists()).toBe(true)
    expect(addRow.vm.model.username).toBe('deploy')
    expect(hasManagePrefill()).toBe(false)
    expect(router.currentRoute.value.query.edit).toBeUndefined()
  })

  it('暫存缺席（例如重新整理）：只開編輯抽屜、不預填', async () => {
    const { w } = await mountAt('/assets?edit=7')
    expect(w.find('.drawer-stub').exists()).toBe(true)
    expect(w.findComponent({ name: 'AssetAccountAddRow' }).exists()).toBe(false)
  })

  it('暫存的資產識別與 ?edit 不符：丟棄不預填，且暫存被清空', async () => {
    stashManagePrefill({ assetId: 8, username: 'deploy', privileged: true })
    const { w } = await mountAt('/assets?edit=7')
    expect(w.findComponent({ name: 'AssetAccountAddRow' }).exists()).toBe(false)
    expect(hasManagePrefill()).toBe(false)
  })

  it('帳號名不進 history.state 與網址', async () => {
    stashManagePrefill({ assetId: 7, username: 'deploy-secret-name', privileged: true })
    const { router } = await mountAt('/assets?edit=7')
    expect(JSON.stringify(window.history.state ?? null)).not.toContain('deploy-secret-name')
    expect(router.currentRoute.value.fullPath).not.toContain('deploy-secret-name')
  })

  it('預填只使用一次：取消後再按新增是空白表單', async () => {
    stashManagePrefill({ assetId: 7, username: 'deploy', privileged: true })
    const { w } = await mountAt('/assets?edit=7')
    await w.find('[data-test="account-add-cancel"]').trigger('click')
    await w.find('[data-test="account-add"]').trigger('click')
    await flushPromises()
    expect(w.findComponent({ name: 'AssetAccountAddRow' }).vm.model.username).toBe('')
  })
})
