import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'
import { getAssetGroups, updateAsset, createAsset } from '@/api/assets'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 範圍化資產頁：餵契約的回應夾具，驗證節點欄計數、列動作依 actions、
// 三種管理範圍狀態、編輯與新增抽屜的可選候選與送出內容。

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

const STUB_ROWS = Symbol('scopedRows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: `<div class="table-stub"><slot />
    <div v-if="!(data || []).length" class="table-empty-stub"><slot name="empty" /></div></div>`,
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
// 下拉選單與抽屜在測試中直接內嵌渲染，才讀得到選單項與抽屜內容
const dropdownStubs = {
  ElDropdown: { template: '<div><slot /><slot name="dropdown" /></div>' },
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
}

const getAssetListMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAsset: vi.fn(),
  createAsset: vi.fn().mockResolvedValue({}),
  updateAsset: vi.fn().mockResolvedValue({}),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn().mockResolvedValue(null),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn(),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
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
  rebindAccountCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
}))
vi.mock('@/api/authorizations', () => ({ getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }) }))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/accessRequests', () => ({ createAccessRequest: vi.fn(), breakGlassConnect: vi.fn() }))

const allow = { allowed: true }
// 只經管理可視的列：無 permission／access_state，節點 A 在範圍內、另有 2 個範圍外歸屬
const managedRow = {
  id: 1,
  name: 'managed-only',
  protocol: 'ssh',
  host: 'h1',
  port: 22,
  username: 'u',
  active: true,
  node_ids: [10],
  node_paths: ['根/A'],
  out_of_scope_node_count: 2,
  actions: {
    edit: allow,
    disable: { allowed: false, reason: 'out_of_scope_nodes', count: 2 },
    delete: { allowed: false, reason: 'out_of_scope_nodes', count: 2 },
    test_connection: allow,
    manage_accounts: allow,
  },
}
// 只經連線可視的列：有 permission，管理旗標全為範圍外
const connectRow = {
  id: 2,
  name: 'connect-only',
  protocol: 'ssh',
  host: 'h2',
  port: 22,
  username: 'u',
  active: true,
  permission: 'connect',
  access_state: 'connectable',
  actions: {
    edit: { allowed: false, reason: 'out_of_scope' },
    disable: { allowed: false, reason: 'out_of_scope' },
    delete: { allowed: false, reason: 'out_of_scope' },
    test_connection: { allowed: false, reason: 'out_of_scope' },
    manage_accounts: { allowed: false, reason: 'out_of_scope' },
  },
}

const listBody = (data, scope, total = data.length) => ({
  data,
  total,
  page: 1,
  page_size: 20,
  management_scope: scope,
})
const scope = (eff, inactive = 0) => ({ effective_node_count: eff, inactive_node_count: inactive, nodes: [] })

// 同時持全域刪除能力：驗證帶 actions 的列不回退全域判斷
const grant = () =>
  setCapabilitiesForTests(['asset:view', 'asset:update', 'asset:delete', 'asset:test', 'asset:create', 'ui:self-service-actions'])

const mountView = () =>
  mount(Assets, {
    global: {
      plugins: [ElementPlus],
      stubs: { ElTable: tableStub, ElTableColumn: tableColumnStub, ...dropdownStubs },
    },
  })

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  grant()
  getAssetGroups.mockResolvedValue({ data: [], total: 0 })
})

describe('範圍化資產列表', () => {
  it('節點欄含範圍外計數、未授權列沒有連線入口', async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow, connectRow], scope(1)))
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('[data-test="out-of-scope-badge"]').text()).toContain('＋2 範圍外')
    expect(wrapper.find('[data-test="scoped-node-paths"]').text()).toContain('根/A')
    expect(wrapper.findAll('[data-test="no-connect-entry"]')).toHaveLength(1)
    expect(wrapper.text()).toContain('未授權')
  })

  it('刪除項依 actions 停用並說明可改為移出自己的節點；同時持全域刪除能力也一樣', async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow], scope(1)))
    const wrapper = mountView()
    await flushPromises()

    const del = wrapper.find('[data-test="row-delete"]')
    expect(del.attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="delete-reason"]').text()).toContain('移出你的節點')
    // 測試連線旗標為允許
    expect(wrapper.find('[data-test="row-test"]').attributes('disabled')).toBeUndefined()
  })

  it('只經連線可視的列：編輯鈕依旗標停用', async () => {
    getAssetListMock.mockResolvedValue(listBody([connectRow], scope(1)))
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="row-edit"]').attributes('disabled')).toBeDefined()
  })
})

describe('管理範圍三種狀態', () => {
  it('無有效節點且無資產：空態', async () => {
    getAssetListMock.mockResolvedValue(listBody([], scope(0), 0))
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="scoped-empty"]').exists()).toBe(true)
  })

  it('無有效節點但仍有連線授權資產：列表照常、顯示提示、不渲染空態', async () => {
    getAssetListMock.mockResolvedValue(listBody([connectRow, { ...connectRow, id: 3, name: 'c2' }], scope(0), 2))
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="scoped-connection-only"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="scoped-empty"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('connect-only')
    expect(wrapper.text()).toContain('c2')
  })

  it('部分節點失效：顯示個數提示，表格照常', async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow], scope(1, 1)))
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="scoped-inactive"]').text()).toContain('1')
    expect(wrapper.text()).toContain('managed-only')
    expect(wrapper.find('[data-test="scoped-empty"]').exists()).toBe(false)
  })
})

const purposeNodes = (all) => ({
  data: [
    { id: 10, name: 'A', path: '根/A', parent_id: null, selectable: true },
    { id: 30, name: 'C', path: '根/C', parent_id: null, selectable: true },
    { id: 40, name: 'D', path: '根/D', parent_id: null, selectable: false },
  ],
  total: 3,
  selectable_all: all,
})

describe('範圍化編輯與新增抽屜', () => {
  it('開編輯抽屜發 purpose=asset_update，顯示範圍外說明；沒動節點欄時本文不帶 node_ids 與 access_policy', async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow], scope(1)))
    getAssetGroups.mockResolvedValue(purposeNodes(false))
    const wrapper = mountView()
    await flushPromises()

    await wrapper.find('[data-test="row-edit"]').trigger('click')
    await flushPromises()

    expect(getAssetGroups).toHaveBeenCalledWith({ purpose: 'asset_update' })
    const hint = wrapper.find('[data-test="out-of-scope-nodes-hint"]')
    expect(hint.text()).toContain('另有 2 個範圍外節點')
    expect(hint.text()).toContain('只能由該範圍的管理者調整')

    await wrapper.find('[data-test="drawer-save"]').trigger('click')
    await flushPromises()

    expect(updateAsset).toHaveBeenCalledTimes(1)
    const body = updateAsset.mock.calls[0][1]
    expect(body).not.toHaveProperty('node_ids')
    expect(body).not.toHaveProperty('access_policy')
  })

  it('停用旗標不允許時，狀態開關唯讀並說明', async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow], scope(1)))
    getAssetGroups.mockResolvedValue(purposeNodes(false))
    const wrapper = mountView()
    await flushPromises()
    await wrapper.find('[data-test="row-edit"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="active-denied-hint"]').text()).toContain('移出你的節點')
  })

  it('新增抽屜發 purpose=asset_create；selectable_all=false 時節點欄必填，不送出', async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow], scope(1)))
    getAssetGroups.mockResolvedValue(purposeNodes(false))
    const wrapper = mountView()
    await flushPromises()

    const createBtn = wrapper.findAll('button').find((b) => b.text().includes('新增資產'))
    await createBtn.trigger('click')
    await flushPromises()

    expect(getAssetGroups).toHaveBeenCalledWith({ purpose: 'asset_create' })
    const confirm = wrapper.findAll('button').find((b) => b.text() === '確定' || b.text() === '確認')
    await confirm.trigger('click')
    await flushPromises()
    expect(createAsset).not.toHaveBeenCalled()
    // 擋下送出的是節點欄本身（不只是名稱等其他必填欄）：節點欄的表單項顯示節點必填的錯誤文字
    // 錯誤字的顯示經元件庫去抖動，等它出現
    await vi.waitFor(() =>
      expect(wrapper.findAll('.el-form-item__error').map((el) => el.text())).toContain('資產至少須掛在一個節點')
    )
  })
})

describe('新增資產的專用帳號可用條件', () => {
  const dedicatedRadio = (wrapper) => wrapper.find('[data-test="credential-mode"] input[value="dedicated"]')
  const openCreate = async () => {
    getAssetListMock.mockResolvedValue(listBody([managedRow], scope(1)))
    getAssetGroups.mockResolvedValue(purposeNodes(true))
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.handleCreate()
    await flushPromises()
    return wrapper
  }

  it('只持 credential:create（不持 credential:manage）：「這台專用」可選，送出本文帶 username', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:create', 'credential:create'])
    const wrapper = await openCreate()

    expect(dedicatedRadio(wrapper).element.disabled).toBe(false)
    expect(wrapper.find('[data-test="credential-dedicated-disabled-note"]').exists()).toBe(false)
    expect(wrapper.vm.form.credential_mode).toBe('dedicated')

    Object.assign(wrapper.vm.form, { name: 'web-05', host: '10.0.0.5', port: 22, username: 'app', password: 'pw-1' })
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(createAsset).toHaveBeenCalledTimes(1)
    expect(createAsset.mock.calls[0][0].username).toBe('app')
  })

  it('兩鍵皆無：「這台專用」停用並寫出原因，預設為共用', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:create'])
    const wrapper = await openCreate()

    expect(dedicatedRadio(wrapper).element.disabled).toBe(true)
    expect(wrapper.find('[data-test="credential-dedicated-disabled-note"]').text()).toContain('新增憑證')
    expect(wrapper.vm.form.credential_mode).toBe('shared')
  })
})
