import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import Assets from '@/views/Assets.vue'
import AccessControl from '@/views/AccessControl.vue'
import { createAsset, updateAsset } from '@/api/assets'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { ENTRY_RULES, entryRuleFor, canEnter } from '@/router/entryRules'
import { classifyOverrideChange } from '@/utils/accessPolicyTier'
import BulkAssetTable from '@/components/asset/bulk/BulkAssetTable.vue'
import { newRow, rowToPayload } from '@/utils/assetBulk'

// 單台連線政策覆寫的能力邊界（前端）：無權限點時唯讀且不送此鍵、降級先確認、
// 存取管控頁依能力掛覆寫表、入口規則與安全政策頁同一條。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const STUB_ROWS = Symbol('stubTableRows')
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
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub">
    <div v-for="(row, i) in rows" :key="i"><slot :row="row" :column="{}" :$index="i" /></div>
  </div>`,
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /></div>',
}
const treeSelectStub = {
  name: 'ElTreeSelect',
  props: ['modelValue', 'data'],
  template: '<div class="tree-select-stub" />',
}

const getAssetListMock = vi.fn()
const getOverridesMock = vi.fn()
const getAssetTagsMock = vi.fn()
const getPoliciesMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
  getAccessPolicyOverrides: (...args) => getOverridesMock(...args),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn(),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: (...args) => getAssetTagsMock(...args),
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
}))

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: vi.fn(),
  previewCompliance: vi.fn().mockResolvedValue({ data: { draft: true, verdicts: [] } }),
  previewApplyPolicies: vi.fn(),
}))

vi.mock('@/api/accessRequests', () => ({
  createAccessRequest: vi.fn(),
  breakGlassConnect: vi.fn(),
}))

// 編輯抽屜內的帳號列會查帳號、憑證與有效使用者；不 mock 時請求會真的送出，
// 測試結果就取決於執行環境有沒有可連的伺服器。
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
}))

vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))

const PERM = 'access_policy:manage'
const SSH_ROW = (accessPolicy) => ({
  id: 7,
  name: 'srv-a',
  protocol: 'ssh',
  host: '10.0.0.7',
  port: 22,
  username: 'root',
  active: true,
  access_policy: accessPolicy,
})

const mountAssets = () =>
  mount(Assets, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        ElTable: tableStub,
        ElTableColumn: tableColumnStub,
        'el-dialog': dialogStub,
        'el-tree-select': treeSelectStub,
        RouterLink: { template: '<a><slot /></a>' },
      },
    },
  })

const policiesWithDefault = (value) => ({
  data: [{ key: 'access_policy_default', type: 'enum', enum_order: ['open', 'reason', 'approval'], label: 'x', value }],
})

describe('資產表單的連線政策能力', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetCapabilities()
    localStorage.clear()
    getAssetListMock.mockResolvedValue({ data: [SSH_ROW('approval')], total: 1, page: 1, page_size: 20 })
    getAssetTagsMock.mockResolvedValue({ data: [] })
    getPoliciesMock.mockResolvedValue(policiesWithDefault('open'))
    updateAsset.mockResolvedValue({})
    createAsset.mockResolvedValue({ id: 99 })
  })

  it('無權限點：欄位 disabled 並顯示唯讀說明，新增與編輯本文都沒有 access_policy 鍵', async () => {
    // 新增時帶帳號名稱建立專用帳號需要建立憑證能力；缺它時對話框預設改挑共用憑證
    setCapabilitiesForTests(['asset:view', 'asset:create', 'asset:update', 'credential:create'])
    const wrapper = mountAssets()
    await flushPromises()

    wrapper.vm.handleEdit(SSH_ROW('approval'))
    await flushPromises()
    const select = wrapper.find('[data-test="access-policy-select"]')
    expect(select.exists()).toBe(true)
    expect(wrapper.findAllComponents({ name: 'ElSelect' }).some((s) => s.props('disabled') && s.attributes('data-test') === 'access-policy-select')).toBe(true)
    const hint = wrapper.find('[data-test="access-policy-readonly-hint"]')
    expect(hint.text()).toBe('這裡只能檢視；調整此政策需要存取政策管理權限，請由持有此權限的人處理')

    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    expect(Object.keys(updateAsset.mock.calls[0][1])).not.toContain('access_policy')

    wrapper.vm.handleCreate()
    await flushPromises()
    Object.assign(wrapper.vm.form, { name: 'new-a', protocol: 'ssh', host: '10.0.0.8', port: 22, username: 'root' })
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(createAsset).toHaveBeenCalledTimes(1)
    expect(Object.keys(createAsset.mock.calls[0][0])).not.toContain('access_policy')
  })

  it('有權限點：欄位可編輯，只改名稱時本文不帶 access_policy', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', PERM])
    const wrapper = mountAssets()
    await flushPromises()
    wrapper.vm.handleEdit(SSH_ROW('approval'))
    await flushPromises()
    expect(wrapper.find('[data-test="access-policy-readonly-hint"]').exists()).toBe(false)
    wrapper.vm.form.name = 'renamed-only'
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    const body = updateAsset.mock.calls[0][1]
    expect(body.name).toBe('renamed-only')
    expect(Object.keys(body)).not.toContain('access_policy')
  })

  it('有權限點：改了連線政策時本文帶新值', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', PERM])
    getAssetListMock.mockResolvedValue({ data: [SSH_ROW('reason')], total: 1, page: 1, page_size: 20 })
    const wrapper = mountAssets()
    await flushPromises()
    wrapper.vm.handleEdit(SSH_ROW('reason'))
    await flushPromises()
    wrapper.vm.form.access_policy = 'approval'
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    expect(updateAsset.mock.calls[0][1].access_policy).toBe('approval')
  })

  it('降級確認：approval 到 reason 跳確認，取消不送出且值回原值，確認後送出一次', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', PERM])
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    const wrapper = mountAssets()
    await flushPromises()
    wrapper.vm.handleEdit(SSH_ROW('approval'))
    await flushPromises()

    wrapper.vm.form.access_policy = 'reason'
    confirmSpy.mockRejectedValueOnce('cancel')
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(updateAsset).not.toHaveBeenCalled()
    expect(wrapper.vm.form.access_policy).toBe('approval')

    wrapper.vm.form.access_policy = 'reason'
    confirmSpy.mockResolvedValueOnce('confirm')
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    expect(updateAsset.mock.calls[0][1].access_policy).toBe('reason')
    confirmSpy.mockRestore()
  })

  it('收緊不跳確認', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', PERM])
    getAssetListMock.mockResolvedValue({ data: [SSH_ROW('reason')], total: 1, page: 1, page_size: 20 })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    const wrapper = mountAssets()
    await flushPromises()
    wrapper.vm.handleEdit(SSH_ROW('reason'))
    await flushPromises()
    wrapper.vm.form.access_policy = 'approval'
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(confirmSpy).not.toHaveBeenCalled()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    confirmSpy.mockRestore()
  })

  it('全域預設未知：清除覆寫一律跳確認並用 unknownDefault 文案', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', PERM])
    getPoliciesMock.mockRejectedValue(new Error('403'))
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountAssets()
    await flushPromises()
    wrapper.vm.handleEdit(SSH_ROW('reason'))
    await flushPromises()
    wrapper.vm.form.access_policy = ''
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    const message = confirmSpy.mock.calls[0][0]
    const text = typeof message === 'string' ? message : String(message.children)
    expect(text).toContain('無法讀取全域預設')
    expect(text).not.toContain('改為「')
    expect(updateAsset).toHaveBeenCalledTimes(1)
    confirmSpy.mockRestore()
  })
})

describe('classifyOverrideChange 段位序', () => {
  it('與後端同一套規則', () => {
    expect(classifyOverrideChange('approval', 'reason', 'open').downgrade).toBe(true)
    expect(classifyOverrideChange('reason', 'approval', 'open').downgrade).toBe(false)
    expect(classifyOverrideChange('reason', '', 'open').downgrade).toBe(true)
    expect(classifyOverrideChange('reason', '', 'approval').downgrade).toBe(false)
    expect(classifyOverrideChange('', 'open', 'open').downgrade).toBe(false)
    expect(classifyOverrideChange('reason', 'reason', 'open').downgrade).toBe(false)
    expect(classifyOverrideChange('reason', '', '').unknownDefault).toBe(true)
  })
})

// ── 存取管控頁：覆寫表閘（4.4）與入口規則（4.3）────────────────────────────

const ElSelectStub = {
  name: 'ElSelect',
  props: ['modelValue'],
  emits: ['change', 'update:modelValue'],
  template: '<div class="select-stub" :data-value="modelValue"><slot /></div>',
}
const ElOptionStub = {
  name: 'ElOption',
  props: ['label', 'value'],
  template: '<div class="option-stub">{{ label }}</div>',
}

const mountAccessControl = async () => {
  const wrapper = mount(AccessControl, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-select': ElSelectStub, 'el-option': ElOptionStub, RouterLink: { template: '<a><slot /></a>' } },
    },
  })
  await flushPromises()
  return wrapper
}

describe('存取管控頁覆寫表閘', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetCapabilities()
    getPoliciesMock.mockResolvedValue({
      data: [
        { key: 'access_policy_default', type: 'enum', enum_order: ['open', 'reason', 'approval'], label: '連線申請政策（全域預設）', value: 'open' },
      ],
      groups: [],
    })
    getOverridesMock.mockResolvedValue({
      data: [{ id: 1, name: '高敏SSH', protocol: 'ssh', access_policy: 'approval', node_ids: [], node_paths: [] }],
      total: 1,
      meta: { global_default: 'open', scoped: false },
    })
    updateAsset.mockResolvedValue({})
  })

  it('持設定組讀取能力、不持存取政策權限點：無覆寫表與搜尋選擇器，顯示說明句，資產請求 0 次，全域預設列照常', async () => {
    setCapabilitiesForTests(['securitypolicy:manage'])
    const wrapper = await mountAccessControl()
    expect(wrapper.findComponent({ name: 'AssetPolicyTable' }).exists()).toBe(false)
    expect(wrapper.find('[data-test="override-managed-elsewhere"]').text()).toBe('單台資產的連線政策由持有存取政策管理權限的人設定')
    expect(getOverridesMock).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('全域預設存取政策段位')
  })

  it('持兩者：覆寫表照常出現並載入資產', async () => {
    setCapabilitiesForTests(['securitypolicy:manage', PERM])
    const wrapper = await mountAccessControl()
    expect(wrapper.findComponent({ name: 'AssetPolicyTable' }).exists()).toBe(true)
    expect(wrapper.find('[data-test="override-managed-elsewhere"]').exists()).toBe(false)
    expect(getOverridesMock).toHaveBeenCalledTimes(1)
  })

  it('覆寫表降級：approval 到 reason 跳確認，取消不呼叫 updateAsset，確認後呼叫一次；reason 到 approval 不跳', async () => {
    setCapabilitiesForTests(['securitypolicy:manage', PERM])
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    const wrapper = await mountAccessControl()
    const table = wrapper.findComponent({ name: 'AssetPolicyTable' })
    const rowSelect = () =>
      table.findAllComponents({ name: 'ElSelect' }).find((s) => s.attributes('aria-label') === '高敏SSH 連線政策')

    confirmSpy.mockRejectedValueOnce('cancel')
    rowSelect().vm.$emit('change', 'reason')
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    expect(updateAsset).not.toHaveBeenCalled()
    expect(rowSelect().attributes('data-value')).toBe('approval')

    confirmSpy.mockResolvedValueOnce('confirm')
    rowSelect().vm.$emit('change', 'reason')
    await flushPromises()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    expect(updateAsset).toHaveBeenCalledWith(1, { access_policy: 'reason' })

    getOverridesMock.mockResolvedValue({ data: [{ id: 1, name: '高敏SSH', protocol: 'ssh', access_policy: 'reason', node_ids: [], node_paths: [] }], total: 1, meta: { global_default: 'open', scoped: false } })
    await table.vm.$.exposed?.loadAssets?.()
    confirmSpy.mockClear()
    updateAsset.mockClear()
    await table.vm.changePolicy({ id: 1, name: '高敏SSH', access_policy: 'reason' }, 'approval')
    await flushPromises()
    expect(confirmSpy).not.toHaveBeenCalled()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    confirmSpy.mockRestore()
  })
})

describe('/access-control 入口規則', () => {
  beforeEach(() => resetCapabilities())

  it('與 /security-policies 深相等', () => {
    expect(entryRuleFor('/access-control')).toStrictEqual(entryRuleFor('/security-policies'))
    expect(ENTRY_RULES['/access-control']).toStrictEqual({ permissionsAll: ['securitypolicy:manage'] })
  })

  it('只持設定組讀取能力：進得去；只持存取政策權限點或兩者皆無：進不去', () => {
    const rule = entryRuleFor('/access-control')
    setCapabilitiesForTests(['securitypolicy:manage'])
    expect(canEnter(rule)).toBe(true)
    setCapabilitiesForTests([PERM, 'asset:view'])
    expect(canEnter(rule)).toBe(false)
    setCapabilitiesForTests(['asset:view'])
    expect(canEnter(rule)).toBe(false)
  })

  it('超管持有全部目錄鍵：入口與現況相同', () => {
    setCapabilitiesForTests(['securitypolicy:manage', PERM])
    expect(canEnter(entryRuleFor('/access-control'))).toBe(true)
  })
})

describe('批次新增表的連線政策欄', () => {
  const mountBulk = () => {
    const row = newRow('ssh')
    row.name = 'b1'
    row.host = '10.0.0.9'
    row.access_policy = 'open'
    return mount(BulkAssetTable, {
      props: { rows: [row] },
      global: { plugins: [ElementPlus], stubs: { ElTable: tableStub, ElTableColumn: tableColumnStub, 'el-tree-select': treeSelectStub } },
    })
  }
  const policySelect = (wrapper) =>
    wrapper.find('[data-cell$="-access_policy"]').findComponent({ name: 'ElSelect' })

  beforeEach(() => resetCapabilities())

  it('無權限點：該欄停用、送出列沒有 access_policy 鍵', () => {
    setCapabilitiesForTests(['asset:create'])
    const wrapper = mountBulk()
    expect(policySelect(wrapper).props('disabled')).toBe(true)
    const { row } = rowToPayload(wrapper.props('rows')[0], { includeAccessPolicy: false })
    expect(Object.keys(row)).not.toContain('access_policy')
  })

  it('有權限點：該欄可編輯、送出列帶此鍵', () => {
    setCapabilitiesForTests(['asset:create', PERM])
    const wrapper = mountBulk()
    expect(policySelect(wrapper).props('disabled')).toBe(false)
    const { row } = rowToPayload(wrapper.props('rows')[0])
    expect(row.access_policy).toBe('open')
  })
})
