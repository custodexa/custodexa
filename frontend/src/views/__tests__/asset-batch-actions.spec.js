import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'
import {
  getAssetGroups,
  getAssetTags,
  batchMoveAssets,
  batchAddAssetTags,
  batchDeleteAssets,
} from '@/api/assets'
import { confirmDestructive } from '@/utils/confirm'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 資產批次動作：勾選欄與批次列、三個動作的對話框與請求本文、整批拒絕的呈現、
// 成功後的重載，以及範圍化檢視者的標籤候選提示與篩選。
// 可勾選與否、可選的目的節點一律餵伺服器標示的回應夾具，前端不自行計算範圍。

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

const STUB_ROWS = Symbol('batchRows')
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
  template: `<div class="col-stub"><th>{{ label }}<slot name="header" /></th>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
// 目的節點選擇器：攤平成按鈕，disabled 取自節點資料，才讀得到哪些節點可選
const treeSelectStub = {
  name: 'ElTreeSelect',
  props: ['data', 'modelValue'],
  emits: ['update:modelValue'],
  computed: {
    flat() {
      const out = []
      const walk = (list) =>
        list.forEach((n) => {
          out.push(n)
          walk(n.children || [])
        })
      walk(this.data || [])
      return out
    },
  },
  template: `<div class="tree-stub"><button v-for="n in flat" :key="n.id" type="button"
    class="tree-opt" :data-id="n.id" :disabled="n.disabled"
    @click="$emit('update:modelValue', n.id)">{{ n.name }}</button></div>`,
}
const stubs = {
  ElTable: tableStub,
  ElTableColumn: tableColumnStub,
  ElTreeSelect: treeSelectStub,
  // 下拉選單、對話框與抽屜在測試中直接內嵌渲染，才讀得到選單項與內容
  ElSelect: { template: '<div class="select-stub"><slot /><slot name="footer" /></div>' },
  ElOption: { template: '<span class="opt-stub"><slot /></span>' },
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
  getAssetTags: vi.fn(),
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
  batchMoveAssets: vi.fn(),
  batchAddAssetTags: vi.fn(),
  batchDeleteAssets: vi.fn(),
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
vi.mock('@/utils/confirm', () => ({
  DESTRUCTIVE_CONFIRM_CLASS: 'el-button--danger',
  confirmDestructive: vi.fn(),
}))

const allow = { allowed: true }
const deny = { allowed: false, reason: 'out_of_scope' }
const baseRow = (id, extra = {}) => ({
  id,
  name: `asset-${id}`,
  protocol: 'ssh',
  host: `h${id}`,
  port: 22,
  username: 'u',
  active: true,
  ...extra,
})
// 全域主體的回應：沒有 actions
const globalRows = [baseRow(1), baseRow(2), baseRow(3)]
// 範圍化檢視者的回應：旗標由伺服器給
const scopedRows = [
  baseRow(11, { actions: { edit: allow, delete: allow } }),
  baseRow(12, { actions: { edit: deny, delete: deny } }),
  baseRow(13, { actions: { edit: deny, delete: allow } }),
]

const listBody = (data, scope = null, total = data.length) => ({
  data,
  total,
  page: 1,
  page_size: 20,
  ...(scope ? { management_scope: scope } : {}),
})
const scope = { effective_node_count: 2, inactive_node_count: 0, nodes: [] }

const CAPS = ['asset:view', 'asset:update', 'asset:delete', 'asset:create']
const mountView = () =>
  mount(Assets, { global: { plugins: [ElementPlus], stubs } })

const nodes = (selectable) => ({
  data: [
    { id: 10, name: 'A', path: '根/A', parent_id: null, ...(selectable ? { selectable: selectable[10] } : {}) },
    { id: 20, name: 'B', path: '根/A/B', parent_id: 10, ...(selectable ? { selectable: selectable[20] } : {}) },
    { id: 30, name: 'C', path: '根/C', parent_id: null, ...(selectable ? { selectable: selectable[30] } : {}) },
  ],
  total: 3,
})

const batchError = (code, count) => ({ response: { status: 404, data: { code, params: { count } } } })

async function tickRows(wrapper, ids) {
  const boxes = wrapper.findAll('[data-test="row-select"] input')
  for (const i of ids) await boxes[i].setValue(true)
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  setCapabilitiesForTests([...CAPS, 'ui:assets-global'])
  getAssetListMock.mockResolvedValue(listBody(globalRows))
  getAssetGroups.mockResolvedValue(nodes(null))
  getAssetTags.mockResolvedValue({ data: [{ name: 'Etl', count: 1 }] })
  confirmDestructive.mockResolvedValue(undefined)
})

describe('勾選欄與批次列', () => {
  it('沒有資產編輯與刪除權限點時沒有勾選欄', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:create', 'ui:assets-global'])
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.findAll('[data-test="row-select"]')).toHaveLength(0)
    expect(wrapper.find('[data-test="select-page"]').exists()).toBe(false)
  })

  it('編輯與刪除旗標皆不可的列勾選框停用，其餘可勾', async () => {
    setCapabilitiesForTests(CAPS)
    getAssetListMock.mockResolvedValue(listBody(scopedRows, scope))
    const wrapper = mountView()
    await flushPromises()
    const boxes = wrapper.findAll('[data-test="row-select"] input')
    expect(boxes).toHaveLength(3)
    expect(boxes[0].attributes('disabled')).toBeUndefined()
    expect(boxes[1].attributes('disabled')).toBeDefined()
    expect(boxes[2].attributes('disabled')).toBeUndefined()
  })

  it('沒有 actions 的全域回應全部可勾', async () => {
    const wrapper = mountView()
    await flushPromises()
    const boxes = wrapper.findAll('[data-test="row-select"] input')
    expect(boxes).toHaveLength(3)
    boxes.forEach((b) => expect(b.attributes('disabled')).toBeUndefined())
  })

  it('勾兩列顯示已選 2 台與四個按鈕', async () => {
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="batch-bar"]').exists()).toBe(false)
    await tickRows(wrapper, [0, 1])
    expect(wrapper.find('[data-test="batch-count"]').text()).toBe('已選 2 台')
    for (const k of ['move', 'tags', 'delete', 'clear']) {
      expect(wrapper.find(`[data-test="batch-${k}"]`).exists()).toBe(true)
    }
  })

  it('表頭只選目前頁中可勾的列', async () => {
    setCapabilitiesForTests(CAPS)
    getAssetListMock.mockResolvedValue(listBody(scopedRows, scope, 40))
    const wrapper = mountView()
    await flushPromises()
    await wrapper.find('[data-test="select-page"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="batch-count"]').text()).toBe('已選 2 台')
  })

  it('換頁後選取清空', async () => {
    getAssetListMock.mockResolvedValue(listBody(globalRows, null, 60))
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0, 1])
    expect(wrapper.find('[data-test="batch-bar"]').exists()).toBe(true)
    wrapper.findComponent({ name: 'ElPagination' }).vm.$emit('current-change', 2)
    await flushPromises()
    expect(wrapper.find('[data-test="batch-bar"]').exists()).toBe(false)
  })

  it('取消選取清空勾選', async () => {
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0])
    await wrapper.find('[data-test="batch-clear"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="batch-bar"]').exists()).toBe(false)
  })
})

describe('搬移對話框', () => {
  it('請求帶 purpose=asset_update，只有 selectable=true 的節點可選，定位祖先停用', async () => {
    setCapabilitiesForTests(CAPS)
    getAssetListMock.mockResolvedValue(listBody(scopedRows, scope))
    getAssetGroups.mockResolvedValue({
      ...nodes({ 10: false, 20: true, 30: false }),
      selectable_all: false,
    })
    const wrapper = mountView()
    await flushPromises()
    getAssetGroups.mockClear()
    await tickRows(wrapper, [0])
    await wrapper.find('[data-test="batch-move"]').trigger('click')
    await flushPromises()

    expect(getAssetGroups).toHaveBeenCalledWith({ purpose: 'asset_update' })
    const opt = (id) => wrapper.find(`.tree-opt[data-id="${id}"]`)
    expect(opt(20).attributes('disabled')).toBeUndefined()
    expect(opt(10).attributes('disabled')).toBeDefined()
    expect(opt(30).attributes('disabled')).toBeDefined()
    // 範圍化檢視者看得到範圍外保留說明
    expect(wrapper.find('[data-test="move-keeps-out-of-scope"]').exists()).toBe(true)
  })

  it('不帶 selectable 的全域回應全部可選，且沒有範圍外保留說明', async () => {
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0, 1])
    await wrapper.find('[data-test="batch-move"]').trigger('click')
    await flushPromises()
    wrapper.findAll('.tree-opt').forEach((o) => expect(o.attributes('disabled')).toBeUndefined())
    expect(wrapper.findAll('.tree-opt')).toHaveLength(3)
    expect(wrapper.find('[data-test="move-keeps-out-of-scope"]').exists()).toBe(false)
  })

  it('selectable_all=true（每節點 true）全部可選', async () => {
    getAssetGroups.mockResolvedValue({ ...nodes({ 10: true, 20: true, 30: true }), selectable_all: true })
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0])
    await wrapper.find('[data-test="batch-move"]').trigger('click')
    await flushPromises()
    wrapper.findAll('.tree-opt').forEach((o) => expect(o.attributes('disabled')).toBeUndefined())
  })

  it('selectable_all=false 且沒有可選節點：顯示無可搬入並停用送出', async () => {
    getAssetGroups.mockResolvedValue({ ...nodes({ 10: false, 20: false, 30: false }), selectable_all: false })
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0])
    await wrapper.find('[data-test="batch-move"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="move-no-target"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="move-submit"]').attributes('disabled')).toBeDefined()
  })

  it('送出本文只含 asset_ids 與 target_node_id，成功後列表與標籤字典各重載一次', async () => {
    batchMoveAssets.mockResolvedValue({ data: { affected: 2, unchanged: 0 } })
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0, 1])
    await wrapper.find('[data-test="batch-move"]').trigger('click')
    await flushPromises()
    await wrapper.find('.tree-opt[data-id="30"]').trigger('click')
    getAssetListMock.mockClear()
    getAssetTags.mockClear()
    await wrapper.find('[data-test="move-submit"]').trigger('click')
    await flushPromises()

    expect(batchMoveAssets).toHaveBeenCalledTimes(1)
    const body = batchMoveAssets.mock.calls[0][0]
    expect(Object.keys(body).sort()).toEqual(['asset_ids', 'target_node_id'])
    expect(body.asset_ids).toEqual([1, 2])
    expect(body.target_node_id).toBe(30)
    // 節點樹重載時另以 page_size=1 取「全部／未分組」兩個計數，不算列表重載
    const listReloads = getAssetListMock.mock.calls.filter(([p]) => p?.page_size !== 1)
    expect(listReloads).toHaveLength(1)
    expect(getAssetTags).toHaveBeenCalledTimes(1)
  })
})

describe('加標籤與刪除', () => {
  it('加標籤本文只含 asset_ids 與 tags', async () => {
    batchAddAssetTags.mockResolvedValue({ data: { affected: 1, unchanged: 0 } })
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [2])
    await wrapper.find('[data-test="batch-tags"]').trigger('click')
    await flushPromises()
    // 標籤輸入以選擇器的雙向綁定寫入
    const select = wrapper.findComponent('[data-test="batch-tag-select"]')
    await select.vm.$emit('update:modelValue', ['Etl', 'new-tag'])
    await flushPromises()
    await wrapper.find('[data-test="tags-submit"]').trigger('click')
    await flushPromises()

    expect(batchAddAssetTags).toHaveBeenCalledTimes(1)
    const body = batchAddAssetTags.mock.calls[0][0]
    expect(Object.keys(body).sort()).toEqual(['asset_ids', 'tags'])
    expect(body.asset_ids).toEqual([3])
    expect(body.tags).toEqual(['Etl', 'new-tag'])
  })

  it('刪除先二次確認、確認文字含台數，本文只含 asset_ids', async () => {
    batchDeleteAssets.mockResolvedValue({ data: { affected: 2, unchanged: 0 } })
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0, 1])
    await wrapper.find('[data-test="batch-delete"]').trigger('click')
    await flushPromises()

    expect(confirmDestructive).toHaveBeenCalledTimes(1)
    expect(confirmDestructive.mock.calls[0][0]).toContain('2 台')
    expect(batchDeleteAssets).toHaveBeenCalledTimes(1)
    const body = batchDeleteAssets.mock.calls[0][0]
    expect(Object.keys(body)).toEqual(['asset_ids'])
    expect(body.asset_ids).toEqual([1, 2])
  })

  it('取消確認不送出', async () => {
    confirmDestructive.mockRejectedValue(new Error('cancel'))
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0])
    await wrapper.find('[data-test="batch-delete"]').trigger('click')
    await flushPromises()
    expect(batchDeleteAssets).not.toHaveBeenCalled()
  })
})

describe('整批拒絕的呈現', () => {
  it('無法操作：顯示整批沒有執行與台數，重新整理鈕重新請求列表', async () => {
    batchDeleteAssets.mockRejectedValue(batchError('NOTFOUND_BATCH_ITEMS_UNAVAILABLE', 2))
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0, 1])
    await wrapper.find('[data-test="batch-delete"]').trigger('click')
    await flushPromises()

    const panel = wrapper.find('[data-test="batch-error"]')
    expect(panel.exists()).toBe(true)
    expect(panel.text()).toContain('整批沒有執行')
    expect(wrapper.find('[data-test="batch-error-body"]').text()).toContain('2 台')
    expect(wrapper.find('[data-test="batch-error-body"]').text()).toContain('沒有改動')

    getAssetListMock.mockClear()
    await wrapper.find('[data-test="batch-error-refresh"]').trigger('click')
    await flushPromises()
    expect(getAssetListMock).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-test="batch-error"]').exists()).toBe(false)
  })

  it('範圍外節點阻擋：顯示受阻台數與移出你的節點的指引', async () => {
    batchDeleteAssets.mockRejectedValue(batchError('RULE_ASSET_BATCH_HAS_OUT_OF_SCOPE_NODES', 3))
    const wrapper = mountView()
    await flushPromises()
    await tickRows(wrapper, [0])
    await wrapper.find('[data-test="batch-delete"]').trigger('click')
    await flushPromises()

    const body = wrapper.find('[data-test="batch-error-body"]').text()
    expect(body).toContain('3 台')
    expect(body).toContain('移出你的節點')
  })
})

describe('標籤候選提示與篩選', () => {
  it('範圍化檢視者的加標籤候選有提示，全域主體沒有', async () => {
    setCapabilitiesForTests(CAPS)
    getAssetListMock.mockResolvedValue(listBody(scopedRows, scope))
    const scoped = mountView()
    await flushPromises()
    await tickRows(scoped, [0])
    await scoped.find('[data-test="batch-tags"]').trigger('click')
    await flushPromises()
    expect(scoped.find('[data-test="tag-visible-hint"]').text()).toContain('只列出你看得到的資產上用過的標籤')
    scoped.unmount()

    setCapabilitiesForTests([...CAPS, 'ui:assets-global'])
    getAssetListMock.mockResolvedValue(listBody(globalRows))
    const admin = mountView()
    await flushPromises()
    await tickRows(admin, [0])
    await admin.find('[data-test="batch-tags"]').trigger('click')
    await flushPromises()
    expect(admin.find('[data-test="tag-visible-hint"]').exists()).toBe(false)
  })

  it('標籤篩選：範圍化檢視者與全域主體呈現，一般使用者沒有；範圍化檢視者會取字典', async () => {
    setCapabilitiesForTests(CAPS)
    getAssetListMock.mockResolvedValue(listBody(scopedRows, scope))
    const scoped = mountView()
    await flushPromises()
    expect(scoped.find('[data-test="tag-filter"]').exists()).toBe(true)
    expect(getAssetTags).toHaveBeenCalled()
    scoped.unmount()

    setCapabilitiesForTests([...CAPS, 'ui:assets-global'])
    getAssetListMock.mockResolvedValue(listBody(globalRows))
    const admin = mountView()
    await flushPromises()
    expect(admin.find('[data-test="tag-filter"]').exists()).toBe(true)
    admin.unmount()

    setCapabilitiesForTests(['asset:view'])
    getAssetTags.mockClear()
    getAssetListMock.mockResolvedValue(listBody(globalRows))
    const user = mountView()
    await flushPromises()
    expect(user.find('[data-test="tag-filter"]').exists()).toBe(false)
    expect(getAssetTags).not.toHaveBeenCalled()
  })
})
