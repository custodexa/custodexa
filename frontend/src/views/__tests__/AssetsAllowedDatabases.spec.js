import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import Assets from '../Assets.vue'
import { createAsset, updateAsset } from '@/api/assets'

// 自 Assets.spec.js 拆出（同 AssetsConnectEntry.spec.js 的理由）：該檔掛載成本高，
// 再疊一組表單案例會讓整檔逼近逾時臨界。本檔獨立承載
// 「允許的資料庫」欄位的顯示條件、回填、送出與協議切換確認
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
const getAssetTagsMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn(),
  resetAssetHostKey: vi.fn(),
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
  getSecurityPolicies: vi.fn().mockResolvedValue({ data: [], deviation_count: 0 }),
}))

vi.mock('@/api/accessRequests', () => ({
  createAccessRequest: vi.fn(),
  breakGlassConnect: vi.fn(),
}))

const MYSQL_ROW = {
  id: 30,
  name: 'mysql-a',
  protocol: 'mysql',
  host: 'mysql-test',
  port: 3306,
  username: 'app',
  active: true,
  db_name: 'app',
  allowed_databases: ['app', 'report'],
}

const mountView = () =>
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

const openEdit = async (wrapper, row) => {
  wrapper.vm.handleEdit(row)
  await flushPromises()
}

describe('Assets 允許的資料庫欄位', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
    getAssetListMock.mockResolvedValue({ data: [MYSQL_ROW], total: 1, page: 1, page_size: 20 })
    getAssetTagsMock.mockResolvedValue({ data: [] })
  })

  it('只對三種 SQL 方言顯示；redis 與 ssh 不顯示', async () => {
    const wrapper = mountView()
    await flushPromises()
    await openEdit(wrapper, MYSQL_ROW)

    expect(wrapper.find('[data-test="allowed-databases"]').exists()).toBe(true)

    // redis 是資料庫協議但非 SQL 方言，主控台不收，欄位一併不出現
    wrapper.vm.form.protocol = 'redis'
    await flushPromises()
    expect(wrapper.find('[data-test="allowed-databases"]').exists()).toBe(false)

    wrapper.vm.form.protocol = 'ssh'
    await flushPromises()
    expect(wrapper.find('[data-test="allowed-databases"]').exists()).toBe(false)
  })

  it('編輯既有資產時原樣回填，且不與原列共用參考', async () => {
    const wrapper = mountView()
    await flushPromises()
    await openEdit(wrapper, MYSQL_ROW)

    expect(wrapper.vm.form.allowed_databases).toEqual(['app', 'report'])
    wrapper.vm.form.allowed_databases.push('staging')
    expect(MYSQL_ROW.allowed_databases).toEqual(['app', 'report'])
  })

  it('helper 的大小寫提示隨協議切換（三方言各自一句）', async () => {
    const wrapper = mountView()
    await flushPromises()
    await openEdit(wrapper, MYSQL_ROW)

    const tips = () => wrapper.findAll('.form-tip').map((n) => n.text())
    expect(tips().some((x) => x.includes('命令列連線不受此欄影響'))).toBe(true)
    expect(tips().some((x) => x.includes('MySQL'))).toBe(true)

    wrapper.vm.form.protocol = 'postgres'
    await flushPromises()
    expect(tips().some((x) => x.includes('PostgreSQL'))).toBe(true)
    expect(tips().some((x) => x.includes('MySQL'))).toBe(false)

    wrapper.vm.form.protocol = 'mssql'
    await flushPromises()
    expect(tips().some((x) => x.includes('SQL Server'))).toBe(true)
  })

  it('送出為字串陣列；非 SQL 方言連空陣列都不送', async () => {
    updateAsset.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()
    await openEdit(wrapper, MYSQL_ROW)

    wrapper.vm.form.allowed_databases = ['app', 'report', 'staging']
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(updateAsset).toHaveBeenCalled()
    const payload = updateAsset.mock.calls.at(-1)[1]
    expect(payload.allowed_databases).toEqual(['app', 'report', 'staging'])

    createAsset.mockResolvedValue({ id: 40 })
    wrapper.vm.handleCreate()
    await flushPromises()
    Object.assign(wrapper.vm.form, {
      name: 'ssh-new',
      protocol: 'ssh',
      host: 'h',
      port: 22,
      username: 'u',
    })
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(createAsset.mock.calls.at(-1)[0].allowed_databases).toBeUndefined()
  })

  it('清單非空時改協議：儲存前先揭露清空，取消則不送出', async () => {
    updateAsset.mockResolvedValue({})
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    const wrapper = mountView()
    await flushPromises()
    await openEdit(wrapper, MYSQL_ROW)

    wrapper.vm.form.protocol = 'ssh'
    await flushPromises()

    confirmSpy.mockRejectedValue('cancel')
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalledTimes(1)
    // 揭露必須帶得出項數，否則管理者不知道自己要失去什麼
    expect(confirmSpy.mock.calls[0][0]).toContain('2')
    expect(confirmSpy.mock.calls[0][2].autofocus).toBe(false)
    expect(updateAsset).not.toHaveBeenCalled()

    confirmSpy.mockResolvedValue('confirm')
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    // 清空由伺服端執行；表單不送這個欄位
    expect(updateAsset.mock.calls[0][1].allowed_databases).toBeUndefined()
    confirmSpy.mockRestore()
  })

  it('清單為空時改協議不打擾', async () => {
    updateAsset.mockResolvedValue({})
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm')
    const wrapper = mountView()
    await flushPromises()
    await openEdit(wrapper, { ...MYSQL_ROW, allowed_databases: [] })

    wrapper.vm.form.protocol = 'ssh'
    await flushPromises()
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(confirmSpy).not.toHaveBeenCalled()
    expect(updateAsset).toHaveBeenCalledTimes(1)
    confirmSpy.mockRestore()
  })
})
