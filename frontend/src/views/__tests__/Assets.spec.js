import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import Assets from '../Assets.vue'
import { getAssetGroups, createAsset, testAssetConnection } from '@/api/assets'

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（與 MyConnections.spec.js 同法）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

// el-table 真渲染在 happy-dom 下極慢（欄寬計算／observer／sticky 機械），本檔每測
// 掛整頁曾達 3s 貼近 5s 上限，並行時隨機超時＝全量 flaky 唯一根因。
// 故以 stub 取代，但**保留欄位模板執行**：表頭出 <th>、每列跑 #default slot 並帶
// row scope，欄內渲染斷言（chips 收納、狀態 badge、風險標記、描述次行）驗證力不變。
// 注意：不採 KeyManagement.spec.js 的「整列 JSON」stub——本檔有「標籤只顯示前 2 個」
// 這類斷言，若把整列資料倒成文字，被收納的標籤反而會出現在 wrapper.text() 而假綠。
// 本檔每測掛整頁且從不卸載，殘留元件在 document 上累積，單測耗時隨進度單調上升
// （實測首測 0.3s、末測 12s）。逐測卸載使成本不隨測試序遞增。
enableAutoUnmount(afterEach)

// 全量高負載下偶發單測 5s 逾時（單跑穩綠）——負載型 flake 治標，非本檔測試不穩
// （慣例同 SessionDetail/AuditLogs/Alerts.spec.js）
vi.setConfig({ testTimeout: 20_000 })

const STUB_ROWS = Symbol('stubTableRows')

const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: `<div class="table-stub">
    <slot />
    <div v-if="!(data || []).length" class="table-empty-stub"><slot name="empty" /></div>
  </div>`,
}

const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop', 'className'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    // Options API 的 inject 會淺解 ref，故此處同時容忍「已解出的陣列」與「computed ref」
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub" :class="className">
    <th>{{ label }}</th>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub">
      <slot :row="row" :column="{}" :$index="i">{{ prop ? row[prop] : '' }}</slot>
    </div>
  </div>`,
}

const tableStubs = { ElTable: tableStub, ElTableColumn: tableColumnStub }

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
  getAssetTags: (...args) => getAssetTagsMock(...args),
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
}))

// 分組對話框開啟時查全域預設段位（唯讀回顯帶「目前：X」文案）
const getSecurityPoliciesMock = vi.fn()
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getSecurityPoliciesMock(...args),
}))

const breakGlassConnectMock = vi.fn()
vi.mock('@/api/accessRequests', () => ({
  createAccessRequest: vi.fn(),
  breakGlassConnect: (...args) => breakGlassConnectMock(...args),
}))

const sampleAssets = {
  data: [
    {
      id: 1,
      name: 'ssh-server',
      protocol: 'ssh',
      host: 'ssh-test',
      port: 2222,
      username: 'testuser',
      active: true,
      permission: 'connect',
    },
    {
      id: 2,
      name: 'view-only-server',
      protocol: 'rdp',
      host: 'rdp-test',
      port: 3389,
      username: 'rdpuser',
      active: true,
      permission: 'view',
    },
  ],
  total: 2,
  page: 1,
  page_size: 20,
}

const setUserRoles = (roles) => {
  localStorage.setItem('user', JSON.stringify({ id: 7, username: 'tester', roles }))
}

const mountView = (extraStubs = {}) =>
  mount(Assets, {
    global: {
      plugins: [ElementPlus],
      stubs: { ...tableStubs, ...extraStubs },
    },
  })

describe('Assets 授權狀態欄按角色顯示（asset-access-scoping）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAssetListMock.mockResolvedValue(sampleAssets)
  })

  it('一般 user 顯示授權狀態欄，等級來自列表回應 permission 欄位', async () => {
    setUserRoles(['user'])
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('授權狀態')
    // connect → 「連線」、view → 「檢視」（等級文字映射）
    expect(text).toContain('連線')
    expect(text).toContain('檢視')
    expect(text).not.toContain('未授權')
  })

  it('permission 欄位缺失時顯示「未授權」（防伺服端欄位缺漏靜默）', async () => {
    setUserRoles(['user'])
    getAssetListMock.mockResolvedValue({
      data: [{ id: 3, name: 'no-perm-server', protocol: 'ssh', host: 'h', port: 22, active: true }],
      total: 1,
      page: 1,
      page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('未授權')
  })

  it.each([['admin'], ['auditor']])('%s 不顯示授權狀態欄', async (role) => {
    setUserRoles([role])
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).not.toContain('授權狀態')
  })

  it('過濾表單不含 authorized_only（授權過濾由伺服端強制）', async () => {
    setUserRoles(['user'])
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).not.toContain('僅已授權')
    const [params] = getAssetListMock.mock.calls[0]
    expect(params).not.toHaveProperty('authorized_only')
  })
})

describe('Assets 破窗緊急連線入口（break-glass-revocation）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  const approvalAsset = (extra = {}) => ({
    data: [{
      id: 5, name: 'db-prod', protocol: 'ssh', host: 'h', port: 22,
      active: true, permission: 'connect', access_state: 'approval_required', ...extra,
    }],
    total: 1, page: 1, page_size: 20,
  })

  it('伺服端標註 break_glass_available 時，申請對話框內出現緊急連線次入口', async () => {
    setUserRoles(['user'])
    getAssetListMock.mockResolvedValue(approvalAsset({ break_glass_available: true }))
    const wrapper = mountView()
    await flushPromises()

    // 開申請對話框
    wrapper.vm.openApplyDialog(wrapper.vm.assetList[0])
    await flushPromises()
    expect(wrapper.text()).toContain('緊急連線（無法等待審核時）')
  })

  it('未標註 break_glass_available 時不出現緊急入口（藏入口）', async () => {
    setUserRoles(['user'])
    getAssetListMock.mockResolvedValue(approvalAsset({ break_glass_available: false }))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openApplyDialog(wrapper.vm.assetList[0])
    await flushPromises()
    expect(wrapper.text()).not.toContain('緊急連線（無法等待審核時）')
  })

  it('送出緊急連線帶 asset_id 與事由（不帶時長）', async () => {
    setUserRoles(['user'])
    getAssetListMock.mockResolvedValue(approvalAsset({ break_glass_available: true }))
    breakGlassConnectMock.mockResolvedValue({ id: 20, status: 'approved' })
    const openSpy = vi.fn()
    vi.stubGlobal('open', openSpy)

    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openBreakGlassDialog(wrapper.vm.assetList[0])
    wrapper.vm.breakGlassReason = '線上服務中斷需立即處理'
    await flushPromises()
    await wrapper.vm.submitBreakGlass()

    expect(breakGlassConnectMock).toHaveBeenCalledWith({
      asset_id: 5,
      reason: '線上服務中斷需立即處理',
    })
    expect(openSpy).toHaveBeenCalledWith('/workspace?asset=5', '_blank')
  })
})

describe('Assets 節點樹與資產表單（asset-node-tree）', () => {
  // el-dialog teleport 到 body，happy-dom 下 wrapper.text() 撈不到——
  // inline stub 讓對話框內容留在元件樹內供斷言
  const dialogStub = {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="dialog-stub"><slot /></div>',
  }
  // el-tree-select（teleported popper）happy-dom 下炸 render——stub 為占位
  const treeSelectStub = {
    name: 'ElTreeSelect',
    props: ['modelValue', 'data'],
    template: '<div class="tree-select-stub" />',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue(sampleAssets)
    getAssetGroups.mockResolvedValue({
      data: [
        { id: 15, name: '高敏審核組', parent_id: null, path: '高敏審核組', assets: [{ id: 1 }] },
        { id: 18, name: '一般組', parent_id: null, path: '一般組', assets: [] },
      ],
      total: 2,
    })
    getSecurityPoliciesMock.mockResolvedValue({
      data: [{ key: 'access_policy_default', type: 'enum', value: 'open' }],
      deviation_count: 0,
    })
  })

  it('左樹取代分組對話框：頁面掛節點樹、無管理分組入口', async () => {
    const wrapper = mountView({
      'el-dialog': dialogStub,
      'el-tree-select': treeSelectStub,
      RouterLink: { template: '<a class="router-link-stub"><slot /></a>' },
    })
    await flushPromises()

    // 樹組件在（虛擬項「全部資產/未分組」由樹渲染）
    expect(wrapper.findComponent({ name: 'AssetNodeTree' }).exists()).toBe(true)
    expect(wrapper.text()).toContain('全部資產')
    // 舊分組管理對話框已移除（節點 CRUD 收斂於左樹）
    expect(wrapper.text()).not.toContain('管理分組')
    expect(wrapper.text()).not.toContain('資產分組管理')
  }, 15000)

  it('資產表單含掛載節點多選與連線政策，繼承選項帶目前全域值文案', async () => {
    const wrapper = mountView({
      'el-dialog': dialogStub,
      'el-tree-select': treeSelectStub,
      'el-select': {
        name: 'ElSelect',
        props: ['modelValue'],
        template: '<div class="select-stub"><slot /></div>',
      },
      'el-option': {
        name: 'ElOption',
        props: ['label', 'value'],
        template: '<div class="option-stub">{{ label }}</div>',
      },
      RouterLink: { template: '<a><slot /></a>' },
    })
    await flushPromises()

    // 開啟新增資產表單（dialogVisible watch 觸發全域政策載入）
    wrapper.vm.handleCreate()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('掛載節點')
    expect(text).toContain('連線政策')
    expect(text).toContain('跟隨全域設定（目前：不需申請）')
    expect(text).toContain('需審核人核准')
    // 表單掛載節點走 el-tree-select 多選（asset-node-tree D5）
    expect(wrapper.findComponent({ name: 'ElTreeSelect' }).exists()).toBe(true)
  }, 15000)

  it('點選節點過濾右表（含子樹預設開）與未分組過濾', async () => {
    const wrapper = mountView({
      'el-dialog': dialogStub,
      'el-tree-select': treeSelectStub,
      RouterLink: { template: '<a><slot /></a>' },
    })
    await flushPromises()
    getAssetListMock.mockClear()

    // 點節點：帶 node_id、含子樹預設開（不送 include_subtree=false）
    wrapper.vm.handleNodeSelect({ id: 15, name: '高敏審核組', path: '高敏審核組' })
    await flushPromises()
    let params = getAssetListMock.mock.calls.at(-1)[0]
    expect(params.node_id).toBe(15)
    expect(params.include_subtree).toBeUndefined()
    expect(wrapper.text()).toContain('含子樹')

    // 顯式關含子樹
    wrapper.vm.includeSubtree = false
    await flushPromises()
    params = getAssetListMock.mock.calls.at(-1)[0]
    expect(params.include_subtree).toBe(false)

    // 未分組虛擬節
    wrapper.vm.handleNodeSelect('ungrouped')
    await flushPromises()
    params = getAssetListMock.mock.calls.at(-1)[0]
    expect(params.ungrouped).toBe(true)
    expect(params.node_id).toBeUndefined()
  }, 15000)

  it('建立資產未選任何節點時，成功訊息提示已置於未分組', async () => {
    createAsset.mockResolvedValue({ id: 9 })
    const successSpy = vi.spyOn(ElMessage, 'success').mockImplementation(() => {})

    const wrapper = mountView({
      'el-dialog': dialogStub,
      'el-tree-select': treeSelectStub,
      RouterLink: { template: '<a><slot /></a>' },
    })
    await flushPromises()

    wrapper.vm.handleCreate()
    await flushPromises()
    Object.assign(wrapper.vm.form, {
      name: 'new-asset',
      protocol: 'ssh',
      host: 'ssh-test',
      port: 22,
      username: 'testuser',
    })
    await wrapper.vm.handleSubmit()

    expect(createAsset).toHaveBeenCalled()
    expect(successSpy).toHaveBeenCalledWith('已新增資產，已置於未分組')
    successSpy.mockRestore()
  }, 15000)
})


describe('Assets 資產標籤（authz-tag-node-filters D4/D5）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAssetListMock.mockResolvedValue(sampleAssets)
    getAssetTagsMock.mockResolvedValue({
      data: [
        { name: 'DBA', count: 2 },
        { name: '生產', count: 1 },
      ],
    })
  })

  it('admin 顯示標籤篩選下拉；標籤欄 chips 最多 2＋「+N」收納、空顯示「—」', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'tagged', protocol: 'ssh', host: 'h', port: 22, active: true, tags: 'a1,b2,c3,d4' },
        { id: 2, name: 'untagged', protocol: 'ssh', host: 'h', port: 22, active: true, tags: '' },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.tag-filter-select').exists()).toBe(true)
    const text = wrapper.text()
    expect(text).toContain('a1')
    expect(text).toContain('b2')
    expect(text).toContain('+2')
    expect(text).toContain('—')
    // 標籤清單端點已載入（篩選/表單/治理共用）
    expect(getAssetTagsMock).toHaveBeenCalled()
  })

  it('一般 user 不渲染標籤篩選下拉、不打標籤清單端點（伺服端 400/403 防護）', async () => {
    setUserRoles(['user'])
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.tag-filter-select').exists()).toBe(false)
    expect(getAssetTagsMock).not.toHaveBeenCalled()
  })

  it('表單標籤含半形逗號拒絕建立（in-band 注入防護）', async () => {
    setUserRoles(['admin'])
    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.form.tagList = ['正常', 'a,b']
    await wrapper.vm.handleFormTagChange(['正常', 'a,b'])

    expect(wrapper.vm.form.tagList).toEqual(['正常'])
    expect(warnSpy).toHaveBeenCalledWith('標籤不得含逗號')
    warnSpy.mockRestore()
  })

  it('建立相似標籤時確認引導使用既有（Dba → 既有 DBA）', async () => {
    setUserRoles(['admin'])
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.form.tagList = ['Dba']
    await wrapper.vm.handleFormTagChange(['Dba'])
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(wrapper.vm.form.tagList).toEqual(['DBA'])
    confirmSpy.mockRestore()
  })

  it('相似確認選「仍要建立」保留使用者輸入', async () => {
    setUserRoles(['admin'])
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.form.tagList = ['DBA專用']
    await wrapper.vm.handleFormTagChange(['DBA專用'])
    await flushPromises()

    expect(wrapper.vm.form.tagList).toEqual(['DBA專用'])
    confirmSpy.mockRestore()
  })

  it('標籤篩選以逗號串接進列表參數（admin）', async () => {
    setUserRoles(['admin'])
    const wrapper = mountView()
    await flushPromises()
    getAssetListMock.mockClear()

    wrapper.vm.filterForm.tags = ['生產', 'DBA']
    wrapper.vm.handleFilter()
    await flushPromises()

    expect(getAssetListMock).toHaveBeenCalledWith(
      expect.objectContaining({ tags: '生產,DBA', page: 1 })
    )
  })
})

describe('Assets 資訊分層（asset-list-info-layering）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAssetTagsMock.mockResolvedValue({ data: [] })
  })

  it('admin 預設六欄：使用者/所屬節點/連測/傳輸不在預設集，狀態合併呈現', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [{
        id: 1, name: 'pg-server', protocol: 'postgres', host: 'db-host', port: 5432,
        username: 'pguser', active: true, last_test_status: 'reachable',
        last_test_latency_ms: 12, last_test_at: '2026-07-20T00:00:00Z',
        node_paths: ['Prod / DB'],
      }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    const headers = wrapper.findAll('.list-panel th').map((th) => th.text())
    expect(headers).toContain('名稱')
    expect(headers).toContain('協議')
    expect(headers).toContain('主機')
    expect(headers).toContain('標籤')
    expect(headers).toContain('狀態')
    expect(headers).not.toContain('使用者')
    expect(headers).not.toContain('所屬節點')
    expect(headers).not.toContain('連測')
    expect(headers).not.toContain('傳輸')

    // 協議 chip 完整（class 掛專用 padding）＋連測結果併入狀態欄
    expect(wrapper.text()).toContain('POSTGRES')
    expect(wrapper.find('.protocol-col').exists()).toBe(true)
    expect(wrapper.find('.conn-badge.ok').text()).toContain('12ms')
  })

  it('狀態欄三態：>9999ms 短格式、不可達、未測佔位、測試中 spinner', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'slow', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'reachable', last_test_latency_ms: 12000, last_test_at: '2026-07-20T00:00:00Z' },
        { id: 2, name: 'down', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'unreachable', last_test_at: '2026-07-20T00:00:00Z' },
        { id: 3, name: 'never', protocol: 'ssh', host: 'h', port: 22, active: true },
      ],
      total: 3, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.conn-badge.ok').text()).toContain('>9s')
    expect(wrapper.find('.conn-badge.fail').text()).toContain('不可達')
    expect(wrapper.find('.conn-badge.muted').exists()).toBe(true)

    wrapper.vm.testingIds.add(3)
    await flushPromises()
    expect(wrapper.find('.conn-badge.testing').text()).toContain('測試中')
  })

  // db-protocol-connection-test 4.3：測試中態逐列獨立
  it('測試中態逐列獨立：兩列可同時 spinner，只禁用自己的測試入口', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'a', protocol: 'ssh', host: 'h', port: 22, active: true },
        { id: 2, name: 'b', protocol: 'mysql', host: 'h', port: 3306, active: true },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.testingIds.add(1)
    wrapper.vm.testingIds.add(2)
    await flushPromises()
    expect(wrapper.findAll('.conn-badge.testing').length).toBe(2)

    // 只有進行中的列被禁用；另一列的入口仍可點
    wrapper.vm.testingIds.delete(2)
    await flushPromises()
    expect(wrapper.vm.isTesting(1)).toBe(true)
    expect(wrapper.vm.isTesting(2)).toBe(false)
  })

  // db-protocol-connection-test 4.4：DB 可達徽章須標明僅埠可達
  it('DB 協議可達徽章 tooltip 明示僅連接埠可達；非 DB 協議不加註', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'pg', protocol: 'postgres', host: 'h', port: 5432, active: true, last_test_status: 'reachable', last_test_latency_ms: 12, last_test_at: '2026-07-20T00:00:00Z' },
        { id: 2, name: 'sshbox', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'reachable', last_test_latency_ms: 12, last_test_at: '2026-07-20T00:00:00Z' },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    const contents = wrapper.findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
      .filter((c) => typeof c === 'string' && c.includes('測於'))
    expect(contents.some((c) => c.includes('僅代表連接埠可達'))).toBe(true)
    // 非 DB 協議維持原文案（不得全面加註而誤述 ssh 的驗證深度）
    expect(contents.some((c) => c.includes('12ms') && !c.includes('僅代表連接埠可達'))).toBe(true)
  })

  // db-protocol-connection-test 4.2：撥測失敗以撥測機器碼呈現，不得退化為「網路錯誤」
  it('撥測失敗顯示機器碼譯文；未收到回應顯示撥測未完成', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [{ id: 1, name: 'pg', protocol: 'postgres', host: 'h', port: 5432, active: true }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    testAssetConnection.mockResolvedValueOnce({
      success: false, code: 'RULE_ASSET_TEST_PROTOCOL_UNSUPPORTED', error_code: 'protocol_unsupported',
    })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(warnSpy.mock.calls[0][0]).toContain('此協議尚未支援連線測試')
    expect(warnSpy.mock.calls[0][0]).not.toContain('網路錯誤')

    // 無 response（傳輸中斷／用戶端逾時）→ 撥測未完成，非通用網路錯誤
    const errSpy = vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
    testAssetConnection.mockRejectedValueOnce(Object.assign(new Error('timeout of 35000ms exceeded'), { request: {} }))
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(errSpy.mock.calls[0][0]).toContain('撥測未完成')
    expect(errSpy.mock.calls[0][0]).not.toContain('網路錯誤')
  })

  it('一般 user：無狀態欄、停用資產顯示已停用且連線/申請入口封閉', async () => {
    setUserRoles(['user'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'disabled-a', protocol: 'ssh', host: 'h', port: 22, active: false, permission: 'connect', access_state: 'connectable' },
        { id: 2, name: 'ok-a', protocol: 'ssh', host: 'h', port: 22, active: true, permission: 'connect', access_state: 'approval_required', break_glass_available: false },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    const headers = wrapper.findAll('.list-panel th').map((th) => th.text())
    expect(headers).not.toContain('狀態')
    expect(headers).toContain('授權狀態')
    expect(wrapper.text()).toContain('已停用')

    // 停用資產（access_state=connectable 也不可連——active 優先）
    expect(wrapper.vm.canConnect({ active: false, access_state: 'connectable', permission: 'connect' })).toBe(false)
    expect(wrapper.vm.needsRequest({ active: false, access_state: 'approval_required' })).toBe(false)
    expect(wrapper.vm.isPendingRequest({ active: false, access_state: 'pending' })).toBe(false)
  })

  it('傳輸風險常駐行內標記：任何角色、不受欄位自訂影響', async () => {
    setUserRoles(['user'])
    getAssetListMock.mockResolvedValue({
      data: [{
        id: 1, name: 'risky', protocol: 'rdp', host: 'h', port: 3389, active: true,
        permission: 'connect',
        transmission_risks: [{ key: 'rdp_nocert', label: 'RDP 未驗憑證' }],
      }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.host-risk').text()).toContain('風險 1')
  })

  it('齒輪加欄即時生效＋localStorage 角色分域持久化＋還原預設', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue(sampleAssets)
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.findAll('.list-panel th').map((th) => th.text())).not.toContain('所屬節點')

    wrapper.vm.optionalColumns = ['nodes']
    await flushPromises()
    expect(wrapper.findAll('.list-panel th').map((th) => th.text())).toContain('所屬節點')
    expect(JSON.parse(localStorage.getItem('ot-assets-columns-admin-v1'))).toEqual(['nodes'])

    // 重新掛載讀回（持久化）
    const wrapper2 = mountView()
    await flushPromises()
    expect(wrapper2.findAll('.list-panel th').map((th) => th.text())).toContain('所屬節點')

    // 還原預設
    wrapper2.vm.resetColumnPrefs()
    await flushPromises()
    expect(wrapper2.findAll('.list-panel th').map((th) => th.text())).not.toContain('所屬節點')
    expect(localStorage.getItem('ot-assets-columns-admin-v1')).toBe(null)
  }, 20000)

  it('localStorage 壞值容錯回預設、user 角色 key 分域不吃 admin 偏好', async () => {
    localStorage.setItem('ot-assets-columns-admin-v1', '{bad json')
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue(sampleAssets)
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.vm.optionalColumns).toEqual([])

    // admin 存好偏好後，user 登入不受影響（角色分域）
    localStorage.setItem('ot-assets-columns-admin-v1', JSON.stringify(['username', 'nodes']))
    localStorage.clear()
    localStorage.setItem('ot-assets-columns-admin-v1', JSON.stringify(['username', 'nodes']))
    setUserRoles(['user'])
    const wrapper2 = mountView()
    await flushPromises()
    expect(wrapper2.vm.optionalColumns).toEqual([])
    // user 池不含 username：即使壞資料寫入 user key 也被池過濾
    localStorage.setItem('ot-assets-columns-user-v1', JSON.stringify(['username', 'nodes']))
    const wrapper3 = mountView()
    await flushPromises()
    expect(wrapper3.vm.optionalColumns).toEqual(['nodes'])
  }, 20000)

  it('名稱欄描述為空不渲染次行', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'no-desc', protocol: 'ssh', host: 'h', port: 22, active: true, description: '' },
        { id: 2, name: 'with-desc', protocol: 'ssh', host: 'h', port: 22, active: true, description: '有描述' },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.findAll('.asset-desc').length).toBe(1)
  }, 15000)
})
