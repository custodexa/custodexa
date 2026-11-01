import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import MainLayout from '../MainLayout.vue'
import Assets from '@/views/Assets.vue'
import WorkspaceAssetSidebar from '../workspace/WorkspaceAssetSidebar.vue'
import i18n from '@/i18n'
import { resetSessionForTests } from '@/utils/session'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { useManageScopeLine } from '@/composables/useManageScope'
import {
  applyPreviewResponse,
  beginPreviewRequest,
  cancelPreview,
  exitPreview,
  exitedNotice,
} from '@/composables/useRolePreview'
import { getPreviewOverlay, isPreviewActive } from '@/utils/previewOverlay'

// 預覽橫幅、離開、預覽範圍、個人呈現、「本人看不到」與「角色沒有資產檢視」。
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })
enableAutoUnmount(afterEach)

const t = (k, p) => i18n.global.t(k, p)

const h = vi.hoisted(() => ({ push: vi.fn(), route: { path: '/assets' } }))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: h.push }),
  useRoute: () => h.route,
}))

const logoutMock = vi.hoisted(() => vi.fn())
vi.mock('@/api/auth', () => ({
  getCurrentUser: vi.fn(),
  logout: (...a) => logoutMock(...a),
}))
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: vi.fn(() => Promise.resolve({ count: 0, review_count: 0 })),
  createAccessRequest: vi.fn(),
  breakGlassConnect: vi.fn(),
}))
vi.mock('@/api/seal', () => ({
  getSealStatus: vi.fn(() => Promise.resolve({ state: 'unsealed' })),
  unseal: vi.fn(),
}))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewPendingCount: vi.fn(() => Promise.resolve({ data: { count: 0, overdue_count: 0 } })),
}))

const api = vi.hoisted(() => ({
  list: vi.fn(),
  groups: vi.fn(),
  tags: vi.fn(),
  tree: vi.fn(),
}))
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => api.list(...a),
  getAssetGroups: (...a) => api.groups(...a),
  getAssetTags: (...a) => api.tags(...a),
  getAssetNodeTree: (...a) => api.tree(...a),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn(),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
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
vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
  getAuthorizationTargetOptions: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))
vi.mock('@/api/securityPolicies', () => ({ getSecurityPolicies: vi.fn() }))

// el-table 在 happy-dom 下極慢：以保留欄位模板執行的替身取代（慣例同 Assets.spec.js）
const STUB_ROWS = Symbol('rows')
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
  props: ['label', 'prop', 'className'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub"><th>{{ label }}</th>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
const tableStubs = { ElTable: tableStub, ElTableColumn: tableColumnStub }

const NODES = [
  { id: 1, name: '台北', path: '台北' },
  { id: 2, name: '高雄', path: '高雄' },
]
const ASSETS = {
  data: [
    { id: 1, name: 'a1', protocol: 'ssh', host: 'h1', port: 22, username: 'u', active: true, permission: 'connect' },
    { id: 2, name: 'a2', protocol: 'ssh', host: 'h2', port: 22, username: 'u', active: true, permission: 'connect' },
  ],
  total: 2,
  page: 1,
  page_size: 20,
}
const ENTRY_STATES = [{ entry: 'assets', path: '/assets', state: 'manage' }]

const enter = (permissions, entryStates = ENTRY_STATES, id = 7, name = '台北 DBA 組長') => {
  const r = applyPreviewResponse(beginPreviewRequest(), {
    role: { id, name },
    previewable: true,
    permissions,
    entry_states: entryStates,
  })
  expect(r).toEqual({ entered: true })
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetSessionForTests()
  resetCapabilities()
  exitedNotice.value = null
  h.route.path = '/assets'
  api.list.mockResolvedValue(ASSETS)
  api.groups.mockResolvedValue({ data: NODES, total: 2 })
  api.tags.mockResolvedValue({ data: [] })
  api.tree.mockResolvedValue({ data: [], can_create_root: false })
})
afterEach(() => {
  cancelPreview()
  resetCapabilities()
})

describe('橫幅與離開', () => {
  const mountLayout = () => mount(MainLayout, { global: { plugins: [ElementPlus], stubs: { 'router-view': true } } })

  it('覆蓋存在時橫幅含角色名、只能看、資料上限句與離開預覽，DOM 順序在守衛橫幅之前；右上仍是本人', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, username: 'root-self', roles: [] }))
    setCapabilitiesForTests(['role:view'], { userId: 1 })
    enter(['asset:view'])
    const w = mountLayout()
    await flushPromises()
    const banner = w.get('[data-test="role-preview-banner"]')
    expect(banner.text()).toContain('正在以角色「台北 DBA 組長」預覽')
    expect(banner.text()).toContain('只能看，不能修改')
    expect(banner.text()).toContain('畫面上的資料以你自己看得到的為上限')
    expect(banner.text()).toContain('離開預覽')
    expect(banner.find('[data-test="preview-range-select"]').exists()).toBe(false)
    const guard = w.find('.instance-guard-banner, [data-test="instance-guard-banner"]')
    const html = w.html()
    const guardIdx = guard.exists() ? html.indexOf(guard.html()) : html.indexOf('capability-alert')
    if (guardIdx >= 0) expect(html.indexOf('role-preview-banner')).toBeLessThan(guardIdx)
    expect(w.text()).toContain('root-self')
  })

  it('覆蓋不存在時不渲染橫幅', async () => {
    setCapabilitiesForTests(['role:view'], { userId: 1 })
    const w = mountLayout()
    await flushPromises()
    expect(w.find('[data-test="role-preview-banner"]').exists()).toBe(false)
  })

  it('離開預覽後覆蓋清空並導到進入時的角色（A→B 後離開仍是 A）', async () => {
    setCapabilitiesForTests(['role:view'], { userId: 1 })
    enter(['role:view'], [], 11, '角色A')
    const w = mountLayout()
    await flushPromises()
    h.route.path = '/roles/12' // 預覽中開啟另一個角色的編輯頁
    await w.get('[data-test="role-preview-exit"]').trigger('click')
    expect(isPreviewActive()).toBe(false)
    expect(h.push).toHaveBeenCalledWith('/roles/11')
    expect(exitedNotice.value).toEqual({ roleId: 11, roleName: '角色A' })
    await flushPromises()
    expect(w.find('[data-test="role-preview-banner"]').exists()).toBe(false)
  })

  it('重新整理後（覆蓋為空）沒有橫幅也沒有任何提示', async () => {
    setCapabilitiesForTests(['role:view'], { userId: 1 })
    const w = mountLayout()
    await flushPromises()
    expect(w.find('[data-test="role-preview-banner"]').exists()).toBe(false)
    expect(exitedNotice.value).toBeNull()
    expect(w.text()).not.toContain('已離開預覽')
  })

  it('登出先清覆蓋再呼叫登出', async () => {
    setCapabilitiesForTests(['role:view'], { userId: 1 })
    enter(['asset:view'])
    let activeAtLogout = null
    logoutMock.mockImplementation(async () => {
      activeAtLogout = isPreviewActive()
    })
    const w = mountLayout()
    await flushPromises()
    for (const d of w.findAllComponents({ name: 'ElDropdown' })) d.vm.$emit('command', 'logout')
    await flushPromises()
    expect(logoutMock).toHaveBeenCalledTimes(1)
    expect(activeAtLogout).toBe(false)
  })
})

describe('預覽範圍與個人呈現（資產管理頁）', () => {
  const mountAssets = () => mount(Assets, { global: { plugins: [ElementPlus], stubs: tableStubs } })
  const lastListParams = () => api.list.mock.calls.at(-1)[0]

  it('範圍選擇器與節點樹同一父區塊、不在橫幅，旁有說明句；預設全部、選項取自本人節點清單', async () => {
    setCapabilitiesForTests(['asset:view', 'role:view'])
    enter(['asset:view', 'asset:create'])
    const w = mountAssets()
    await flushPromises()
    const bar = w.get('[data-test="preview-range-bar"]')
    const treeColumn = bar.element.parentElement
    expect(treeColumn.classList.contains('tree-column')).toBe(true)
    expect(treeColumn.querySelector('.asset-node-tree, [data-test="node-tree"], .tree-root') || treeColumn.children.length >= 2).toBeTruthy()
    expect(bar.text()).toContain('預覽範圍')
    expect(bar.get('[data-test="preview-range-note"]').text()).toBe('只篩選畫面，不改變角色')
    expect(w.vm.previewRange).toBeNull()
    const select = w.findAllComponents({ name: 'ElSelect' }).find((c) => c.attributes('data-test') === 'preview-range-select')
    const options = select.findAllComponents({ name: 'ElOption' }).map((o) => o.props('value'))
    expect(options).toEqual(NODES.map((n) => n.id))
  })

  it('節點樹在預覽中停用拖曳、沒有把手，停在節點列上時列下方出現說明卡；離開預覽後恢復', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', 'role:view'])
    enter(['asset:view', 'asset:update'])
    const w = mountAssets()
    await flushPromises()
    const tree = w.findComponent({ name: 'AssetNodeTree' })
    expect(tree.props('nodeDragDisabled')).toBe(true)
    expect(w.find('.drag-handle').exists()).toBe(false)
    // 懶載入的樹列在測試替身下不渲染：在樹欄內放一個同 class 的列，驗證委派的滑過
    const rowEl = document.createElement('div')
    rowEl.className = 'tree-node-row'
    w.get('.tree-column').element.appendChild(rowEl)
    const row = { element: rowEl, trigger: (ev) => rowEl.dispatchEvent(new Event(ev, { bubbles: true })) }
    row.element.getBoundingClientRect = () => ({ left: 10, right: 210, top: 50, bottom: 74, width: 200, height: 24 })
    await row.trigger('pointerover')
    const card = document.querySelector('[data-test="preview-hint-card"]')
    expect(card.hidden).toBe(false)
    expect(card.textContent).toContain('這個節點不能搬')
    expect(card.textContent).toContain('預覽中不能搬移節點。持有這個角色的人可以使用。')
    expect(card.style.top).toBe('80px')
    await w.get('.tree-column').trigger('pointerleave')
    expect(card.hidden).toBe(true)
    // 鍵盤焦點移到節點列上時同樣出現說明卡，焦點離開時收起
    await row.trigger('focusin')
    expect(card.hidden).toBe(false)
    expect(card.textContent).toContain('這個節點不能搬')
    await row.trigger('focusout')
    expect(card.hidden).toBe(true)
    exitPreview()
    await flushPromises()
    expect(w.findComponent({ name: 'AssetNodeTree' }).props('nodeDragDisabled')).toBe(false)
  })

  it('選一個節點後資產列表請求與自己選取該節點時逐欄相同；預覽集合不變', async () => {
    setCapabilitiesForTests(['asset:view', 'role:view'])
    const plain = mountAssets()
    await flushPromises()
    plain.vm.handleNodeSelect(NODES[1])
    await flushPromises()
    const own = { ...lastListParams() }
    plain.unmount()

    api.list.mockClear()
    enter(['asset:view', 'asset:create'])
    const permsBefore = [...getPreviewOverlay().permissions]
    const w = mountAssets()
    await flushPromises()
    w.vm.onPreviewRangeChange(2)
    await flushPromises()
    expect(lastListParams()).toEqual(own)
    expect(getPreviewOverlay().range).toBe(2)
    expect([...getPreviewOverlay().permissions]).toEqual(permsBefore)
    // 範圍清除回到不篩選
    w.vm.onPreviewRangeChange(null)
    await flushPromises()
    expect(getPreviewOverlay().range).toBeNull()
  })

  it('預覽中無授權狀態欄與連線按鈕，底部有說明；離開後恢復', async () => {
    setCapabilitiesForTests(['asset:view', 'role:view'])
    enter(['asset:view'])
    const w = mountAssets()
    await flushPromises()
    expect(w.findAll('th').map((x) => x.text())).not.toContain(t('assets.permissionColumn'))
    expect(w.findAll('.cell-stub').map((x) => x.text()).join('|')).not.toContain(t('common.connect'))
    expect(w.get('[data-test="preview-asset-total"]').text()).toBe('連線按鈕因人而異，預覽中不顯示。')
    w.unmount()

    exitPreview()
    const after = mountAssets()
    await flushPromises()
    expect(after.find('[data-test="preview-asset-total"]').exists()).toBe(false)
    expect(after.findAll('th').map((x) => x.text())).toContain(t('assets.permissionColumn'))
    expect(after.findAll('.cell-stub').map((x) => x.text()).join('|')).toContain(t('common.connect'))
  })

  it('頁首範圍行（憑證頁、授權頁來源）在預覽中不渲染，離開後依原值恢復', () => {
    const scope = [{ permission: 'credential:view', binding_scope: 'nodes', nodes: [{ path: ['A'] }] }]
    setCapabilitiesForTests(['credential:view'], { scope })
    const line = useManageScopeLine('credential:view')
    expect(line.value).not.toBeNull()
    enter(['credential:view'])
    expect(line.value).toBeNull()
    exitPreview()
    expect(line.value).not.toBeNull()
  })
})

describe('資料上限與角色沒有資產檢視', () => {
  const mountAssets = () => mount(Assets, { global: { plugins: [ElementPlus], stubs: tableStubs } })

  it('角色有資產檢視、本人沒有：資產頁說明本人看不到，列表／群組／標籤請求為 0，無錯誤訊息，新增按鈕呈現且停用', async () => {
    const errorSpy = vi.spyOn(ElMessage, 'error')
    setCapabilitiesForTests(['role:view'])
    enter(['asset:view', 'asset:create'])
    const w = mountAssets()
    await flushPromises()
    expect(api.list).not.toHaveBeenCalled()
    expect(api.groups).not.toHaveBeenCalled()
    expect(api.tags).not.toHaveBeenCalled()
    const panel = w.get('[data-test="assets-self-cannot-see"]')
    expect(panel.text()).toContain('這裡的資料你本人看不到')
    expect(panel.text()).toContain(t('rolePreview.selfCannotSee.body'))
    expect(w.find('[data-test="assets-no-view"]').exists()).toBe(false)
    expect(errorSpy).not.toHaveBeenCalled()
    const create = w.get('[data-test="bulk-entry"]')
    expect(create.attributes('disabled')).toBeDefined()
    expect(create.attributes('aria-description')).toBe(t('rolePreview.disabledCreate'))
  })

  it('同一情境在工作區側欄：不請求資產列表，顯示同一說明', async () => {
    setCapabilitiesForTests(['role:view'])
    enter(['asset:view'])
    const w = mount(WorkspaceAssetSidebar, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    w.vm.loadAssets()
    await flushPromises()
    expect(api.list).not.toHaveBeenCalled()
    expect(w.get('[data-test="assets-self-cannot-see"]').text()).toContain('這裡的資料你本人看不到')
  })

  it('角色不含資產檢視：顯示持有者看到的既有說明', async () => {
    setCapabilitiesForTests(['asset:view', 'role:view'])
    enter(['user:manage'])
    const w = mountAssets()
    await flushPromises()
    expect(api.list).not.toHaveBeenCalled()
    expect(w.text()).toContain('你的角色沒有資產檢視權限')
    expect(w.find('[data-test="assets-self-cannot-see"]').exists()).toBe(false)
  })
})
