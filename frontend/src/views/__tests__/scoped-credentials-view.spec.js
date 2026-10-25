import { computed } from 'vue'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import ElementPlus from 'element-plus'
import CredentialLibrary from '@/views/CredentialLibrary.vue'
import CredentialTable from '@/components/credential/CredentialTable.vue'
import CredentialFormDialog from '@/components/credential/CredentialFormDialog.vue'
import CredentialOwnershipSelect from '@/components/credential/CredentialOwnershipSelect.vue'
import CredentialDetailPanel from '@/components/credential/CredentialDetailPanel.vue'
import CredentialRotateDialog from '@/components/credential/CredentialRotateDialog.vue'
import CredentialSecretFixDialog from '@/components/credential/CredentialSecretFixDialog.vue'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import AssetAccountRows from '@/components/asset/AssetAccountRows.vue'
import Dashboard from '@/views/Dashboard.vue'
import { grantFor, permissionsFor } from '@/composables/__tests__/capabilityFixtures'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { canEnter, entryMeta } from '@/router/entryRules'
import { useUpgradeGuidance } from '@/composables/useUpgradeGuidance'

// 範圍化檢視者的帳號憑證庫、共用憑證修改確認、資產抽屜與升級說明卡。
//
// 前端只消費伺服器標示（ownership、actions、selectable、確認端點回應），本檔每個案例
// 餵的都是伺服器回應的形狀，不替前端造出任何「範圍計算」。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const listMock = vi.fn()
const getMock = vi.fn()
const impactMock = vi.fn()
const setSecretMock = vi.fn()
const startRotationMock = vi.fn()
const reassignMock = vi.fn()
const createMock = vi.fn()
const updateMock = vi.fn()
const convertScopeMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listMock(...a),
  getCredential: (...a) => getMock(...a),
  createCredential: (...a) => createMock(...a),
  updateCredential: (...a) => updateMock(...a),
  deleteCredential: vi.fn(),
  bindCredential: vi.fn(),
  unbindCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  convertCredentialScope: (...a) => convertScopeMock(...a),
  setCredentialSecret: (...a) => setSecretMock(...a),
  startCredentialRotation: (...a) => startRotationMock(...a),
  getCredentialRotation: vi.fn(),
  retryCredentialRotationMember: vi.fn(),
  abandonCredentialRotation: vi.fn(),
  confirmCredentialImpact: (...a) => impactMock(...a),
  reassignCredentialOwnership: (...a) => reassignMock(...a),
  rebindAccountCredential: vi.fn(),
}))

const groupsMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetGroups: (...a) => groupsMock(...a),
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))

const listAccountsMock = vi.fn()
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: (...a) => listAccountsMock(...a),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))

vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))

const getGuidanceStateMock = vi.fn()
vi.mock('@/api/releaseGuidance', () => ({
  getReleaseGuidanceState: (...a) => getGuidanceStateMock(...a),
  dismissReleaseGuidance: vi.fn(),
  getRetentionAdjustments: vi.fn().mockResolvedValue({ notice_version: '1.18.0', items: [], uncovered: [] }),
}))
vi.mock('@/api/dashboard', () => ({
  getDashboardCard: vi.fn((key) => Promise.resolve({ key, value: 1, unit: 'count', filters: {} })),
}))
vi.mock('@/api/sessions', () => ({ getActiveSessions: vi.fn().mockResolvedValue([]) }))
vi.mock('@/api/myConnections', () => ({ getMyConnections: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
vi.mock('@/api/alerts', () => ({ searchAlerts: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: vi.fn().mockResolvedValue({ data: { enabled: false } }),
  getDailyReviewPending: vi.fn(),
  getDailyReviewPendingCount: vi.fn().mockResolvedValue({ data: { count: 0, overdue_count: 0 } }),
  signDailyReview: vi.fn(),
}))
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: vi.fn().mockResolvedValue({ count: 0, review_count: 0 }),
}))

const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const mountOpts = { global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } } }

// --- 夾具 ---

const sharedRow = (over = {}) => ({
  id: 1,
  name: 'linux-ops',
  scope: 'shared',
  username: 'ops',
  secret_type: 'password',
  protocol_family: 'ssh',
  note: '',
  has_password: true,
  has_private_key: false,
  binding_count: 5,
  current_version_no: 3,
  rotation_active: false,
  created_at: '2026-07-02T03:00:00Z',
  updated_at: '2026-08-30T03:00:00Z',
  ownership: { kind: 'node', node_id: 7 },
  ...over,
})

const allowed = { allowed: true }
const scopedActions = () => ({
  edit: allowed,
  set_secret: allowed,
  rotate: allowed,
  bind: allowed,
  convert_scope: allowed,
  reassign: allowed,
  delete: { allowed: false, reason: 'out_of_scope' },
})

// 範圍化檢視者的列表：伺服器附 actions 與範圍外台數
const scopedList = () => [
  sharedRow({ id: 1, actions: scopedActions(), out_of_scope_asset_count: 9 }),
  sharedRow({ id: 2, name: 'pg-replica', username: 'replicator', binding_count: 8, actions: scopedActions() }),
]

// 超管視角：沒有 actions、沒有範圍外台數
const globalList = () => [
  sharedRow({ id: 1, name: 'domain-admin', username: 'administrator', ownership: { kind: 'global' }, binding_count: 41 }),
  sharedRow({ id: 2, name: 'linux-root-legacy', username: 'root', ownership: { kind: 'global' }, binding_count: 27 }),
  sharedRow({ id: 3, name: 'win-local-admin', username: 'localadmin', ownership: { kind: 'global' }, binding_count: 18 }),
  sharedRow({ id: 4, name: 'web-01 / app', scope: 'dedicated', username: 'app', ownership: { kind: 'asset' }, binding_count: 1 }),
]

const bindingsOf = (n) => Array.from({ length: n }, (_, i) => ({
  account_id: 100 + i,
  asset_id: 10 + i,
  asset_name: `host-${i + 1}.example.internal`,
  username: 'ops',
  is_default: false,
  privileged: false,
  note: '',
  effective_version_no: 3,
  up_to_date: true,
}))

const nodes = (rows) => rows.map(([id, name, selectable]) => ({
  id, name, path: `台北機房 / ${name}`, ...(selectable === undefined ? {} : { selectable }),
}))

async function mountPage() {
  const wrapper = mount(CredentialLibrary, mountOpts)
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  grantFor(['admin'])
  listMock.mockResolvedValue({ data: globalList(), total: 46 })
  getMock.mockResolvedValue({ data: { ...sharedRow(), bindings: bindingsOf(5) }, aggregate_state: 'idle' })
  groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫']]) })
  impactMock.mockResolvedValue({ required: false, in_scope_count: 5 })
  setSecretMock.mockResolvedValue({ id: 1 })
  startRotationMock.mockResolvedValue({ data: { id: 7 } })
  reassignMock.mockResolvedValue({ changed: 3 })
  createMock.mockResolvedValue({ id: 9 })
  updateMock.mockResolvedValue({ id: 9 })
  convertScopeMock.mockResolvedValue({ data: sharedRow() })
  listAccountsMock.mockResolvedValue({ data: [] })
})

// --- 8.1 憑證庫 ---

describe('憑證庫：範圍化視角', () => {
  beforeEach(() => {
    listMock.mockResolvedValue({ data: scopedList(), total: 2 })
  })

  it('掛載欄含「＋範圍外 9」，沒有範圍外的列不出現', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="credential-out-of-scope-1"]').text()).toBe('＋範圍外 9')
    expect(wrapper.find('[data-test="credential-bindings-1"]').text()).toBe('5')
    expect(wrapper.find('[data-test="credential-out-of-scope-2"]').exists()).toBe(false)
  })

  it('頁尾為範圍化文案，沒有勾選欄、改歸鈕與已選列', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="credential-footnote"]').text())
      .toBe('全公司共用的憑證由全系統管理者維護，不會列在這裡')
    expect(wrapper.find('.el-table-column--selection').exists()).toBe(false)
    expect(wrapper.find('[data-test="credential-reassign-1"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="batch-bar"]').exists()).toBe(false)
  })

  it('歸屬欄顯示節點路徑（取自節點列表），查不到退回節點編號', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[7, '核心資料庫', true]]) })
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="credential-ownership-1"]').text()).toBe('台北機房 / 核心資料庫')
    groupsMock.mockResolvedValue({ data: [] })
    const again = await mountPage()
    expect(again.find('[data-test="credential-ownership-1"]').text()).toBe('節點 7')
  })

  it('詳情說明含範圍外台數 9，且只列範圍內的 5 台', async () => {
    getMock.mockResolvedValue({
      data: { ...sharedRow({ actions: scopedActions(), out_of_scope_asset_count: 9 }), bindings: bindingsOf(5) },
      aggregate_state: 'idle',
    })
    const wrapper = await mountPage()
    await wrapper.vm.selectCredential({ id: 1 })
    await flushPromises()
    expect(wrapper.find('[data-test="detail-out-of-scope"]').text()).toContain('9')
    expect(wrapper.findAll('[data-test^="binding-row-"]')).toHaveLength(5)
    expect(wrapper.find('[data-test="detail-ownership"]').exists()).toBe(true)
  })

  it('依 actions 呈現動作：旗標為不可操作的動作停用並寫出原因', async () => {
    getMock.mockResolvedValue({
      data: {
        ...sharedRow({ actions: { ...scopedActions(), rotate: { allowed: false, reason: 'no_capability' } } }),
        bindings: bindingsOf(2),
      },
      aggregate_state: 'idle',
    })
    const wrapper = await mountPage()
    await wrapper.vm.selectCredential({ id: 1 })
    await flushPromises()
    expect(wrapper.find('[data-test="action-rotate"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="action-bind"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-test="blocked-rotate"]').text()).toBe('你的角色沒有執行這個動作的權限。')
    expect(wrapper.find('[data-test="detail-delete"]').attributes('disabled')).toBeDefined()
  })
})

describe('憑證庫：超管視角', () => {
  it('有勾選欄與列操作；選三筆後標題含 3、列出三個名稱，送出本文為 credential_ids 與目的節點', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫']]) })
    const wrapper = await mountPage()
    expect(wrapper.find('.el-table-column--selection').exists()).toBe(true)
    expect(wrapper.find('[data-test="credential-reassign-1"]').exists()).toBe(true)
    // 專用憑證恆隨資產，沒有列操作
    expect(wrapper.find('[data-test="credential-reassign-4"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="credential-footnote"]').text()).toContain('歸屬「全域」的憑證只有超級管理者')

    const rows = wrapper.vm.credentials.slice(0, 3)
    wrapper.findComponent(CredentialTable).vm.$emit('update:selection', rows)
    await flushPromises()
    expect(wrapper.find('[data-test="batch-count"]').text()).toBe('已選 3 筆')

    await wrapper.find('[data-test="batch-reassign"]').trigger('click')
    await flushPromises()
    const dialog = wrapper.find('[data-test="reassign-dialog"]')
    expect(dialog.exists()).toBe(true)
    expect(wrapper.find('[data-test="reassign-names"]').text()).toBe('domain-admin、linux-root-legacy、win-local-admin')
    expect(wrapper.find('[data-test="reassign-submit"]').text()).toBe('改歸 3 組')
    expect(groupsMock).toHaveBeenCalledWith({ purpose: 'credential_update' })

    wrapper.findComponent(CredentialOwnershipSelect).vm.$emit('update:modelValue', { kind: 'node', node_id: 5 })
    await flushPromises()
    await wrapper.find('[data-test="reassign-submit"]').trigger('click')
    await flushPromises()
    expect(reassignMock).toHaveBeenCalledWith({
      credential_ids: [1, 2, 3],
      ownership: { kind: 'node', node_id: 5 },
    })
  })

  it('歸屬篩選送到伺服端', async () => {
    const wrapper = await mountPage()
    wrapper.vm.filters.ownership = 'global'
    await wrapper.vm.applyFilters()
    await flushPromises()
    expect(listMock.mock.calls.at(-1)[0].ownership).toBe('global')
  })
})

describe('歸屬選擇器：只消費伺服器標示', () => {
  const mountForm = async (props = {}) => {
    const wrapper = mount(CredentialFormDialog, { ...mountOpts, props: { modelValue: false, ...props } })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()
    return wrapper
  }

  it('新增對話框請求網址含 purpose=credential_create，編輯含 credential_update', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫', true]]), selectable_all: false })
    await mountForm()
    expect(groupsMock).toHaveBeenLastCalledWith({ purpose: 'credential_create' })
    await mountForm({ credential: sharedRow({ id: 9 }) })
    expect(groupsMock).toHaveBeenLastCalledWith({ purpose: 'credential_update' })
  })

  it('selectable=false 的定位祖先為停用列、節點選項只有 selectable=true 者可選', async () => {
    groupsMock.mockResolvedValue({
      data: nodes([[1, '台北機房', false], [5, '核心資料庫', true], [6, '唯讀副本', true]]),
      selectable_all: false,
    })
    const wrapper = await mountForm()
    const options = wrapper.findComponent(CredentialOwnershipSelect).vm.nodes
    expect(options.filter((n) => n.selectable).map((n) => n.id)).toEqual([5, 6])
    expect(options.find((n) => n.id === 1).selectable).toBe(false)
  })

  it('範圍化主體沒有全域選項；未選歸屬不送出', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫', true]]), selectable_all: false })
    const wrapper = await mountForm()
    expect(wrapper.find('[data-test="ownership-kind"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="form-submit"]').attributes('disabled')).toBeDefined()
    wrapper.findComponent(CredentialOwnershipSelect).vm.$emit('update:modelValue', { kind: 'node', node_id: 5 })
    await flushPromises()
    expect(wrapper.find('[data-test="form-submit"]').attributes('disabled')).toBeUndefined()
    Object.assign(wrapper.vm.form, { name: 'pg-monitor', username: 'monitor', password: 'x' })
    expect(wrapper.vm.createPayload().ownership).toEqual({ kind: 'node', node_id: 5 })
  })

  it('selectable_all=true 時全部可選且可選全域；不帶 selectable 的回應全部可選', async () => {
    groupsMock.mockResolvedValue({
      data: nodes([[5, '核心資料庫', true], [6, '唯讀副本', true]]),
      selectable_all: true,
    })
    const all = await mountForm()
    expect(all.find('[data-test="ownership-kind"]').exists()).toBe(true)
    expect(all.findComponent(CredentialOwnershipSelect).vm.nodes.every((n) => n.selectable)).toBe(true)

    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫'], [6, '唯讀副本']]) })
    const plain = await mountForm()
    expect(plain.findComponent(CredentialOwnershipSelect).vm.nodes.every((n) => n.selectable)).toBe(true)
    // 全域主體不選節點：維持現行「不帶歸屬」
    Object.assign(plain.vm.form, { name: 'a', username: 'b', password: 'c' })
    expect('ownership' in plain.vm.createPayload()).toBe(false)
  })

  it('selectable_all=false 且沒有任何可選節點：選項為空、無法送出', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[1, '台北機房', false]]), selectable_all: false })
    const wrapper = await mountForm()
    expect(wrapper.find('[data-test="ownership-none"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="form-submit"]').attributes('disabled')).toBeDefined()
  })

  it('編輯時歸屬沒改就不送，也不因候選為空擋住改名', async () => {
    groupsMock.mockResolvedValue({ data: [], selectable_all: false })
    const wrapper = await mountForm({ credential: sharedRow({ id: 9 }) })
    wrapper.vm.form.name = '新名稱'
    expect('ownership' in wrapper.vm.updatePayload()).toBe(false)
    expect(wrapper.find('[data-test="form-submit"]').attributes('disabled')).toBeUndefined()
  })

  it('編輯對話框逐項說明兩種歸屬由誰管理；新增對話框維持一句提示', async () => {
    const globalLine = '全域：只有超級管理者與管理範圍為全系統的資產管理員能管理、掛載。'
    const nodeLine = '節點：該節點的資產管理員也能管理、掛載。'
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫', true]]), selectable_all: true })
    const edit = await mountForm({ credential: sharedRow({ id: 9 }) })
    expect(edit.find('[data-test="ownership-explain-global"]').text()).toBe(globalLine)
    expect(edit.find('[data-test="ownership-explain-node"]').text()).toBe(nodeLine)
    expect(edit.find('[data-test="ownership-hint"]').exists()).toBe(false)

    const create = await mountForm()
    expect(create.find('[data-test="ownership-hint"]').text())
      .toBe('歸屬決定誰能管理與掛載這組憑證。只能選你可管理的節點。')
    expect(create.find('[data-test="ownership-explain-global"]').exists()).toBe(false)
    expect(create.find('[data-test="ownership-explain-node"]').exists()).toBe(false)

    // 範圍化主體沒有全域選項：只說明節點歸屬
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫', true]]), selectable_all: false })
    const scoped = await mountForm({ credential: sharedRow({ id: 9 }) })
    expect(scoped.find('[data-test="ownership-explain-global"]').exists()).toBe(false)
    expect(scoped.find('[data-test="ownership-explain-node"]').text()).toBe(nodeLine)
  })

  it('編輯時 reassign 旗標為不可操作：欄位停用並說明原因', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫', true]]), selectable_all: false })
    const wrapper = await mountForm({
      credential: sharedRow({ id: 9, actions: { reassign: { allowed: false, reason: 'out_of_scope' } } }),
    })
    expect(wrapper.find('[data-test="form-ownership"]').text()).toContain('這筆憑證的歸屬不在你可管理的範圍內。')
    wrapper.vm.form.name = '新名稱'
    expect('ownership' in wrapper.vm.updatePayload()).toBe(false)
  })

  it('轉為共用對話框請求網址含 credential_convert_scope', async () => {
    groupsMock.mockResolvedValue({ data: nodes([[5, '核心資料庫', true]]), selectable_all: false })
    const wrapper = mount(CredentialDetailPanel, {
      ...mountOpts,
      props: {
        credential: { ...sharedRow({ scope: 'dedicated', binding_count: 1 }), bindings: bindingsOf(1) },
      },
    })
    wrapper.vm.openToShared()
    await flushPromises()
    expect(groupsMock).toHaveBeenLastCalledWith({ purpose: 'credential_convert_scope' })
    wrapper.vm.toSharedName = 'pg-shared'
    wrapper.findComponent(CredentialOwnershipSelect).vm.$emit('update:modelValue', { kind: 'node', node_id: 5 })
    await flushPromises()
    await wrapper.vm.convertToShared()
    expect(convertScopeMock).toHaveBeenCalledWith(1, {
      scope: 'shared',
      name: 'pg-shared',
      ownership: { kind: 'node', node_id: 5 },
    })
  })
})

// --- 8.2 共用憑證修改確認 ---

describe('共用憑證修改確認', () => {
  const fixCredential = () => ({ ...sharedRow({ id: 12 }), bindings: bindingsOf(5) })
  const mountFix = async () => {
    const wrapper = mount(CredentialSecretFixDialog, {
      ...mountOpts,
      props: { modelValue: false, credentialId: 12, credential: fixCredential() },
    })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()
    return wrapper
  }
  const fillAndSubmit = async (wrapper) => {
    await wrapper.find('[data-test="secret-fix-password"]').setValue('Right-Pass-1')
    await wrapper.find('[data-test="secret-fix-confirm"]').setValue('Right-Pass-1')
    await wrapper.find('[data-test="secret-fix-submit"]').trigger('click')
    await flushPromises()
  }

  it('required=false：直接送出，請求不帶確認欄', async () => {
    const wrapper = await mountFix()
    await fillAndSubmit(wrapper)
    expect(impactMock).toHaveBeenCalledWith(12, 'set_secret')
    expect(setSecretMock).toHaveBeenCalledTimes(1)
    expect(setSecretMock.mock.calls[0][1]).toEqual({ password: 'Right-Pass-1' })
    expect(wrapper.find('[data-test="impact-dialog"]').exists()).toBe(false)
  })

  it('required=true：未勾選送出鈕停用，勾選後送出本文含 impact_confirmation_id', async () => {
    impactMock.mockResolvedValue({
      required: true, confirmation_id: 'c-1', in_scope_count: 5, out_of_scope_asset_count: 9,
    })
    const wrapper = await mountFix()
    await fillAndSubmit(wrapper)
    expect(setSecretMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="impact-dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="impact-lead"]').text()).toContain('14')
    expect(wrapper.find('[data-test="impact-in-cell"]').text()).toContain('5')
    expect(wrapper.find('[data-test="impact-out-cell"]').text()).toContain('9')
    expect(wrapper.find('[data-test="impact-out-cell"]').text()).toContain('由其他管理者負責，這裡不列出')
    expect(wrapper.find('[data-test="impact-submit"]').text()).toBe('儲存並套用到 14 台')
    expect(wrapper.find('[data-test="impact-submit"]').attributes('disabled')).toBeDefined()
    // 清單只列範圍內，不含任何範圍外資產
    expect(wrapper.findAll('[data-test="impact-assets"] tbody tr')).toHaveLength(5)

    await wrapper.find('[data-test="impact-ack"] input').setValue(true)
    expect(wrapper.find('[data-test="impact-submit"]').attributes('disabled')).toBeUndefined()
    await wrapper.find('[data-test="impact-submit"]').trigger('click')
    await flushPromises()
    expect(setSecretMock).toHaveBeenCalledTimes(1)
    expect(setSecretMock.mock.calls[0][1]).toEqual({ password: 'Right-Pass-1', impact_confirmation_id: 'c-1' })
    expect(wrapper.emitted('saved')).toHaveLength(1)
  })

  it('取消確認：不送出，已輸入的明文保留', async () => {
    impactMock.mockResolvedValue({
      required: true, confirmation_id: 'c-1', in_scope_count: 5, out_of_scope_asset_count: 9,
    })
    const wrapper = await mountFix()
    await fillAndSubmit(wrapper)
    await wrapper.find('[data-test="impact-cancel"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="impact-dialog"]').exists()).toBe(false)
    expect(setSecretMock).not.toHaveBeenCalled()
    expect(wrapper.vm.form.secret).toBe('Right-Pass-1')
  })

  it('409 後以新台數重開對話框，輸入的明文保留至關閉', async () => {
    impactMock
      .mockResolvedValueOnce({ required: true, confirmation_id: 'c-1', in_scope_count: 5, out_of_scope_asset_count: 9 })
      .mockResolvedValueOnce({ required: true, confirmation_id: 'c-2', in_scope_count: 5, out_of_scope_asset_count: 12 })
    setSecretMock.mockRejectedValueOnce({
      response: {
        status: 409,
        data: { code: 'RULE_CREDENTIAL_IMPACT_CONFIRMATION_REQUIRED', params: { count: 12 } },
      },
    })
    const wrapper = await mountFix()
    await fillAndSubmit(wrapper)
    await wrapper.find('[data-test="impact-ack"] input').setValue(true)
    await wrapper.find('[data-test="impact-submit"]').trigger('click')
    await flushPromises()

    expect(setSecretMock).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-test="impact-dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="impact-out-cell"]').text()).toContain('12')
    expect(wrapper.find('[data-test="impact-lead"]').text()).toContain('17')
    // 新的範圍外集合要重新勾選
    expect(wrapper.find('[data-test="impact-submit"]').attributes('disabled')).toBeDefined()
    expect(wrapper.vm.form.secret).toBe('Right-Pass-1')
    expect(wrapper.emitted('saved')).toBeUndefined()

    await wrapper.find('[data-test="impact-ack"] input').setValue(true)
    await wrapper.find('[data-test="impact-submit"]').trigger('click')
    await flushPromises()
    expect(setSecretMock.mock.calls[1][1].impact_confirmation_id).toBe('c-2')
    expect(wrapper.emitted('saved')).toHaveLength(1)
  })

  it('改密對話框：範圍外台數 >0 時先顯示提示，總數為範圍內加範圍外', async () => {
    const wrapper = mount(CredentialRotateDialog, {
      ...mountOpts,
      props: {
        modelValue: true, credentialId: 1, credentialName: 'linux-ops',
        bindingCount: 5, outOfScopeCount: 9, bindings: bindingsOf(5), username: 'ops',
      },
    })
    await flushPromises()
    expect(wrapper.find('[data-test="rotate-out-of-scope-hint"]').text()).toContain('14')
    expect(wrapper.find('[data-test="rotate-out-of-scope-hint"]').text()).toContain('9')
    expect(wrapper.find('[data-test="rotate-summary"]').text()).toContain('14')

    const none = mount(CredentialRotateDialog, {
      ...mountOpts,
      props: { modelValue: true, credentialId: 1, credentialName: 'linux-ops', bindingCount: 5 },
    })
    await flushPromises()
    expect(none.find('[data-test="rotate-out-of-scope-hint"]').exists()).toBe(false)
  })

  it('改密：required=true 時先確認，勾選後本文含 impact_confirmation_id', async () => {
    impactMock.mockResolvedValue({
      required: true, confirmation_id: 'r-1', in_scope_count: 5, out_of_scope_asset_count: 9,
    })
    const wrapper = mount(CredentialRotateDialog, {
      ...mountOpts,
      props: {
        modelValue: true, credentialId: 1, credentialName: 'linux-ops',
        bindingCount: 5, outOfScopeCount: 9, bindings: bindingsOf(5), username: 'ops',
      },
    })
    await flushPromises()
    await wrapper.find('[data-test="rotate-submit"]').trigger('click')
    await flushPromises()
    expect(impactMock).toHaveBeenCalledWith(1, 'rotate')
    expect(startRotationMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="impact-submit"]').text()).toBe('送出改密並套用到 14 台')
    await wrapper.find('[data-test="impact-ack"] input').setValue(true)
    await wrapper.find('[data-test="impact-submit"]').trigger('click')
    await flushPromises()
    expect(startRotationMock.mock.calls[0][1].impact_confirmation_id).toBe('r-1')
  })
})

// --- 8.3 資產抽屜 ---

describe('資產抽屜：範圍外憑證的帳號列', () => {
  const outRow = (over = {}) => ({
    id: 31,
    asset_id: 2,
    username: 'ops',
    is_default: false,
    privileged: false,
    note: '',
    has_password: true,
    has_private_key: false,
    shared_credential: true,
    credential_scope: 'shared',
    credential_out_of_scope: true,
    effective_version_no: 3,
    ...over,
  })
  const inRow = () => ({
    id: 32,
    asset_id: 2,
    username: 'monitor',
    is_default: false,
    privileged: false,
    note: '',
    has_password: true,
    has_private_key: false,
    shared_credential: true,
    credential_id: 110,
    credential_name: 'pg-monitor',
    credential_scope: 'shared',
    binding_count: 4,
    effective_version_no: 3,
  })

  // el-table 在 happy-dom 下極慢：以保留欄位模板執行的替身取代，列內渲染的斷言力不變
  const ROWS = Symbol('rows')
  const tableStub = {
    name: 'ElTable',
    props: ['data'],
    provide() { return { [ROWS]: computed(() => this.data || []) } },
    template: '<div class="table-stub"><slot /></div>',
  }
  const columnStub = {
    name: 'ElTableColumn',
    props: ['label', 'prop', 'width', 'minWidth', 'className'],
    inject: { stubRows: { from: ROWS, default: null } },
    // 選項式 inject 會自動解包注入的 ref：拿到的可能是陣列本身
    computed: {
      rows() {
        const injected = this.stubRows
        if (!injected) return []
        return Array.isArray(injected) ? injected : injected.value || []
      },
    },
    template: `<div class="col-stub"><div v-for="(row, i) in rows" :key="i" class="cell-stub">
      <slot :row="row" :column="{}" :$index="i" /></div></div>`,
  }
  const mountRows = async (rows) => {
    listAccountsMock.mockResolvedValue({ data: rows })
    listMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mount(AssetAccountRows, {
      global: {
        plugins: [ElementPlus],
        stubs: { 'el-dialog': dialogStub, ElTable: tableStub, ElTableColumn: columnStub },
      },
      props: { assetId: 2, assetName: 'db-core-ro-03', protocol: 'ssh' },
    })
    await flushPromises()
    return wrapper
  }

  it('範圍外憑證列不渲染憑證名稱與台數；更正與脫離停用並有說明；更換與移除可用', async () => {
    const wrapper = await mountRows([
      outRow({ actions: {
        rebind: allowed, remove: allowed,
        secret_fix: { allowed: false, reason: 'out_of_scope' },
        detach: { allowed: false, reason: 'out_of_scope' },
      } }),
    ])
    expect(wrapper.find('[data-test="account-out-of-scope-31"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="account-credential-31"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="account-shared-31"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="account-secret-fix-31"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="account-detach-31"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="account-rebind-31"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-test="account-remove-31"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-test="account-out-of-scope-note-31"]').exists()).toBe(true)
  })

  it('沒有 actions 的範圍外憑證列：更正與脫離仍不可執行', async () => {
    const wrapper = await mountRows([outRow()])
    expect(wrapper.find('[data-test="account-secret-fix-31"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="account-detach-31"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="account-rebind-31"]').attributes('disabled')).toBeUndefined()
  })

  it('旗標標示缺能力的動作停用並寫出原因；範圍內憑證列照舊', async () => {
    const wrapper = await mountRows([
      outRow({ actions: {
        rebind: { allowed: false, reason: 'no_capability' }, remove: allowed,
        secret_fix: { allowed: false, reason: 'out_of_scope' }, detach: { allowed: false, reason: 'out_of_scope' },
      } }),
      inRow(),
    ])
    expect(wrapper.find('[data-test="account-rebind-31"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="account-denied-no_capability-31"]').text())
      .toBe('你的角色沒有執行這個動作的權限。')
    expect(wrapper.find('[data-test="account-credential-32"]').text()).toBe('pg-monitor')
    expect(wrapper.find('[data-test="account-secret-fix-32"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-test="account-denied-no_capability-32"]').exists()).toBe(false)
  })

  it('更換憑證選單下方有說明句（清單項帶 actions 時），全域視角沒有', async () => {
    listMock.mockResolvedValue({ data: scopedList(), total: 2 })
    const scoped = mount(CredentialPicker, { ...mountOpts, props: { protocol: 'ssh' } })
    await flushPromises()
    expect(scoped.find('[data-test="credential-picker-scoped-note"]').text())
      .toBe('只列出歸屬在你可管理節點的共用憑證。')

    listMock.mockResolvedValue({ data: globalList(), total: 4 })
    const plain = mount(CredentialPicker, { ...mountOpts, props: { protocol: 'ssh' } })
    await flushPromises()
    expect(plain.find('[data-test="credential-picker-scoped-note"]').exists()).toBe(false)
  })
})

describe('資產抽屜：新增帳號的專用模式可用條件', () => {
  const tableStub2 = { name: 'ElTable', props: ['data'], template: '<div class="table-stub"><slot /></div>' }
  const columnStub2 = { name: 'ElTableColumn', props: ['label', 'prop', 'width', 'minWidth', 'className'], template: '<div />' }
  const openAdd = async (perms) => {
    setCapabilitiesForTests(perms, { userId: 1 })
    listAccountsMock.mockResolvedValue({ data: [] })
    listMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mount(AssetAccountRows, {
      global: {
        plugins: [ElementPlus],
        stubs: { 'el-dialog': dialogStub, ElTable: tableStub2, ElTableColumn: columnStub2 },
      },
      props: { assetId: 2, assetName: 'db-core-ro-03', protocol: 'ssh' },
    })
    await flushPromises()
    await wrapper.find('[data-test="account-add"]').trigger('click')
    await flushPromises()
    return wrapper.find('[data-test="account-add-row"]')
  }
  const dedicatedRadio = (row) => row.find('[data-test="credential-mode"] input[value="dedicated"]')

  it('只持 credential:create：專用模式可用、不顯示停用說明', async () => {
    const row = await openAdd(['asset:update', 'credential:create'])
    expect(dedicatedRadio(row).element.disabled).toBe(false)
    expect(row.find('[data-test="credential-dedicated-disabled-note"]').exists()).toBe(false)
  })

  it('兩鍵皆無：專用模式停用，說明不提權限名', async () => {
    const row = await openAdd(['asset:update'])
    expect(dedicatedRadio(row).element.disabled).toBe(true)
    expect(row.find('[data-test="credential-dedicated-disabled-note"]').text()).toContain('新增憑證')
  })
})

// --- 8.3 升級說明卡 ---

describe('升級說明卡第三步', () => {
  const VERSION = '1.18.0'
  const stepIds = (w) => w.findAll('[data-step]').map((n) => n.attributes('data-step'))
  const sectionIds = (w) => w.findAll('[data-section]').map((n) => n.attributes('data-section'))

  async function mountDashboard() {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/:pathMatch(.*)*', component: { render: () => null } }],
    })
    router.push('/dashboard')
    await router.isReady()
    const wrapper = mount(Dashboard, { global: { plugins: [ElementPlus, router] }, attachTo: document.body })
    await flushPromises()
    return wrapper
  }

  beforeEach(() => {
    resetCapabilities()
    useUpgradeGuidance().reset()
    getGuidanceStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: false })
  })

  it('超管與只持 credential:view 者都渲染第三步與入口連結，文字不含數字', async () => {
    for (const perms of [permissionsFor(['admin']), ['credential:view']]) {
      useUpgradeGuidance().reset()
      setCapabilitiesForTests(perms, { userId: 1 })
      expect(canEnter(entryMeta('/credentials'))).toBe(true)
      const wrapper = await mountDashboard()
      expect(stepIds(wrapper)).toContain('credentialOwnership')
      const step = wrapper.find('[data-step="credentialOwnership"]')
      expect(step.text()).toContain('把共用憑證改歸到節點')
      expect(step.text()).not.toMatch(/\d/)
      expect(step.find('[data-link="/credentials"]').exists()).toBe(true)
      // 變更欄只說事實一次，連結不重複
      expect(sectionIds(wrapper).filter((s) => s === 'credentialOwnership')).toHaveLength(1)
      expect(wrapper.findAll('[data-link="/credentials"]')).toHaveLength(1)
    }
  })

  it('不持任何憑證語義鍵：不渲染第三步', async () => {
    setCapabilitiesForTests(['asset:view'], { userId: 1 })
    const wrapper = await mountDashboard()
    expect(stepIds(wrapper)).not.toContain('credentialOwnership')
    expect(sectionIds(wrapper)).not.toContain('credentialOwnership')
  })
})
