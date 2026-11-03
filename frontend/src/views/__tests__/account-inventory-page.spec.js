import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import ElementPlus from 'element-plus'
import AccountInventory from '../AccountInventory.vue'
import previewWrite from '@/directives/previewWrite'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { takeManagePrefill, stashManagePrefill } from '@/utils/inventoryManageHandoff'

// 全域主機帳號盤點頁：待處理清單、唯讀者、就地開抽屜、忽略、納管、空狀態與錯誤。

const listMock = vi.fn()
const getAssetMock = vi.fn()
const getInvMock = vi.fn()
vi.mock('@/api/hostInventory', () => ({
  listGlobalInventoryFindings: (...a) => listMock(...a),
  getAssetInventory: (...a) => getInvMock(...a),
  startInventoryScan: vi.fn(),
  reopenInventoryFinding: vi.fn(),
  ignoreInventoryFinding: vi.fn(),
}))
vi.mock('@/api/assets', () => ({
  getAsset: (...a) => getAssetMock(...a),
  getAssetHostKey: vi.fn().mockResolvedValue(null),
}))
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn().mockResolvedValue({ data: [{ id: 1, username: 'root', is_default: true }] }),
}))

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

const ignoreStub = {
  name: 'HostInventoryIgnoreDialog',
  props: ['modelValue', 'assetId', 'assetName', 'finding'],
  emits: ['done', 'gone', 'denied', 'update:modelValue'],
  template: '<div v-if="modelValue" class="ignore-stub" :data-asset="assetId" />',
}
const stubs = {
  HostInventoryIgnoreDialog: ignoreStub,
  'el-drawer': {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="drawer-stub"><slot name="header" /><slot /></div>',
  },
  'el-tooltip': { template: '<span><slot /></span>' },
  'el-popover': { template: '<span><slot name="reference" /><span><slot /></span></span>' },
  'el-collapse': { template: '<div><slot /></div>', props: ['modelValue'] },
  'el-collapse-item': { template: '<div><slot /></div>', props: ['title', 'name'] },
}

const ZWSP = String.fromCodePoint(0x200b)
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString()
const f = (o = {}) => ({
  id: 1, asset_id: 7, username: 'backup2', uid: '0', login_capable: true, privileged: true, incomplete: false,
  present: true, status: 'open', privileged_reasons: ['uid0'], first_seen_at: daysAgo(1), last_seen_at: daysAgo(0), ...o,
})
const body = (findings, total = findings.length) => ({ findings, total, page: 1, page_size: 20 })
const allow = { allowed: true }

async function mountPage(perms = ['asset:view', 'asset:update', 'account:discover']) {
  setCapabilitiesForTests(perms)
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/account-inventory', component: { template: '<i />' } },
      { path: '/assets', component: { template: '<i />' } },
    ],
  })
  router.push('/account-inventory')
  await router.isReady()
  const w = mount(AccountInventory, {
    global: { plugins: [ElementPlus, router], stubs, directives: { 'preview-write': previewWrite } },
  })
  await flushPromises()
  return { w, router }
}

beforeEach(() => {
  vi.clearAllMocks()
  resetCapabilities()
  stashManagePrefill(null)
  listMock.mockResolvedValue(body([f(), f({ id: 2, username: 'jenkins', privileged_reasons: ['sudoers_all'] })]))
  getAssetMock.mockResolvedValue({ id: 7, name: 'web-prod-01', host: '10.0.3.21', protocol: 'ssh', effective_rotation_channel: 'posix_ssh', actions: undefined })
  getInvMock.mockResolvedValue({ scan: null, coverage: [], fixed_notes: [], findings: [], total: 0, page: 1, page_size: 50 })
})
afterEach(() => resetCapabilities())

describe('全域主機帳號盤點頁：清單', () => {
  it('列出待處理帳號，資產名稱依識別去重只讀一次，並有通用不完整提醒', async () => {
    const { w } = await mountPage()
    expect(w.findAll('[data-test="ai-row"]')).toHaveLength(2)
    expect(w.text()).toContain('web-prod-01')
    expect(w.text()).toContain('10.0.3.21')
    expect(getAssetMock).toHaveBeenCalledTimes(1)
    expect(listMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(w.find('[data-test="ai-incomplete"]').exists()).toBe(true)
    expect(w.find('[data-test="ai-tab-open"]').text()).toContain('(2)')
  })

  it('含隱藏字元的帳號名以跳脫形式顯示', async () => {
    listMock.mockResolvedValue(body([f({ username: `dep${ZWSP}loy` })]))
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-row"]').text()).toContain('<U+200B>')
  })

  it('最近看到超過 30 天以警示色標示，三天前不標', async () => {
    listMock.mockResolvedValue(body([f({ id: 1, last_seen_at: daysAgo(51) }), f({ id: 2, last_seen_at: daysAgo(3) })]))
    const { w } = await mountPage()
    const cells = w.findAll('[data-test="ai-last"]')
    expect(cells[0].classes()).toContain('is-stale')
    expect(cells[0].text()).toContain('51')
    expect(cells[1].classes()).not.toContain('is-stale')
  })

  it('讀取不到資產名稱時退回「資產 #id」', async () => {
    getAssetMock.mockRejectedValue(new Error('x'))
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-asset"]').text()).toContain('#7')
  })

  it('超過一頁時顯示分頁，換頁送出對應頁碼', async () => {
    listMock.mockResolvedValue(body([f()], 45))
    const { w } = await mountPage()
    const pager = w.findComponent({ name: 'AppPagination' })
    expect(pager.exists()).toBe(true)
    pager.vm.$emit('current-change', 2)
    await flushPromises()
    expect(listMock).toHaveBeenLastCalledWith({ page: 2, page_size: 20 })
  })
})

describe('全域主機帳號盤點頁：空狀態與錯誤', () => {
  it('沒有待處理：中性空狀態、通用提醒仍在，不說全部都好', async () => {
    listMock.mockResolvedValue(body([]))
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-empty"]').exists()).toBe(true)
    expect(w.find('[data-test="ai-empty-incomplete"]').exists()).toBe(true)
    expect(w.find('[data-test="ai-table"]').exists()).toBe(false)
  })

  it('回應不帶不完整主機數：只顯示通用提醒，不顯示數量', async () => {
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-incomplete"]').text()).not.toMatch(/\d/)
  })

  it('讀取失敗：頁內錯誤條與重試，重試後恢復', async () => {
    listMock.mockRejectedValueOnce(new Error('x'))
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-error"]').exists()).toBe(true)
    await w.find('[data-test="ai-retry"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="ai-error"]').exists()).toBe(false)
    expect(w.findAll('[data-test="ai-row"]')).toHaveLength(2)
  })
})

describe('全域主機帳號盤點頁：權限', () => {
  it('唯讀者（稽核）：沒有納管與忽略，只有查看這台，且有唯讀說明', async () => {
    const { w } = await mountPage(['asset:view', 'ui:assets-global'])
    expect(w.find('[data-test="ai-readonly"]').exists()).toBe(true)
    expect(w.find('[data-test="ai-manage"]').exists()).toBe(false)
    expect(w.find('[data-test="ai-ignore"]').exists()).toBe(false)
    expect(w.find('[data-test="ai-view"]').exists()).toBe(true)
  })

  it('只持 asset:view＋asset:update、不持 account:discover：看不到納管與忽略', async () => {
    const { w } = await mountPage(['asset:view', 'asset:update', 'ui:assets-global'])
    expect(w.findAll('[data-test="ai-row"]').length).toBeGreaterThan(0)
    expect(w.find('[data-test="ai-manage"]').exists()).toBe(false)
    expect(w.find('[data-test="ai-ignore"]').exists()).toBe(false)
    expect(w.find('[data-test="ai-view"]').exists()).toBe(true)
  })

  it('持 account:discover、不持 asset:update：看不到納管，忽略仍在', async () => {
    const { w } = await mountPage(['asset:view', 'account:discover'])
    expect(w.find('[data-test="ai-manage"]').exists()).toBe(false)
    expect(w.find('[data-test="ai-ignore"]').exists()).toBe(true)
  })

  it('有權者：沒有唯讀說明，三個操作都在', async () => {
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-readonly"]').exists()).toBe(false)
    expect(w.find('[data-test="ai-manage"]').exists()).toBe(true)
    expect(w.find('[data-test="ai-ignore"]').exists()).toBe(true)
  })
})

describe('全域主機帳號盤點頁：欄位與無障礙', () => {
  it('時間欄如實標為最近看到；表頭有 scope、表格有標題、複製鈕有可讀名稱', async () => {
    const { w } = await mountPage()
    expect(w.find('[data-test="ai-col-last"]').text()).toBe('最近看到')
    expect(w.text()).not.toContain('最近盤點')
    const ths = w.findAll('[data-test="ai-table"] th')
    expect(ths.length).toBe(7)
    ths.forEach((th) => expect(th.attributes('scope')).toBe('col'))
    expect(w.find('[data-test="ai-caption"]').text()).toBe('待處理的主機帳號')
    expect(w.find('[data-test="ai-copy"]').attributes('aria-label')).toBe('複製帳號名')
  })
})

describe('全域主機帳號盤點頁：查看這台', () => {
  it('點資產名開抽屜不換頁，抽屜以 getAsset 取旗標（範圍化檢視者：旗標不可做時沒有發起鈕）', async () => {
    getAssetMock.mockResolvedValue({
      id: 7, name: 'web-prod-01', host: '10.0.3.21', protocol: 'ssh', effective_rotation_channel: 'posix_ssh',
      actions: { discover_accounts: { allowed: false, reason: 'out_of_scope' }, manage_accounts: { allowed: false, reason: 'out_of_scope' }, edit: { allowed: false, reason: 'out_of_scope' } },
    })
    const { w, router } = await mountPage()
    await w.find('[data-test="ai-asset"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/account-inventory')
    expect(w.find('.drawer-stub').exists()).toBe(true)
    expect(getInvMock).toHaveBeenCalledWith(7, expect.anything())
    expect(w.find('[data-test="inv-start"]').exists()).toBe(false)
  })
})

describe('全域主機帳號盤點頁：忽略', () => {
  it('忽略成功：該列就地移除、數字減一', async () => {
    const { w } = await mountPage()
    await w.findAll('[data-test="ai-ignore"]')[0].trigger('click')
    expect(w.find('.ignore-stub').attributes('data-asset')).toBe('7')
    w.findComponent({ name: 'HostInventoryIgnoreDialog' }).vm.$emit('done', { id: 1, status: 'ignored', reason: 'r' })
    await flushPromises()
    expect(w.findAll('[data-test="ai-row"]')).toHaveLength(1)
    expect(w.find('[data-test="ai-tab-open"]').text()).toContain('(1)')
  })
})

describe('全域主機帳號盤點頁：納管', () => {
  it('詳情 manage_accounts 不可做：不跳頁、不留暫存，就地說明', async () => {
    getAssetMock.mockResolvedValue({
      id: 7, name: 'web-prod-01', host: 'h', protocol: 'ssh',
      actions: { manage_accounts: { allowed: false, reason: 'out_of_scope' } },
    })
    const { w, router } = await mountPage()
    await w.find('[data-test="ai-manage"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/account-inventory')
    expect(takeManagePrefill(7)).toBeNull()
  })

  it('可做：寫一次性暫存並前往 /assets?edit=<id>，帳號名不在網址上', async () => {
    getAssetMock.mockResolvedValue({ id: 7, name: 'web-prod-01', host: 'h', protocol: 'ssh', actions: { manage_accounts: allow } })
    const { w, router } = await mountPage()
    const push = vi.spyOn(router, 'push')
    await w.find('[data-test="ai-manage"]').trigger('click')
    await flushPromises()
    expect(push).toHaveBeenCalledWith({ path: '/assets', query: { edit: '7' } })
    expect(JSON.stringify(push.mock.calls)).not.toContain('backup2')
    expect(router.currentRoute.value.path).toBe('/assets')
    expect(takeManagePrefill(7)).toMatchObject({ username: 'backup2', privileged: true })
    expect(takeManagePrefill(7)).toBeNull()
  })
})
