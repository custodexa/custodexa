import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import Workspace from '../Workspace.vue'
import { getAsset } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// 會話元件以 stub 取代：工作區測試聚焦頁籤狀態邏輯
vi.mock('@/components/SshTerminal.vue', () => ({
  default: { name: 'SshTerminal', props: ['assetId'], template: '<div class="stub-ssh" />' },
}))
vi.mock('@/components/GuacamoleClient.vue', () => ({
  default: { name: 'GuacamoleClient', props: ['assetId', 'protocol', 'assetName'], template: '<div class="stub-guac" />' },
}))
vi.mock('@/components/FileManager.vue', () => ({
  default: {
    name: 'FileManager',
    props: ['assetId', 'modelValue', 'sessionId', 'accountUsername'],
    template: '<div />',
  },
}))
vi.mock('@/components/SnippetDrawer.vue', () => ({
  default: { name: 'SnippetDrawer', props: ['modelValue'], template: '<div />' },
}))
vi.mock('@/components/SessionStatsPanel.vue', () => ({
  default: { name: 'SessionStatsPanel', props: ['modelValue', 'sessionId'], template: '<div />' },
}))
vi.mock('@/components/ShareDialog.vue', () => ({
  default: { name: 'ShareDialog', props: ['modelValue', 'sessionId'], template: '<div />' },
}))
vi.mock('@/components/TerminalWatermark.vue', () => ({
  default: { name: 'TerminalWatermark', template: '<div />' },
}))
// 兩個連線前選擇器各有專屬 spec；此處以 stub 取代——真 el-table 在
// happy-dom 下的 MutationObserver 會拋未捕捉例外污染同檔後續案例
vi.mock('@/components/K8sPodSelector.vue', () => ({
  default: {
    name: 'K8sPodSelector',
    props: ['modelValue', 'assetId', 'assetName', 'assetNamespace'],
    template: '<div class="stub-pod-selector" />',
  },
}))
vi.mock('@/components/AccountSelector.vue', () => ({
  default: {
    name: 'AccountSelector',
    props: ['modelValue', 'assetName', 'accounts'],
    template: '<div class="stub-account-selector" />',
  },
}))

const routeQuery = { asset: undefined }
vi.mock('vue-router', () => ({
  useRoute: () => ({ query: routeQuery }),
}))

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({
    data: [
      { id: 1, name: 'ssh-a', protocol: 'ssh', active: true },
      { id: 77, name: 'vnc-a', protocol: 'vnc', active: true },
    ],
    total: 2,
  }),
  getAsset: vi.fn(),
}))

// 多帳號：openTab 開籤前查有效授權帳號，
// 預設回零帳號＝維持既有直連行為
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn() }))

const mountWorkspace = () =>
  mount(Workspace, { global: { plugins: [ElementPlus] } })

describe('Workspace 頁籤邏輯', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routeQuery.asset = undefined
    localStorage.clear()
    listAssetAccounts.mockResolvedValue({ data: [], total: 0 })
  })

  // 連線面在 MainLayout 之外，工作區頂欄須有自己的切換入口；
  // 切語言就地重繪（同一 wrapper、頁籤/連線元件不重建）
  it('頂欄語言切換就地換語且不重建頁籤（免 reload 不斷線）', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()
    expect(wrapper.vm.tabs.length).toBe(1)
    expect(wrapper.find('.workspace-hint').text()).toBe('工作區')

    const langDropdown = wrapper
      .findAllComponents({ name: 'ElDropdown' })
      .find((d) => d.find('.workspace-lang-label').exists())
    expect(langDropdown, '工作區頂欄應有語言切換').toBeTruthy()
    langDropdown.vm.$emit('command', 'en-US')
    await wrapper.vm.$nextTick()

    expect(wrapper.find('.workspace-hint').text()).toBe('Workspace')
    expect(localStorage.getItem('ot-lang')).toBe('en-US')
    // 頁籤與會話 stub 未重建＝連線不因換語重掛
    expect(wrapper.vm.tabs.length).toBe(1)
    expect(wrapper.find('.stub-ssh').exists()).toBe(true)
  })

  it('開籤即啟用；同資產可多開', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()

    wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()

    expect(wrapper.vm.tabs).toHaveLength(2)
    expect(wrapper.vm.activeKey).toBe(wrapper.vm.tabs[1].key)
    expect(wrapper.findAll('.stub-ssh')).toHaveLength(2)
    wrapper.unmount()
  })

  it('關閉目前頁籤切到鄰近籤，其餘保留', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    wrapper.vm.openTab({ id: 77, name: 'vnc-a', protocol: 'vnc' })
    await flushPromises()
    const [first, second] = wrapper.vm.tabs

    wrapper.vm.closeTab(second.key)
    await flushPromises()

    expect(wrapper.vm.tabs).toHaveLength(1)
    expect(wrapper.vm.activeKey).toBe(first.key)
    wrapper.unmount()
  })

  it('?asset= 自動開啟首個頁籤', async () => {
    routeQuery.asset = '77'
    getAsset.mockResolvedValue({ id: 77, name: 'vnc-a', protocol: 'vnc' })

    const wrapper = mountWorkspace()
    await flushPromises()

    expect(getAsset).toHaveBeenCalledWith('77')
    expect(wrapper.vm.tabs).toHaveLength(1)
    expect(wrapper.vm.tabs[0].protocol).toBe('vnc')
    wrapper.unmount()
  })

  it('切換頁籤以 v-show 保活：非目前頁籤元件仍掛載', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    wrapper.vm.openTab({ id: 77, name: 'vnc-a', protocol: 'vnc' })
    await flushPromises()

    // 兩個會話元件都在 DOM（保活），且恰有一個面板被 v-show 隱藏
    expect(wrapper.findAll('.stub-ssh')).toHaveLength(1)
    expect(wrapper.findAll('.stub-guac')).toHaveLength(1)
    const panels = wrapper.findAll('.tab-panel')
    expect(panels).toHaveLength(2)
    const hidden = panels.filter((p) => (p.attributes('style') || '').includes('display: none'))
    expect(hidden).toHaveLength(1)
    wrapper.unmount()
  })
})


describe('Workspace 頁籤右鍵選單', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routeQuery.asset = undefined
    localStorage.clear()
    listAssetAccounts.mockResolvedValue({ data: [], total: 0 })
  })

  async function withThreeTabs() {
    const wrapper = mountWorkspace()
    await flushPromises()
    wrapper.vm.openTab({ id: 1, name: 'a', protocol: 'ssh' })
    wrapper.vm.openTab({ id: 1, name: 'b', protocol: 'ssh' })
    wrapper.vm.openTab({ id: 77, name: 'c', protocol: 'vnc' })
    await flushPromises()
    return wrapper
  }

  it('右鍵開啟選單並記錄目標 key', async () => {
    const wrapper = await withThreeTabs()
    wrapper.vm.openTabMenu({ clientX: 10, clientY: 20 }, wrapper.vm.tabs[1].key)
    expect(wrapper.vm.tabMenu.visible).toBe(true)
    expect(wrapper.vm.tabMenu.key).toBe(wrapper.vm.tabs[1].key)
  })

  it('重新連線遞增 epoch 並標記 connecting，其他頁籤不動', async () => {
    const wrapper = await withThreeTabs()
    const target = wrapper.vm.tabs[0]
    wrapper.vm.openTabMenu({ clientX: 0, clientY: 0 }, target.key)
    wrapper.vm.menuReconnect()
    expect(wrapper.vm.tabs[0].epoch).toBe(1)
    expect(wrapper.vm.tabs[0].status).toBe('connecting')
    expect(wrapper.vm.tabs[1].epoch).toBeUndefined()
    expect(wrapper.vm.tabMenu.visible).toBe(false)
  })

  it('複製會話以同資產開新籤並啟用', async () => {
    const wrapper = await withThreeTabs()
    const target = wrapper.vm.tabs[2]
    wrapper.vm.openTabMenu({ clientX: 0, clientY: 0 }, target.key)
    wrapper.vm.menuDuplicate()
    expect(wrapper.vm.tabs).toHaveLength(4)
    const newTab = wrapper.vm.tabs[3]
    expect(newTab.assetId).toBe(77)
    expect(newTab.protocol).toBe('vnc')
    expect(wrapper.vm.activeKey).toBe(newTab.key)
  })

  it('關閉其他僅留目標', async () => {
    const wrapper = await withThreeTabs()
    const target = wrapper.vm.tabs[1]
    wrapper.vm.openTabMenu({ clientX: 0, clientY: 0 }, target.key)
    wrapper.vm.menuCloseOthers()
    expect(wrapper.vm.tabs.map((t) => t.key)).toEqual([target.key])
    expect(wrapper.vm.activeKey).toBe(target.key)
  })

  it('關閉右側後 active 退至目標', async () => {
    const wrapper = await withThreeTabs()
    const target = wrapper.vm.tabs[0]
    wrapper.vm.activeKey = wrapper.vm.tabs[2].key
    wrapper.vm.openTabMenu({ clientX: 0, clientY: 0 }, target.key)
    wrapper.vm.menuCloseRight()
    expect(wrapper.vm.tabs).toHaveLength(1)
    expect(wrapper.vm.activeKey).toBe(target.key)
  })

  it('關閉全部清空', async () => {
    const wrapper = await withThreeTabs()
    wrapper.vm.openTabMenu({ clientX: 0, clientY: 0 }, wrapper.vm.tabs[0].key)
    wrapper.vm.menuCloseAll()
    expect(wrapper.vm.tabs).toHaveLength(0)
    expect(wrapper.vm.activeKey).toBe('')
  })
})

// 多帳號連線：開籤前的帳號分流
describe('Workspace 多帳號連線', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routeQuery.asset = undefined
    localStorage.clear()
    listAssetAccounts.mockResolvedValue({ data: [], total: 0 })
  })

  it('有效帳號兩個以上時開籤前彈選擇器，不直接建籤', async () => {
    listAssetAccounts.mockResolvedValue({
      data: [
        { id: 1, username: 'app', is_default: true },
        { id: 2, username: 'root', is_default: false, privileged: true },
      ],
    })
    const wrapper = mountWorkspace()
    await flushPromises()

    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()

    expect(wrapper.vm.accountSelectorVisible).toBe(true)
    expect(wrapper.vm.tabs).toHaveLength(0)

    wrapper.vm.onAccountSelected({ id: 2, username: 'root' })
    await flushPromises()
    expect(wrapper.vm.tabs).toHaveLength(1)
    expect(wrapper.vm.tabs[0].accountId).toBe(2)
    expect(wrapper.vm.tabs[0].accountUsername).toBe('root')
  })

  it('有效帳號僅一個時直連不打擾，且帶上該帳號', async () => {
    listAssetAccounts.mockResolvedValue({ data: [{ id: 9, username: 'app', is_default: true }] })
    const wrapper = mountWorkspace()
    await flushPromises()

    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()

    expect(wrapper.vm.accountSelectorVisible).toBe(false)
    expect(wrapper.vm.tabs).toHaveLength(1)
    expect(wrapper.vm.tabs[0].accountId).toBe(9)
  })

  it('K8s 一律先走 pod 選擇器，不查帳號（固定單一預設帳號）', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()

    await wrapper.vm.openTab({ id: 5, name: 'k8s-a', protocol: 'k8s' })
    await flushPromises()

    expect(wrapper.vm.podSelectorVisible).toBe(true)
    expect(wrapper.vm.accountSelectorVisible).toBe(false)
    expect(listAssetAccounts).not.toHaveBeenCalled()
  })

  it('帳號清單查詢失敗時退回預設帳號直連，且明示不靜默', async () => {
    listAssetAccounts.mockRejectedValue(new Error('boom'))
    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    const wrapper = mountWorkspace()
    await flushPromises()

    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()

    expect(wrapper.vm.tabs).toHaveLength(1)
    expect(wrapper.vm.tabs[0].accountId).toBe(null)
    // 使用者有權知道自己是以預設（通常特權）帳號連上的
    expect(warnSpy).toHaveBeenCalledWith('無法取得帳號清單，本次將以預設帳號連線')
    warnSpy.mockRestore()
  })

  it('挑過帳號的分頁標題附 `@帳號`；單帳號直連沿用純資產名', async () => {
    listAssetAccounts.mockResolvedValue({
      data: [
        { id: 3, username: 'root', is_default: true },
        { id: 4, username: 'app', is_default: false },
      ],
    })
    const wrapper = mountWorkspace()
    await flushPromises()

    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()
    wrapper.vm.onAccountSelected({ id: 4, username: 'app' })
    await flushPromises()
    expect(wrapper.vm.tabLabel(wrapper.vm.tabs[0])).toBe('ssh-a@app')

    // 單帳號資產：migration 後幾乎都有 default account，無條件附加會讓
    // 所有標題變成 `web-01@root`，稀釋「非預設身分」的訊號
    listAssetAccounts.mockResolvedValue({ data: [{ id: 3, username: 'root', is_default: true }] })
    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()
    expect(wrapper.vm.tabs[1].accountId).toBe(3)
    expect(wrapper.vm.tabLabel(wrapper.vm.tabs[1])).toBe('ssh-a')
  })

  it('連點兩個多帳號資產：選擇器的 pending 槽位以後發者為準（latest-request-wins）', async () => {
    const twoAccounts = (prefix) => ({
      data: [
        { id: 1, username: `${prefix}-a`, is_default: true },
        { id: 2, username: `${prefix}-b`, is_default: false },
      ],
    })
    let resolveFirst
    listAssetAccounts
      .mockImplementationOnce(() => new Promise((r) => { resolveFirst = r }))
      .mockResolvedValueOnce(twoAccounts('vnc'))

    const wrapper = mountWorkspace()
    await flushPromises()

    const first = wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    const second = wrapper.vm.openTab({ id: 77, name: 'vnc-a', protocol: 'vnc' })
    await second
    // 慢的先發者回來了，但已非最新請求——不得把選擇器改回 A 的資產與帳號
    resolveFirst(twoAccounts('ssh'))
    await first
    await flushPromises()

    expect(wrapper.vm.pendingAccountAsset.id).toBe(77)
    expect(wrapper.vm.pendingAccounts.map((a) => a.username)).toEqual(['vnc-a', 'vnc-b'])
  })

  it('連開多個單帳號資產：各自開籤，不因後發者取消（開籤非競態）', async () => {
    listAssetAccounts.mockResolvedValue({ data: [{ id: 9, username: 'ops', is_default: true }] })
    const wrapper = mountWorkspace()
    await flushPromises()

    await Promise.all([
      wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' }),
      wrapper.vm.openTab({ id: 77, name: 'vnc-a', protocol: 'vnc' }),
    ])
    await flushPromises()

    expect(wrapper.vm.tabs.map((t) => t.assetId).sort()).toEqual([1, 77])
  })

  it('自會話分頁的檔案管理帶該 session 與其帳號（帳號沿用）', async () => {
    listAssetAccounts.mockResolvedValue({
      data: [
        { id: 3, username: 'root', is_default: true },
        { id: 4, username: 'app', is_default: false },
      ],
    })
    const wrapper = mountWorkspace()
    await flushPromises()

    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()
    wrapper.vm.onAccountSelected({ id: 4, username: 'app' })
    await flushPromises()
    wrapper.vm.tabs[0].sessionId = 55
    await flushPromises()

    const fm = wrapper.findComponent({ name: 'FileManager' })
    expect(fm.props('sessionId')).toBe(55)
    expect(fm.props('accountUsername')).toBe('app')
  })

  it('複製分頁沿用原帳號，不再問一次', async () => {
    listAssetAccounts.mockResolvedValue({ data: [{ id: 4, username: 'ops', is_default: true }] })
    const wrapper = mountWorkspace()
    await flushPromises()
    await wrapper.vm.openTab({ id: 1, name: 'ssh-a', protocol: 'ssh' })
    await flushPromises()

    listAssetAccounts.mockClear()
    wrapper.vm.openTabMenu({ clientX: 0, clientY: 0 }, wrapper.vm.tabs[0].key)
    wrapper.vm.menuDuplicate()

    expect(wrapper.vm.tabs).toHaveLength(2)
    expect(wrapper.vm.tabs[1].accountId).toBe(4)
    expect(listAssetAccounts).not.toHaveBeenCalled()
  })
})
