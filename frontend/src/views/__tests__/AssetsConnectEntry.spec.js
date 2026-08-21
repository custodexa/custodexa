import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'

// 自 Assets.spec.js 拆出（asset-syslog-debt-cleanup）：該檔已 32 案、掛載成本高，
// 每案 mount 完整頁面時整檔逼近逾時臨界（既有已知體質）。本檔獨立承載
// 「連線入口成因、延遲呈現、連測中態」三組行為，兩檔各自都能在時限內完成

// 本檔掛載後從不卸載，殘留元件在 document 上累積使單測耗時隨測試序上升
// ——全量並行時末幾格逼近逾時上限而轉紅（單跑穩綠）。與 Assets.spec.js／
// AuditLogs.spec.js 同型根因，治法相同：逐測卸載使成本不隨測試序遞增。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

// 全量高負載下偶發單測 5s 逾時（單跑穩綠）——負載型 flake 治標，非本檔測試不穩
// （慣例同 SessionDetail/AuditLogs/Alerts.spec.js）
vi.setConfig({ testTimeout: 20_000 })

const getAssetListMock = vi.fn()
const getAssetTagsMock = vi.fn()
const testAssetConnectionMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn(),
  resetAssetHostKey: vi.fn(),
  testAssetConnection: (...args) => testAssetConnectionMock(...args),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
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

const setUserRoles = (roles) => {
  localStorage.setItem('user', JSON.stringify({ id: 7, username: 'tester', roles }))
}

const mountView = () =>
  mount(Assets, {
    global: { plugins: [ElementPlus] },
  })


describe('Assets 入口成因與延遲呈現（asset-syslog-debt-cleanup）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAssetTagsMock.mockResolvedValue({ data: [] })
  })

  it('停用資產的連線入口提示指向停用成因，而非「權限不足」', async () => {
    setUserRoles(['admin'])
    const wrapper = mountView()
    await flushPromises()

    const tip = wrapper.vm.connectTooltipContent({ active: false, permission: 'connect' })
    // 與授權狀態欄同一鍵（assets.disabledTooltip），成因指向停用
    expect(tip).toBe(wrapper.vm.$t('assets.disabledTooltip'))
    expect(tip).toContain('停用')
    expect(tip).not.toContain('權限不足')
  })

  it('template 實際接線：停用列的操作欄 tooltip 取 disabledTooltip 且連線鈕 disabled', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [{ id: 1, name: 'disabled-a', protocol: 'ssh', host: 'h', port: 22, active: false }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    // 直接呼叫 helper 不足以證明 template 有接線——若日後 template 退回舊的
    // 二元表達式，helper 測試仍會綠。此案鎖定實際渲染出的 tooltip content
    const contents = wrapper.findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
      .filter((c) => typeof c === 'string' && c)
    const disabledTip = wrapper.vm.$t('assets.disabledTooltip')
    expect(contents).toContain(disabledTip)
    expect(contents).not.toContain(wrapper.vm.$t('assets.noPermTooltip'))

    // EP disabled button 帶 is-disabled class（happy-dom 下 disabled attribute
    // 不一定反映在 wrapper.attributes）
    const connectBtns = wrapper.findAll('button').filter((b) => b.text().includes('連線'))
    expect(connectBtns.length).toBeGreaterThan(0)
    expect(
      connectBtns.some((b) => b.classes().includes('is-disabled') || b.attributes('disabled') !== undefined)
    ).toBe(true)
  }, 15000)

  it('一般 user 對啟用但無 connect 授權的資產，提示指向權限成因', async () => {
    setUserRoles(['user'])
    const wrapper = mountView()
    await flushPromises()

    const tip = wrapper.vm.connectTooltipContent({ active: true, permission: 'view' })
    expect(tip).toBe(wrapper.vm.$t('assets.noPermTooltip'))
    expect(tip).not.toContain('停用')
  })

  it('可連資產提示為連線引導（三態不互相汙染）', async () => {
    setUserRoles(['user'])
    const wrapper = mountView()
    await flushPromises()

    const tip = wrapper.vm.connectTooltipContent({ active: true, permission: 'connect' })
    expect(tip).toBe(wrapper.vm.$t('assets.connectTooltip'))
    expect(tip).not.toContain('權限不足')
    expect(tip).not.toContain('停用')
  })

  it('auditor 無顯式授權（permission=view）：連線鈕禁用且提示權限成因', async () => {
    setUserRoles(['auditor'])
    getAssetListMock.mockResolvedValue({
      data: [{ id: 1, name: 'no-grant', protocol: 'ssh', host: 'h', port: 22, active: true, permission: 'view' }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    // 執行期 auditor 無角色自動 connect（CPG-002）——入口不得再裝可連
    //（auditor-connect-entry-honesty；helper＋template 實接雙軌鎖定）
    expect(wrapper.vm.canConnect({ active: true, permission: 'view' })).toBe(false)
    const contents = wrapper.findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
      .filter((c) => typeof c === 'string' && c)
    expect(contents).toContain(wrapper.vm.$t('assets.noPermTooltip'))
    const connectBtns = wrapper.findAll('button').filter((b) => b.text().includes('連線'))
    expect(connectBtns.length).toBeGreaterThan(0)
    expect(
      connectBtns.some((b) => b.classes().includes('is-disabled') || b.attributes('disabled') !== undefined)
    ).toBe(true)
  }, 15000)

  it('auditor 持顯式 connect grant（CPG-002 D1 例外通道）：連線入口可用', async () => {
    setUserRoles(['auditor'])
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.vm.canConnect({ active: true, permission: 'connect' })).toBe(true)
    expect(wrapper.vm.connectTooltipContent({ active: true, permission: 'connect' }))
      .toBe(wrapper.vm.$t('assets.connectTooltip'))
  })

  it('admin 角色短路保留：無 permission 欄仍可連（回應形狀凍結）', async () => {
    setUserRoles(['admin'])
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.vm.canConnect({ active: true })).toBe(true)
  })

  it('延遲缺值：徽章顯示佔位符不輸出 nullms', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [{
        id: 1, name: 'no-latency', protocol: 'ssh', host: 'h', port: 22, active: true,
        last_test_status: 'reachable', last_test_latency_ms: null, last_test_at: '2026-07-20T00:00:00Z',
      }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).not.toContain('nullms')
    expect(wrapper.text()).not.toContain('undefinedms')
    expect(wrapper.find('.conn-badge.ok').text()).toContain('-')
    expect(wrapper.vm.latencyText(null)).toBe('-')
    expect(wrapper.vm.latencyText(undefined)).toBe('-')
  })

  it('tooltip 保留完整延遲值且單位不重複（徽章短格式不外溢）', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'fast', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'reachable', last_test_latency_ms: 12, last_test_at: '2026-07-20T00:00:00Z' },
        { id: 2, name: 'slow', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'reachable', last_test_latency_ms: 12000, last_test_at: '2026-07-20T00:00:00Z' },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    const badges = wrapper.findAll('.conn-badge.ok').map((b) => b.text())
    expect(badges[0]).toContain('12ms')
    expect(badges[1]).toContain('>9s')

    // tooltip 內容取自 el-tooltip 的 content prop（happy-dom 不觸發 hover 浮層）
    const tips = wrapper.findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
      .filter((c) => typeof c === 'string' && c.includes('延遲'))
    expect(tips.some((c) => c.includes('12000ms'))).toBe(true)
    // 單位不得重複：套用徽章短格式會產生 12msms／>9sms
    for (const c of tips) {
      expect(c).not.toContain('msms')
      expect(c).not.toContain('>9sms')
    }
  })

  it('延遲缺值時 tooltip 退用不帶延遲的文案（不顯示破碎字串）', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [{
        id: 1, name: 'no-latency', protocol: 'ssh', host: 'h', port: 22, active: true,
        last_test_status: 'reachable', last_test_latency_ms: null, last_test_at: '2026-07-20T00:00:00Z',
      }],
      total: 1, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    const tips = wrapper.findAllComponents({ name: 'ElTooltip' })
      .map((c) => c.props('content'))
      .filter((c) => typeof c === 'string' && c.includes('測於'))
    expect(tips.length).toBeGreaterThan(0)
    for (const c of tips) {
      expect(c).not.toContain('延遲')
      expect(c).not.toContain('nullms')
    }
  })

  it('測試中態持續至列表重載完成，不回退顯示上一次結果', async () => {
    setUserRoles(['admin'])
    const stale = {
      data: [{
        id: 1, name: 'a1', protocol: 'ssh', host: 'h', port: 22, active: true,
        last_test_status: 'unreachable', last_test_at: '2026-07-20T00:00:00Z',
      }],
      total: 1, page: 1, page_size: 20,
    }
    getAssetListMock.mockResolvedValue(stale)
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('.conn-badge.fail').exists()).toBe(true)

    // 連測回應已返回，但列表重載仍 pending
    testAssetConnectionMock.mockResolvedValue({ success: true, latency_ms: 5 })
    let releaseList
    getAssetListMock.mockReturnValue(new Promise((resolve) => {
      releaseList = () => resolve({
        data: [{
          id: 1, name: 'a1', protocol: 'ssh', host: 'h', port: 22, active: true,
          last_test_status: 'reachable', last_test_latency_ms: 5, last_test_at: '2026-07-21T00:00:00Z',
        }],
        total: 1, page: 1, page_size: 20,
      })
    }))

    const done = wrapper.vm.handleTest({ id: 1 })
    await flushPromises()

    // 關鍵：此刻 spinner 仍在，不得已經退回舊的「不可達」徽章
    expect(wrapper.find('.conn-badge.testing').exists()).toBe(true)
    expect(wrapper.find('.conn-badge.fail').exists()).toBe(false)

    releaseList()
    await done
    await flushPromises()

    expect(wrapper.find('.conn-badge.testing').exists()).toBe(false)
    expect(wrapper.find('.conn-badge.ok').text()).toContain('5ms')
  }, 15000)
})

describe('Assets 連測逐列中態（db-protocol-connection-test 4.3）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAssetTagsMock.mockResolvedValue({ data: [] })
  })

  // 原斷言是「第二列被 single-flight 擋下」（asset-syslog-debt-cleanup 實作審查 M1）。
  // db-protocol-connection-test 4.3 起中態改為 id 集合：擋的是**同一列**重複觸發，
  // 不同列可並行且各自解除——先完成者只從集合移除自己，不會清掉他列的 spinner。
  it('不同列可並行測試、各自解除；同一列重複觸發被擋下', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'a1', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'unreachable', last_test_at: '2026-07-20T00:00:00Z' },
        { id: 2, name: 'a2', protocol: 'ssh', host: 'h', port: 22, active: true, last_test_status: 'unreachable', last_test_at: '2026-07-20T00:00:00Z' },
      ],
      total: 2, page: 1, page_size: 20,
    })
    const wrapper = mountView()
    await flushPromises()

    // 第一筆：連測回應懸置
    let releaseTest
    testAssetConnectionMock.mockReturnValue(new Promise((resolve) => {
      releaseTest = () => resolve({ success: true, latency_ms: 5 })
    }))
    const first = wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(wrapper.vm.isTesting(1)).toBe(true)

    // 同一列重複觸發：被擋下，不重複打端點
    await wrapper.vm.handleTest({ id: 1 })
    expect(testAssetConnectionMock).toHaveBeenCalledTimes(1)

    // 另一列在第一筆未完成時觸發：不被擋，兩列同時處於測試中態
    const second = wrapper.vm.handleTest({ id: 2 })
    await flushPromises()
    expect(testAssetConnectionMock).toHaveBeenCalledTimes(2)
    expect(wrapper.vm.isTesting(1)).toBe(true)
    expect(wrapper.vm.isTesting(2)).toBe(true)

    releaseTest()
    await first
    await second
    await flushPromises()
    expect(wrapper.vm.isTesting(1)).toBe(false)
    expect(wrapper.vm.isTesting(2)).toBe(false)
  }, 15000)
})
