// 審核中心被直達：以網址直接開啟審核中心的指定頁籤與單據。
//
// tab 與 request 各自判斷；找得到時切頁籤、標示、焦點落在列容器、待審展開逐項區；
// 待審與待補審找不到時只用網址上的編號說明（含清單上限一句）並提供「查看歷史」，不另外查這張單；
// 載入失敗與 403 不顯示說明；手動切頁籤移除 request；只有歷史資格者只有歷史頁籤。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import { createRouter, createMemoryHistory } from 'vue-router'
import Approvals from '../Approvals.vue'
import PerItemApproval from '@/components/access-request/PerItemApproval.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { parseApprovalsDirect, directInitialTab } from '@/components/access-request/approvalsDirect'
import { t } from '@/i18n'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
// 第 201 張的情境要渲染 200 列，整套並行時單測耗時會被拉長
vi.setConfig({ testTimeout: 20_000 })

// 申請 API 的每一個匯出都換成計數用的替身：用來斷言「沒有額外查這張單、沒有任何核決請求」
const api = vi.hoisted(() => ({}))
vi.mock('@/api/accessRequests', async (importOriginal) => {
  const actual = await importOriginal()
  const out = {}
  for (const name of Object.keys(actual)) {
    api[name] = vi.fn().mockResolvedValue({ data: [], total: 0 })
    out[name] = (...a) => api[name](...a)
  }
  return out
})
const assets = vi.hoisted(() => ({ getAsset: vi.fn(), listAssetAccounts: vi.fn() }))
vi.mock('@/api/assets', () => ({ getAsset: (...a) => assets.getAsset(...a) }))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: (...a) => assets.listAssetAccounts(...a) }))

const pendingRow = (id) => ({
  id,
  requester_id: 5,
  requester: { id: 5, username: 'chen.wei' },
  status: 'pending',
  reason: '例行維護',
  requested_duration_minutes: 240,
  created_at: '2026-11-20T17:02:00+08:00',
  items: [
    { id: id * 10 + 1, asset_id: 1, accounts: [], status: 'pending' },
    { id: id * 10 + 2, asset_id: 2, accounts: [], status: 'pending' },
  ],
})
const reviewRow = (id) => ({
  id,
  kind: 'break_glass',
  requester_id: 6,
  requester: { username: 'chen.wei' },
  asset_id: 7,
  asset: { name: 'db-prod-07' },
  reason: '緊急',
  created_at: '2026-11-20T03:12:00+08:00',
})
const historyRow = (id) => ({
  id,
  requester: { username: 'chen.wei' },
  asset: { name: 'web-prod-03' },
  status: 'approved',
  decided_at: '2026-11-20T17:06:00+08:00',
  items: [],
})

// 呼叫過、但不在允許清單內的申請 API（展開逐項區時讀的資產名稱與帳號不在這個模組）
const callsOutside = (allowed) =>
  Object.entries(api).filter(([name, fn]) => !allowed.includes(name) && fn.mock.calls.length > 0).map(([name]) => name)

const setUrl = (search) => window.history.replaceState({}, '', `/approvals${search}`)
const mountView = () => mount(Approvals, { global: { plugins: [ElementPlus] }, attachTo: document.body })

const directRow = (wrapper) => wrapper.find('tr.direct-row')
const notFound = (wrapper) => wrapper.find('[data-test="direct-not-found"]')
const activeTabName = (wrapper) => wrapper.find('.el-tabs__item.is-active').attributes('id')

beforeEach(() => {
  vi.clearAllMocks()
  for (const fn of Object.values(api)) fn.mockResolvedValue({ data: [], total: 0 })
  api.getPendingAccessRequests.mockResolvedValue({ data: [pendingRow(14), pendingRow(12), pendingRow(11)] })
  api.getPendingReviews.mockResolvedValue({ data: [reviewRow(9)] })
  api.getAccessRequestHistory.mockResolvedValue({ data: [historyRow(13), historyRow(12)], total: 2 })
  api.getPendingAccessRequestCount.mockResolvedValue({ count: 3, review_count: 1 })
  assets.getAsset.mockResolvedValue({ name: 'web-prod-03', protocol: 'ssh' })
  assets.listAssetAccounts.mockResolvedValue({ data: [] })
})
afterEach(() => {
  resetCapabilities()
  window.history.replaceState({}, '', '/')
  ElMessage.closeAll()
  document.body.querySelectorAll('.el-message').forEach((n) => n.remove())
})

describe('參數解析（各自判斷，不合格單獨忽略）', () => {
  it.each([
    ['?tab=pending&request=42', { tab: 'pending', request: 42 }],
    ['?request=42&request=43', { tab: null, request: 42 }],
    ['?request[]=42', { tab: null, request: null }],
    ['?tab=pending&request=012', { tab: 'pending', request: null }],
    ['?tab=pending&request=0', { tab: 'pending', request: null }],
    ['?tab=pending&request=-3', { tab: 'pending', request: null }],
    ['?tab=pending&request=1.5', { tab: 'pending', request: null }],
    ['?tab=pending&request=12345678901', { tab: 'pending', request: null }],
    ['?tab=pending&request=1234567890', { tab: 'pending', request: 1234567890 }],
    ['?tab=abc&request=12', { tab: null, request: 12 }],
    ['?tab=PENDING&request=12', { tab: null, request: 12 }],
    ['?tab=pending&tab=history', { tab: 'pending', request: null }],
  ])('%s', (search, want) => {
    expect(parseApprovalsDirect(search)).toEqual(want)
  })

  it('頁籤決定：只有歷史資格者一律歷史；頁籤缺席而有單號落歷史；都沒有用預設', () => {
    expect(directInitialTab({ tab: 'pending', request: 12 }, { historyOnly: true })).toBe('history')
    expect(directInitialTab({ tab: null, request: 12 }, { historyOnly: false })).toBe('history')
    expect(directInitialTab({ tab: 'reviews', request: null }, { historyOnly: false })).toBe('reviews')
    expect(directInitialTab({ tab: null, request: null }, { historyOnly: false })).toBe('pending')
  })
})

describe('以網址直達待審的單', () => {
  it('(a) 找得到：待審頁籤、列加標示、展開逐項區、沒有預選、焦點在列容器', async () => {
    setUrl('?tab=pending&request=12')
    const wrapper = mountView()
    await flushPromises()

    expect(activeTabName(wrapper)).toBe('tab-pending')
    const row = directRow(wrapper)
    expect(row.exists()).toBe(true)
    expect(row.text()).toContain('12')
    // 只展開這一張，而且是唯讀內容：沒有進入逐項調整、沒有任何決定被預選
    const reviews = wrapper.findAllComponents(PerItemApproval)
    expect(reviews).toHaveLength(1)
    expect(reviews[0].props('request').id).toBe(12)
    expect(reviews[0].attributes('data-mode')).toBe('read')
    expect(reviews[0].find('input[type="radio"]').exists()).toBe(false)
    for (const form of Object.values(reviews[0].vm.forms)) expect(form.action || '').toBe('')
    // 標示涵蓋列與展開內容，展開區第一行說明從通知連結進來
    expect(wrapper.get('[data-test="expand-sticky"]').classes()).toContain('direct-expanded')
    expect(reviews[0].get('[data-test="direct-label"]').text()).toBe('你從通知連結進來的申請')
    // 同一張申請只有一組決定入口：列上改為指向下方
    expect(row.find('[data-test="ops-below"]').exists()).toBe(true)
    expect(row.find('[data-test="row-approve"]').exists()).toBe(false)
    // 沒有開啟任何決定對話框
    expect(wrapper.vm.singleTarget).toBeNull()
    // (f) 焦點在列容器，不是按鈕、連結或表單控件
    const active = document.activeElement
    expect(active).toBe(row.element)
    expect(active.tagName).toBe('TR')
    expect(active.getAttribute('tabindex')).toBe('-1')
    expect(notFound(wrapper).exists()).toBe(false)
  })

  it('(f) 焦點在列上按 Enter 不發出任何請求、不開任何對話框', async () => {
    setUrl('?tab=pending&request=12')
    const wrapper = mountView()
    await flushPromises()
    const before = Object.fromEntries(Object.entries(api).map(([k, fn]) => [k, fn.mock.calls.length]))
    document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    document.activeElement.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', bubbles: true }))
    await flushPromises()
    const after = Object.fromEntries(Object.entries(api).map(([k, fn]) => [k, fn.mock.calls.length]))
    expect(after).toEqual(before)
    expect(wrapper.vm.singleTarget).toBeNull()
    expect(document.body.querySelector('.el-dialog')).toBeNull()
  })

  it('(a)(d) 已被處理（不在待審清單）：說明含清單上限一句與「查看歷史」，不另外查這張單、沒有核決請求', async () => {
    setUrl('?tab=pending&request=99')
    const wrapper = mountView()
    await flushPromises()

    const box = notFound(wrapper)
    expect(box.exists()).toBe(true)
    expect(box.text()).toContain(t('approvals.directNotFoundPending', { id: 99 }))
    expect(box.text()).toContain('200')
    // 規格列舉的原因：已被處理、撤回、逾期、不在檢視者的範圍內、超出清單的顯示上限
    expect(box.text()).toContain('不在你的審核範圍內')
    expect(box.text()).toContain(t('approvals.viewHistory'))
    // 不宣稱已被處理、不出現單的內容
    expect(box.text()).not.toContain('已被處理')
    expect(directRow(wrapper).exists()).toBe(false)
    expect(api.getPendingAccessRequests).toHaveBeenCalledTimes(1)
    expect(api.getAccessRequestHistory).toHaveBeenCalledTimes(0)
    expect(callsOutside(['getPendingAccessRequests', 'getPendingAccessRequestCount'])).toEqual([])
  })

  it('(d) 不存在的單號與不在範圍的單號畫面相同（都只依網址上的編號）', async () => {
    setUrl('?tab=pending&request=99')
    const a = mountView()
    await flushPromises()
    const textA = notFound(a).text()
    a.unmount()
    // 換一個「存在但不在他範圍」的編號：清單回應相同，畫面只差編號
    setUrl('?tab=pending&request=98')
    const b = mountView()
    await flushPromises()
    expect(notFound(b).text()).toBe(textA.replace('99', '98'))
  })

  it('(e) 第 201 張（清單上限 200 張之外）：落到含清單上限一句的說明', async () => {
    const twoHundred = Array.from({ length: 200 }, (_, i) => pendingRow(1000 + i))
    api.getPendingAccessRequests.mockResolvedValue({ data: twoHundred })
    api.getPendingAccessRequestCount.mockResolvedValue({ count: 201, review_count: 0 })
    setUrl('?tab=pending&request=1200')
    const wrapper = mountView()
    await flushPromises()
    expect(notFound(wrapper).text()).toContain(t('approvals.directNotFoundPending', { id: 1200 }))
    expect(callsOutside(['getPendingAccessRequests', 'getPendingAccessRequestCount'])).toEqual([])
  })

  it('「查看歷史」：切到歷史頁籤、網址改為 tab=history 並保留單號、展開該單', async () => {
    setUrl('?tab=pending&request=12')
    api.getPendingAccessRequests.mockResolvedValue({ data: [pendingRow(14)] })
    const wrapper = mountView()
    await flushPromises()
    await wrapper.get('[data-test="direct-view-history"]').trigger('click')
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-history')
    expect(new URLSearchParams(window.location.search).get('tab')).toBe('history')
    expect(new URLSearchParams(window.location.search).get('request')).toBe('12')
    expect(wrapper.vm.highlightId).toBe(12)
    expect(wrapper.find('.el-table__expanded-cell').exists()).toBe(true)
    expect(notFound(wrapper).exists()).toBe(false)
    // 落到歷史後同樣標示該列、焦點移到列容器
    const row = directRow(wrapper)
    expect(row.exists()).toBe(true)
    expect(row.text()).toContain('12')
    expect(document.activeElement).toBe(row.element)
    // 站內按「查看歷史」落到歷史，不標成從通知連結進來
    expect(wrapper.find('[data-test="history-direct-label"]').exists()).toBe(false)
  })

  it('403 時不顯示「找不到」，沿用無資格的呈現', async () => {
    api.getPendingAccessRequests.mockRejectedValue({ response: { status: 403 } })
    setUrl('?tab=pending&request=12')
    const wrapper = mountView()
    await flushPromises()
    expect(notFound(wrapper).exists()).toBe(false)
    expect(wrapper.text()).toContain(t('approvals.forbiddenTitle'))
  })

  it('載入失敗時不顯示「找不到」，沿用載入失敗的呈現', async () => {
    api.getPendingAccessRequests.mockRejectedValue({ response: { status: 500 } })
    setUrl('?tab=pending&request=12')
    const wrapper = mountView()
    await flushPromises()
    expect(notFound(wrapper).exists()).toBe(false)
    expect(wrapper.text()).toContain(t('approvals.loadFailed'))
  })
})

describe('以網址直達待補審的單', () => {
  it('找得到：待補審頁籤、列加標示、焦點在列本身（不在「補審」按鈕）', async () => {
    setUrl('?tab=reviews&request=9')
    const wrapper = mountView()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-reviews')
    const row = directRow(wrapper)
    expect(row.exists()).toBe(true)
    expect(document.activeElement).toBe(row.element)
    expect(document.activeElement.tagName).toBe('TR')
    expect(wrapper.vm.reviewVisible).toBe(false)
  })

  it('找不到：換成補審的句子與「查看歷史」，不另外查', async () => {
    setUrl('?tab=reviews&request=3')
    const wrapper = mountView()
    await flushPromises()
    expect(notFound(wrapper).text()).toContain(t('approvals.directNotFoundReview', { id: 3 }))
    expect(callsOutside(['getPendingReviews', 'getPendingAccessRequestCount'])).toEqual([])
  })
})

describe('以網址直達歷史頁籤', () => {
  // 目標在第一頁但不在第一列：清單 8 筆、#19 在第 8 列
  const historyPage = () => ({
    data: [26, 25, 24, 23, 22, 21, 20, 19].map((id) => historyRow(id)),
    total: 30,
  })

  it('tab=history&request=19：標示第 8 列、展開、捲到畫面中央、焦點在列容器', async () => {
    api.getAccessRequestHistory.mockResolvedValue(historyPage())
    const scrolls = []
    const original = HTMLElement.prototype.scrollIntoView
    HTMLElement.prototype.scrollIntoView = function (opts) { scrolls.push({ el: this, opts }) }
    try {
      setUrl('?tab=history&request=19')
      const wrapper = mountView()
      await flushPromises()
      expect(activeTabName(wrapper)).toBe('tab-history')
      const rows = wrapper.findAll('.history-table tbody tr.el-table__row')
      const marked = rows.filter((r) => r.classes('direct-row'))
      expect(marked).toHaveLength(1)
      expect(rows.indexOf(marked[0])).toBe(7)
      expect(marked[0].text()).toContain('19')
      expect(wrapper.find('.el-table__expanded-cell').exists()).toBe(true)
      expect(document.activeElement).toBe(marked[0].element)
      expect(document.activeElement.getAttribute('tabindex')).toBe('-1')
      expect(scrolls.some((s) => s.el === marked[0].element && s.opts?.block === 'center')).toBe(true)
      // 歷史頁籤找得到時不顯示「不在這一頁」
      expect(wrapper.find('[data-test="history-highlight-missing"]').exists()).toBe(false)
      // 從網址帶單號進來（通知連結）：標示從通知連結進來
      expect(wrapper.find('[data-test="history-direct-label"]').exists()).toBe(true)
    } finally {
      HTMLElement.prototype.scrollIntoView = original
    }
  })

  it('站內的「看這張申請單」點進來：同樣標示該列，但不寫從通知連結進來', async () => {
    api.getAccessRequestHistory.mockResolvedValue(historyPage())
    sessionStorage.setItem('ot-approvals-internal-request', '19')
    setUrl('?tab=history&request=19')
    const wrapper = mountView()
    await flushPromises()
    expect(directRow(wrapper).text()).toContain('19')
    expect(wrapper.find('[data-test="history-direct-label"]').exists()).toBe(false)
    // 記號用過即清：重新整理（重新掛載）同一網址就當作從連結進入
    expect(sessionStorage.getItem('ot-approvals-internal-request')).toBeNull()
  })

  it('目標不在這一頁：沿用既有的「不在這一頁」，沒有任何列被標示', async () => {
    api.getAccessRequestHistory.mockResolvedValue(historyPage())
    setUrl('?tab=history&request=3')
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="history-highlight-missing"]').text()).toContain(t('approvals.requestNotOnPage', { id: 3 }))
    expect(directRow(wrapper).exists()).toBe(false)
  })

  it('只有 request（逐項審核「看這張申請單」的既有連結）同樣標示並移焦點', async () => {
    api.getAccessRequestHistory.mockResolvedValue(historyPage())
    setUrl('?request=19')
    const wrapper = mountView()
    await flushPromises()
    expect(directRow(wrapper).text()).toContain('19')
    expect(document.activeElement).toBe(directRow(wrapper).element)
  })

  it('手動切到其他頁籤再切回歷史：標示清掉', async () => {
    api.getAccessRequestHistory.mockResolvedValue(historyPage())
    setUrl('?tab=history&request=19')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.get('#tab-pending').trigger('click')
    await flushPromises()
    await wrapper.get('#tab-history').trigger('click')
    await flushPromises()
    expect(directRow(wrapper).exists()).toBe(false)
    expect(new URLSearchParams(window.location.search).get('request')).toBeNull()
  })
})

describe('(c) 參數邊界', () => {
  it('只有 request：照既有行為落歷史並展開', async () => {
    setUrl('?request=12')
    const wrapper = mountView()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-history')
    expect(wrapper.vm.highlightId).toBe(12)
    expect(wrapper.find('.el-table__expanded-cell').exists()).toBe(true)
    expect(api.getPendingAccessRequests).toHaveBeenCalledTimes(0)
  })

  it('重複的 request 取第一個', async () => {
    setUrl('?tab=pending&request=12&request=14')
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.findAllComponents(PerItemApproval)[0].props('request').id).toBe(12)
  })

  it('陣列形式的鍵（request[]）不是 request：忽略，待審頁籤、不顯示找不到', async () => {
    setUrl('?tab=pending&request[]=12')
    const wrapper = mountView()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-pending')
    expect(directRow(wrapper).exists()).toBe(false)
    expect(notFound(wrapper).exists()).toBe(false)
  })

  it.each(['012', '0', '-12', '1.5', '12345678901'])('不合格的單號 %s：待審頁籤、不顯示找不到', async (bad) => {
    setUrl(`?tab=pending&request=${bad}`)
    const wrapper = mountView()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-pending')
    expect(notFound(wrapper).exists()).toBe(false)
    expect(directRow(wrapper).exists()).toBe(false)
  })

  it('不合格的頁籤加合格的單號：頁籤被忽略，落歷史並展開', async () => {
    setUrl('?tab=abc&request=12')
    const wrapper = mountView()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-history')
    expect(wrapper.vm.highlightId).toBe(12)
    expect(wrapper.find('.el-table__expanded-cell').exists()).toBe(true)
  })

  it('只有歷史資格者帶 tab=pending：只有歷史頁籤，展開該單，不讀待審', async () => {
    setCapabilitiesForTests(['ui:approval-history'])
    setUrl('?tab=pending&request=12')
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.findAll('.el-tabs__item').map((n) => n.text())).toEqual([t('approvals.tabHistory')])
    expect(wrapper.vm.highlightId).toBe(12)
    expect(api.getPendingAccessRequests).toHaveBeenCalledTimes(0)
  })

  it('手動切頁籤：網址移除 request、頁籤參數跟著目前頁籤，標示清掉', async () => {
    setUrl('?tab=pending&request=12')
    const wrapper = mountView()
    await flushPromises()
    expect(directRow(wrapper).exists()).toBe(true)
    await wrapper.get('#tab-reviews').trigger('click')
    await flushPromises()
    const params = new URLSearchParams(window.location.search)
    expect(params.get('request')).toBeNull()
    expect(params.get('tab')).toBe('reviews')
    expect(wrapper.vm.directId).toBeNull()
    // 切回待審：不再有標示
    await wrapper.get('#tab-pending').trigger('click')
    await flushPromises()
    expect(directRow(wrapper).exists()).toBe(false)
  })

  it('重新整理（重新掛載）：參數還在就再套用一次', async () => {
    setUrl('?tab=pending&request=12')
    const first = mountView()
    await flushPromises()
    expect(directRow(first).exists()).toBe(true)
    first.unmount()
    const again = mountView()
    await flushPromises()
    expect(directRow(again).exists()).toBe(true)
    expect(document.activeElement).toBe(directRow(again).element)
  })

  it('不帶任何參數：照現行的預設頁籤，沒有標示或說明', async () => {
    setUrl('')
    const wrapper = mountView()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-pending')
    expect(directRow(wrapper).exists()).toBe(false)
    expect(notFound(wrapper).exists()).toBe(false)
  })
})

describe('站內改換直達網址與決定後的網址', () => {
  const makeRouter = async (path) => {
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/approvals', component: { template: '<div />' } }] })
    await router.push(path)
    await router.isReady()
    return router
  }
  const mountWithRouter = (router) => mount(Approvals, { global: { plugins: [ElementPlus, router] }, attachTo: document.body })

  it('已停在歷史頁籤，同一頁面內被導向待審直達網址：切到待審、標示列與展開區、唯讀展開', async () => {
    setUrl('?tab=history')
    const router = await makeRouter('/approvals?tab=history')
    const wrapper = mountWithRouter(router)
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-history')
    await router.push('/approvals?tab=pending&request=12')
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('tab-pending')
    const row = directRow(wrapper)
    expect(row.exists()).toBe(true)
    expect(row.text()).toContain('12')
    expect(wrapper.get('[data-test="expand-sticky"]').classes()).toContain('direct-expanded')
    const review = wrapper.getComponent(PerItemApproval)
    expect(review.props('request').id).toBe(12)
    expect(review.attributes('data-mode')).toBe('read')
    expect(review.find('input[type="radio"]').exists()).toBe(false)
    expect(wrapper.vm.singleTarget).toBeNull()
    expect(document.activeElement).toBe(row.element)
  })

  it('從直達網址核准了該單：網址不再指定該單，停在待審頁籤、沒有「找不到」', async () => {
    setUrl('?tab=pending&request=12')
    const router = await makeRouter('/approvals?tab=pending&request=12')
    api.approveAccessRequest.mockResolvedValue({ id: 12, status: 'approved', items: [] })
    const wrapper = mountWithRouter(router)
    await flushPromises()
    await wrapper.getComponent(PerItemApproval).get('[data-test="detail-approve"]').trigger('click')
    await flushPromises()
    api.getPendingAccessRequests.mockResolvedValue({ data: [pendingRow(14), pendingRow(11)] })
    await wrapper.get('[data-test="single-decision-dialog"] [data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(api.approveAccessRequest).toHaveBeenCalledTimes(1)
    expect(router.currentRoute.value.query.request).toBeUndefined()
    expect(router.currentRoute.value.query.tab).toBe('pending')
    expect(activeTabName(wrapper)).toBe('tab-pending')
    expect(notFound(wrapper).exists()).toBe(false)
    expect(directRow(wrapper).exists()).toBe(false)
  })

  it('沒有路由器時（整頁）：決定後網址列移除單號', async () => {
    setUrl('?tab=pending&request=12')
    api.approveAccessRequest.mockResolvedValue({ id: 12, status: 'approved', items: [] })
    const wrapper = mountView()
    await flushPromises()
    await wrapper.getComponent(PerItemApproval).get('[data-test="detail-approve"]').trigger('click')
    await flushPromises()
    api.getPendingAccessRequests.mockResolvedValue({ data: [pendingRow(14)] })
    await wrapper.get('[data-test="single-decision-dialog"] [data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const params = new URLSearchParams(window.location.search)
    expect(params.get('request')).toBeNull()
    expect(params.get('tab')).toBe('pending')
  })
})
