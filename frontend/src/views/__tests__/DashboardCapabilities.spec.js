import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { createRouter, createMemoryHistory } from 'vue-router'
import Dashboard from '../Dashboard.vue'
import Approvals from '../Approvals.vue'
import { t } from '@/i18n'
import { useUpgradeGuidance } from '@/composables/useUpgradeGuidance'

enableAutoUnmount(afterEach)

const getDashboardCardMock = vi.fn()
const getActiveSessionsMock = vi.fn()
const getMyConnectionsMock = vi.fn()
const searchAlertsMock = vi.fn()
const getDailyReviewStatusMock = vi.fn()
const routerPushMock = vi.fn()
const getPendingMock = vi.fn()
const getReviewsMock = vi.fn()
const getPendingCountMock = vi.fn()
const getReleaseGuidanceStateMock = vi.fn()

vi.mock('@/api/dashboard', () => ({
  getDashboardCard: (...args) => getDashboardCardMock(...args),
}))
vi.mock('@/api/releaseGuidance', () => ({
  getReleaseGuidanceState: (...args) => getReleaseGuidanceStateMock(...args),
  dismissReleaseGuidance: vi.fn(),
  getRetentionAdjustments: vi.fn(),
}))
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequests: (...args) => getPendingMock(...args),
  getPendingReviews: (...args) => getReviewsMock(...args),
  getPendingAccessRequestCount: (...args) => getPendingCountMock(...args),
  getAccessRequestHistory: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getActiveTickets: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  approveAccessRequest: vi.fn(),
  rejectAccessRequest: vi.fn(),
  revokeAccessRequest: vi.fn(),
  reviewBreakGlass: vi.fn(),
}))
vi.mock('@/api/sessions', () => ({
  getActiveSessions: (...args) => getActiveSessionsMock(...args),
}))
vi.mock('@/api/myConnections', () => ({
  getMyConnections: (...args) => getMyConnectionsMock(...args),
}))
vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
}))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: (...args) => getDailyReviewStatusMock(...args),
  getDailyReviewPending: vi.fn(),
  signDailyReview: vi.fn(),
}))

// 十二張卡各自的必要能力（呈現判準）
const NEED = {
  assets: ['asset:view'],
  // 已登入者看自己的資料（owner/self）：不要求任何能力點，與側欄入口同一判準
  'my-connections': [],
  'my-pending-requests': [],
  'active-sessions': ['session:view'],
  'today-sessions': ['session:view'],
  'total-sessions': ['session:view'],
  'today-alerts': ['audit:view'],
  'recording-storage': ['audit:view'],
  'pending-approvals': ['ui:approvals'],
  'unreviewed-alerts': ['audit:view'],
  'recording-failures': ['session:view'],
  'last-access-review': ['audit:view'],
}
const KEYS = Object.keys(NEED)
const ALL_PERMS = ['asset:view', 'ui:self-service-actions', 'session:view', 'audit:view', 'ui:approvals', 'ui:assets-global']

// 日界線字串保留微秒，導覽時必須逐字相同
const DAY_START = '2026-10-19T00:00:00.000000+08:00'
const DAY_END = '2026-10-19T23:59:59.999999+08:00'

// 每張卡的回應：value 互不相同，才能證明顯示的是自己的值
const RESPONSES = {
  assets: { value: 11, unit: 'count', filters: {} },
  'my-connections': { value: 12, unit: 'count', filters: {} },
  'my-pending-requests': { value: 13, unit: 'count', filters: { status: 'pending' } },
  'active-sessions': { value: 14, unit: 'count', filters: { status: 'active' } },
  'today-sessions': { value: 15, unit: 'count', filters: { start_time: DAY_START, end_time: DAY_END } },
  'total-sessions': { value: 16, unit: 'count', filters: {} },
  'today-alerts': { value: 17, unit: 'count', filters: { start_time: DAY_START, end_time: DAY_END } },
  'recording-storage': { value: 931724, unit: 'bytes', filters: {} },
  'pending-approvals': { value: 18, unit: 'count', filters: {}, count: 15, review_count: 3 },
  'unreviewed-alerts': { value: 19, unit: 'count', filters: { unreviewed: 'true' } },
  'recording-failures': { value: 20, unit: 'count', filters: { status: 'active', recording_error: 'true' } },
  'last-access-review': { value: 21, unit: 'days', filters: {}, overdue: false, review_period_days: 180 },
}
// 與條件無關的落點頁籤，和卡片 filters 分開帶
const EXTRA = {
  'active-sessions': { tab: 'active' },
  'today-sessions': { tab: 'history' },
  'total-sessions': { tab: 'history' },
  'recording-failures': { tab: 'active' },
}
const PATHS = {
  assets: '/assets',
  'my-connections': '/my-connections',
  'my-pending-requests': '/my-requests',
  'active-sessions': '/sessions',
  'today-sessions': '/sessions',
  'total-sessions': '/sessions',
  'today-alerts': '/alerts',
  'recording-storage': null,
  'pending-approvals': '/approvals',
  'unreviewed-alerts': '/alerts',
  'recording-failures': '/sessions',
  'last-access-review': '/access-reviews',
}

const grant = (perms) => setCapabilitiesForTests(perms)
const mountDashboard = () =>
  mount(Dashboard, {
    global: {
      plugins: [ElementPlus],
      mocks: { $router: { push: routerPushMock } },
      // 說明卡需要真實路由；掛載位置另有專案案例驗證
      stubs: { UpgradeGuidanceCard: true },
    },
  })
const requested = () => getDashboardCardMock.mock.calls.map((c) => c[0])
const cardEl = (w, key) => w.find(`[data-card="${key}"]`)
const valueOf = (w, key) => cardEl(w, key).find('.stat-value').text()

describe('DashboardCapabilities', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    resetCapabilities()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    getDashboardCardMock.mockImplementation((key) => Promise.resolve({ key, ...RESPONSES[key] }))
    getActiveSessionsMock.mockResolvedValue([])
    getMyConnectionsMock.mockResolvedValue({ data: [], total: 0 })
    searchAlertsMock.mockResolvedValue({ data: [], total: 0 })
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: false } })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe.each(KEYS)('卡片 %s', (key) => {
    it('缺必要能力時不呈現且不發請求', async () => {
      grant(ALL_PERMS.filter((p) => !NEED[key].includes(p)))
      const wrapper = mountDashboard()
      await flushPromises()

      if (NEED[key].length === 0) {
        // 自助卡不吃能力點：能力集再空也呈現並取數
        expect(cardEl(wrapper, key).exists()).toBe(true)
        expect(requested()).toContain(key)
        return
      }
      expect(cardEl(wrapper, key).exists()).toBe(false)
      expect(requested()).not.toContain(key)
      // 其他卡的能力仍在者照常取數，缺一張不影響別張
      for (const other of KEYS) {
        if (NEED[other].every((p) => !NEED[key].includes(p))) {
          expect(requested()).toContain(other)
        }
      }
    })

    it('具能力時顯示同源回應並導至同篩選列表', async () => {
      grant(NEED[key])
      const wrapper = mountDashboard()
      await flushPromises()

      expect(requested()).toContain(key)
      const el = cardEl(wrapper, key)
      expect(el.exists()).toBe(true)
      const resp = RESPONSES[key]
      if (key === 'recording-storage') {
        expect(valueOf(wrapper, key)).toBe('909.9 KB')
      } else {
        expect(valueOf(wrapper, key)).toBe(String(resp.value))
      }
      await el.trigger('click')
      if (PATHS[key] === null) {
        expect(routerPushMock).not.toHaveBeenCalled()
        expect(el.classes()).not.toContain('stat-card-clickable')
      } else {
        expect(routerPushMock).toHaveBeenCalledTimes(1)
        expect(routerPushMock).toHaveBeenCalledWith({
          path: PATHS[key],
          query: { ...resp.filters, ...(EXTRA[key] || {}) },
        })
      }
    })
  })

  it('今日卡導覽的日界線與卡片回應逐字相同（微秒完整）', async () => {
    grant(['session:view', 'audit:view'])
    const wrapper = mountDashboard()
    await flushPromises()

    for (const key of ['today-sessions', 'today-alerts']) {
      routerPushMock.mockClear()
      await cardEl(wrapper, key).trigger('click')
      const query = routerPushMock.mock.calls[0][0].query
      expect(query.start_time).toBe(DAY_START)
      expect(query.end_time).toBe(DAY_END)
      expect(query.end_time.endsWith('.999999+08:00')).toBe(true)
    }
  })

  it('持 ui:assets-global 而缺 session:view 者不出現 session 卡與錄影失敗卡，缺 audit:view 者不出現告警與錄影佔用卡', async () => {
    grant(['ui:assets-global', 'asset:view'])
    const wrapper = mountDashboard()
    await flushPromises()

    // 兩張自助卡只看已登入，不吃能力點，所以仍在
    const SELF = ['my-connections', 'my-pending-requests']
    for (const key of KEYS.filter((k) => k !== 'assets' && !SELF.includes(k))) {
      expect(cardEl(wrapper, key).exists()).toBe(false)
    }
    expect([...requested()].sort()).toEqual(['assets', ...SELF].sort())
    expect(getActiveSessionsMock).not.toHaveBeenCalled()
    expect(searchAlertsMock).not.toHaveBeenCalled()
    expect(getDailyReviewStatusMock).not.toHaveBeenCalled()
    expect(valueOf(wrapper, 'assets')).toBe('11')
    expect(cardEl(wrapper, 'assets').text()).toContain('資產總數')

    resetCapabilities()
    vi.clearAllMocks()
    grant(['ui:assets-global', 'asset:view', 'session:view'])
    const w2 = mountDashboard()
    await flushPromises()
    for (const key of ['today-alerts', 'recording-storage', 'unreviewed-alerts', 'last-access-review']) {
      expect(cardEl(w2, key).exists()).toBe(false)
      expect(requested()).not.toContain(key)
    }
    for (const key of ['active-sessions', 'today-sessions', 'total-sessions', 'recording-failures']) {
      expect(cardEl(w2, key).exists()).toBe(true)
    }
  })

  it('同時持全域與自助能力者看得到兩張自助卡、本人近期連線，也看得到其他面板', async () => {
    grant(['ui:assets-global', 'ui:self-service-actions', 'asset:view', 'session:view', 'audit:view'])
    getMyConnectionsMock.mockResolvedValue({
      data: [{ asset_name: 'web-server', protocol: 'ssh', status: 'active' }],
      total: 1,
    })
    getActiveSessionsMock.mockResolvedValue([
      { id: 1, protocol: 'ssh', user: { username: 'alice' }, asset: { name: 'db-1' } },
    ])
    searchAlertsMock.mockResolvedValue({
      data: [{ id: 1, kind: 'rule', rule_name: '危險刪除', command: 'rm -rf /', severity: 'high', username: 'u', triggered_at: '2026-10-19T01:00:00Z' }],
      total: 1,
    })
    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardEl(wrapper, 'my-connections').exists()).toBe(true)
    expect(cardEl(wrapper, 'my-pending-requests').exists()).toBe(true)
    expect(wrapper.find('[data-panel="my-connections"]').text()).toContain('web-server')
    expect(wrapper.find('[data-panel="active-sessions"]').text()).toContain('alice')
    expect(wrapper.find('[data-panel="recent-alerts"]').text()).toContain('危險刪除')
    expect(getMyConnectionsMock).toHaveBeenCalledWith({ page: 1, page_size: 5 })
  })

  it('recording-failures 只依 session:view：只持 audit:view 不出現，只持 session:view 出現', async () => {
    grant(['audit:view'])
    let wrapper = mountDashboard()
    await flushPromises()
    expect(cardEl(wrapper, 'recording-failures').exists()).toBe(false)
    expect(requested()).not.toContain('recording-failures')
    wrapper.unmount()

    resetCapabilities()
    vi.clearAllMocks()
    grant(['session:view'])
    wrapper = mountDashboard()
    await flushPromises()
    expect(cardEl(wrapper, 'recording-failures').exists()).toBe(true)
    expect(requested()).toContain('recording-failures')
  })

  it('管理能力不兜底待審：持全部管理類能力但缺 ui:approvals 者無待審卡且不發請求', async () => {
    grant(['asset:view', 'session:view', 'audit:view', 'securitypolicy:manage', 'user:manage', 'authorization:manage', 'approverscope:manage', 'ui:assets-global', 'ui:super-admin'])
    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardEl(wrapper, 'pending-approvals').exists()).toBe(false)
    expect(requested()).not.toContain('pending-approvals')
  })

  it('混合能力取聯集，每張卡只出現一次', async () => {
    grant(ALL_PERMS)
    const wrapper = mountDashboard()
    await flushPromises()

    const keys = wrapper.findAll('[data-card]').map((n) => n.attributes('data-card'))
    expect(new Set(keys).size).toBe(keys.length)
    expect([...keys].sort()).toEqual([...KEYS].sort())
    // 每張卡只取一次數
    expect([...requested()].sort()).toEqual([...KEYS].sort())
  })

  it('稽核兼審核者（無 ui:self-service-actions）看得到十二卡聯集，含兩張自助卡與我的連線面板', async () => {
    grant(['asset:view', 'session:view', 'audit:view', 'ui:approvals', 'ui:assets-global'])
    getMyConnectionsMock.mockResolvedValue({ data: [{ asset_name: 'web-server', protocol: 'ssh', status: 'active' }], total: 1 })
    const wrapper = mountDashboard()
    await flushPromises()

    const keys = wrapper.findAll('[data-card]').map((n) => n.attributes('data-card'))
    expect([...keys].sort()).toEqual([...KEYS].sort())
    expect(new Set(keys).size).toBe(keys.length)
    expect(wrapper.find('[data-panel="my-connections"]').exists()).toBe(true)
    expect(getMyConnectionsMock).toHaveBeenCalledWith({ page: 1, page_size: 5 })
  })

  it('超管（只持 ui:super-admin、ui:assets-global，無 ui:self-service-actions）也看得到兩張自助卡', async () => {
    grant(['asset:view', 'session:view', 'audit:view', 'ui:assets-global', 'ui:super-admin'])
    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardEl(wrapper, 'my-connections').exists()).toBe(true)
    expect(cardEl(wrapper, 'my-pending-requests').exists()).toBe(true)
    expect(requested()).toContain('my-connections')
    expect(requested()).toContain('my-pending-requests')
  })

  it('待辦列順序照核可稿：未審閱告警、錄影失敗連線、上次存取複審、待審申請', async () => {
    grant(ALL_PERMS)
    const wrapper = mountDashboard()
    await flushPromises()

    const keys = wrapper.findAll('[data-card]').map((n) => n.attributes('data-card'))
    const backlog = keys.filter((k) =>
      ['pending-approvals', 'unreviewed-alerts', 'recording-failures', 'last-access-review'].includes(k))
    expect(backlog).toEqual(['unreviewed-alerts', 'recording-failures', 'last-access-review', 'pending-approvals'])
  })

  it('失敗顯示「未取得」不冒充 0，且只影響該卡', async () => {
    grant(ALL_PERMS)
    getDashboardCardMock.mockImplementation((key) =>
      key === 'today-alerts'
        ? Promise.reject(new Error('network down'))
        : Promise.resolve({ key, ...RESPONSES[key] })
    )
    const wrapper = mountDashboard()
    await flushPromises()

    expect(valueOf(wrapper, 'today-alerts')).toBe('未取得')
    expect(valueOf(wrapper, 'today-alerts')).not.toBe('0')
    // 取不到值的卡不可點，避免未帶條件就落到清單
    await cardEl(wrapper, 'today-alerts').trigger('click')
    expect(routerPushMock).not.toHaveBeenCalled()
    for (const key of KEYS.filter((k) => k !== 'today-alerts' && k !== 'recording-storage')) {
      expect(valueOf(wrapper, key)).toBe(String(RESPONSES[key].value))
    }
    expect(valueOf(wrapper, 'recording-storage')).toBe('909.9 KB')
  })

  it('403 被拒與其他錯誤一樣只讓該卡顯示未取得，並清掉舊值', async () => {
    grant(['asset:view', 'session:view'])
    const wrapper = mountDashboard()
    await flushPromises()
    expect(valueOf(wrapper, 'assets')).toBe('11')

    getDashboardCardMock.mockImplementation((key) =>
      key === 'assets'
        ? Promise.reject(Object.assign(new Error('forbidden'), { response: { status: 403 } }))
        : Promise.resolve({ key, ...RESPONSES[key] })
    )
    await wrapper.find('.page-header button, button').trigger('click')
    await flushPromises()

    expect(valueOf(wrapper, 'assets')).toBe('未取得')
    expect(cardEl(wrapper, 'assets').text()).not.toContain('11')
    expect(valueOf(wrapper, 'active-sessions')).toBe('14')
  })

  it('last-access-review：從未複審顯示破折號，逾期改標題', async () => {
    grant(['audit:view'])
    getDashboardCardMock.mockImplementation((key) =>
      Promise.resolve({ key, ...RESPONSES[key], ...(key === 'last-access-review' ? { value: -1, overdue: true } : {}) })
    )
    const wrapper = mountDashboard()
    await flushPromises()

    expect(valueOf(wrapper, 'last-access-review')).toBe('—')
    expect(cardEl(wrapper, 'last-access-review').text()).toContain('已逾期')
  })

  it('失權後卡片消失、清掉舊值，再具能力時重新取數；在途的舊回應不留舊數', async () => {
    grant(['asset:view', 'session:view'])
    const wrapper = mountDashboard()
    await flushPromises()
    expect(valueOf(wrapper, 'assets')).toBe('11')

    // 在途請求：失權之後才回來的舊回應
    let release
    getDashboardCardMock.mockImplementation((key) =>
      key === 'active-sessions'
        ? new Promise((resolve) => {
            release = () => resolve({ key, ...RESPONSES[key], value: 777 })
          })
        : Promise.resolve({ key, ...RESPONSES[key] })
    )
    // 能力變動（仍持 session:view）觸發整批重算，active-sessions 進入在途
    grant(['asset:view', 'session:view', 'ui:assets-global'])
    await flushPromises()
    // 在途中失去 session:view
    grant(['asset:view'])
    await flushPromises()
    release()
    await flushPromises()

    expect(cardEl(wrapper, 'active-sessions').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('777')
    expect(valueOf(wrapper, 'assets')).toBe('11')

    // 登出（能力清空）後所有卡消失
    resetCapabilities()
    await flushPromises()
    // 全域卡全部消失；兩張自助卡只看已登入，不隨能力清空消失（真實登出時整頁卸載）
    expect(wrapper.findAll('[data-card]').map((n) => n.attributes('data-card')).sort())
      .toEqual(['my-connections', 'my-pending-requests'])
  })

  it('換帳號後舊會話的回應不寫入新帳號的卡片', async () => {
    grant(['asset:view'])
    let release
    getDashboardCardMock.mockImplementation((key) =>
      new Promise((resolve) => {
        release = () => resolve({ key, ...RESPONSES[key], value: 555 })
      })
    )
    const wrapper = mountDashboard()
    await flushPromises()

    const releaseOld = release
    getDashboardCardMock.mockImplementation((key) => Promise.resolve({ key, ...RESPONSES[key] }))
    setCapabilitiesForTests(['asset:view'], { userId: 2 })
    await flushPromises()
    releaseOld()
    await flushPromises()

    expect(valueOf(wrapper, 'assets')).toBe('11')
    expect(wrapper.text()).not.toContain('555')
  })

  it('錄影佔用卡無假連結、不輪詢：多次等待後仍只取一次', async () => {
    const intervalSpy = vi.spyOn(globalThis, 'setInterval')
    grant(['audit:view'])
    const wrapper = mountDashboard()
    await flushPromises()
    await new Promise((r) => setTimeout(r, 50))
    await flushPromises()

    const el = cardEl(wrapper, 'recording-storage')
    expect(el.classes()).not.toContain('stat-card-clickable')
    expect(el.attributes('role')).toBeUndefined()
    expect(requested().filter((k) => k === 'recording-storage')).toHaveLength(1)
    expect(intervalSpy).not.toHaveBeenCalled()
  })

  it('重新整理對每張卡各取一次，彼此獨立', async () => {
    grant(ALL_PERMS)
    const wrapper = mountDashboard()
    await flushPromises()
    getDashboardCardMock.mockClear()

    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect([...requested()].sort()).toEqual([...KEYS].sort())
  })

  it('每日安全審閱只在 audit:view 時取數與顯示，並與卡片並存', async () => {
    grant(['asset:view', 'session:view'])
    let wrapper = mountDashboard()
    await flushPromises()
    expect(getDailyReviewStatusMock).not.toHaveBeenCalled()
    wrapper.unmount()

    resetCapabilities()
    grant(['asset:view', 'audit:view'])
    getDailyReviewStatusMock.mockResolvedValue({
      data: { enabled: false, timezone_state: { active: 'Asia/Taipei', today: {}, pending: null }, pending_count: 0 },
    })
    wrapper = mountDashboard()
    await flushPromises()
    expect(getDailyReviewStatusMock).toHaveBeenCalledTimes(1)
    expect(wrapper.find('.review-card').exists()).toBe(true)
  })

  it('快速操作依落點入口規則（canEnter）決定，缺能力的入口不出現', async () => {
    grant(['asset:view'])
    let wrapper = mountDashboard()
    await flushPromises()
    let titles = wrapper.findAll('.action-title').map((n) => n.text())
    expect(titles).not.toContain('連線管理')
    expect(titles).not.toContain('操作日誌')
    expect(titles).not.toContain('我的連線')
    expect(titles).not.toContain('我的申請')
    wrapper.unmount()

    resetCapabilities()
    grant(['asset:view', 'session:view', 'audit:view'])
    wrapper = mountDashboard()
    await flushPromises()
    titles = wrapper.findAll('.action-title').map((n) => n.text())
    expect(titles).toContain('連線管理')
    expect(titles).toContain('操作日誌')
    wrapper.unmount()

    resetCapabilities()
    grant(['asset:view', 'ui:self-service-actions'])
    wrapper = mountDashboard()
    await flushPromises()
    titles = wrapper.findAll('.action-title').map((n) => n.text())
    expect(titles).toContain('我的連線')
    expect(titles).toContain('我的申請')
  })
  it('說明卡掛在頁首之後、統計卡之前，且不阻擋卡片取數與操作', async () => {
    useUpgradeGuidance().reset()
    getReleaseGuidanceStateMock.mockResolvedValue({ notice_version: '1.18.0', dismissed: false })
    grant(['asset:view', 'session:view'])
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/:pathMatch(.*)*', component: { render: () => null } }],
    })
    router.push('/dashboard')
    await router.isReady()
    const wrapper = mount(Dashboard, { global: { plugins: [ElementPlus, router] } })
    await flushPromises()
    const html = wrapper.html()
    const guidanceAt = html.indexOf('data-test="upgrade-guidance"')
    const headerAt = html.indexOf('page-header')
    const cardAt = html.indexOf('data-card="assets"')
    expect(guidanceAt).toBeGreaterThan(headerAt)
    expect(cardAt).toBeGreaterThan(guidanceAt)
    expect(getDashboardCardMock).toHaveBeenCalled()
    expect(valueOf(wrapper, 'assets')).not.toBe('')
    useUpgradeGuidance().reset()
  })

  it('審核列表顯示已載入數與全量數：待審與待補審各讀同一計數端點的 count 與 review_count', async () => {
    class MutationObserverStub { observe() {} disconnect() {} takeRecords() { return [] } }
    vi.stubGlobal('MutationObserver', MutationObserverStub)
    grant(['ui:approvals'])
    const sheet = (id) => ({
      id, requester_id: 5, requester: { username: 'alice' }, asset_id: 1, asset: { name: 'db' },
      reason: 'r', requested_duration_minutes: 60, status: 'pending', created_at: '2026-10-19T10:00:00+08:00',
    })
    getPendingMock.mockResolvedValue({ data: [sheet(1), sheet(2)], total: 2 })
    getReviewsMock.mockResolvedValue({ data: [], total: 0 })
    getPendingCountMock.mockResolvedValue({ count: 250, review_count: 3 })
    const wrapper = mount(Approvals, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    expect(wrapper.find('[data-test="pending-loaded-of-total"]').text()).toBe(
      t('dashboard.loadedOfTotal', { loaded: 2, total: 250 }),
    )
    expect(wrapper.find('[data-test="reviews-loaded-of-total"]').text()).toBe(
      t('dashboard.loadedOfTotal', { loaded: 0, total: 3 }),
    )
    // 計數讀不到：顯示未取得，不用載入數冒充全量
    getPendingCountMock.mockRejectedValue(new Error('boom'))
    const again = mount(Approvals, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    expect(again.find('[data-test="pending-loaded-of-total"]').text()).toBe(
      t('dashboard.loadedOfTotal', { loaded: 2, total: t('dashboard.valueUnavailable') }),
    )
    vi.unstubAllGlobals()
  })
})
