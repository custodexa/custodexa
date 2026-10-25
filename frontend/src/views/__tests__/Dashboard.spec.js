import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { permissionsFor } from '@/composables/__tests__/capabilityFixtures'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Dashboard from '../Dashboard.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
enableAutoUnmount(afterEach)

const getDashboardCardMock = vi.fn()
const getActiveSessionsMock = vi.fn()
const getMyConnectionsMock = vi.fn()
const searchAlertsMock = vi.fn()
const getDailyReviewStatusMock = vi.fn()
const getDailyReviewPendingMock = vi.fn()
const signDailyReviewMock = vi.fn()
const routerPushMock = vi.fn()

// 十二張卡改由逐卡 API 供值；每個案例用 setCards 覆寫需要的卡，其餘預設 0
vi.mock('@/api/dashboard', () => ({
  getDashboardCard: (...args) => getDashboardCardMock(...args),
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
  getDailyReviewPending: (...args) => getDailyReviewPendingMock(...args),
  signDailyReview: (...args) => signDailyReviewMock(...args),
}))

// 逐卡回應：overrides 以 key 對應 { value, filters, ... } 或 Error（拒絕）
let cardOverrides = {}
const setCards = (overrides) => {
  cardOverrides = overrides
}
const cardCalls = () => getDashboardCardMock.mock.calls.map((c) => c[0])
const DAY_START = '2026-10-19T00:00:00.000000+08:00'
const DAY_END = '2026-10-19T23:59:59.999999+08:00'

// 第二參數＝登入回應的 is_approver（後端有效審核資格：approver 角色 OR 審核方群組）。
// 群組審核方的 roles 不含 approver，只能靠這個欄位認出來，故測試必須能單獨設定它。
// 能力來自後端 /auth/me 的 permissions（共用能力狀態），不是登入快取裡的角色：
// 這裡把該身分的能力寫入共用狀態；localStorage 的 user 只留顯示用的欄位
const setUserRoles = (roles, isApprover) => {
  const user = { username: 'tester', roles }
  if (isApprover !== undefined) user.is_approver = isApprover
  localStorage.setItem('user', JSON.stringify(user))
  setCapabilitiesForTests(permissionsFor(roles, { approver: isApprover }))
}

// /daily-reviews/status 的回應形狀（昨日待簽、期限內、告警 1 筆未處置）
const TZ_STATE = {
  active: 'Asia/Taipei',
  today: { date: '2026-10-11', window_start: '2026-10-10T16:00:00Z', window_end: '2026-10-11T16:00:00Z' },
  pending: null,
}
const yesterdayLive = {
  date: '2026-10-10',
  timezone: 'Asia/Taipei',
  window_start: '2026-10-09T16:00:00Z',
  window_end: '2026-10-10T16:00:00Z',
  due_at: '2026-10-11T16:00:00Z',
  signable_at: '2026-10-10T16:30:00Z',
  signable: true,
  in_scope: true,
  enabled_basis: 'recorded',
  signed: false,
  review: null,
  counts: {
    date: '2026-10-10',
    login_failures: 3,
    login_failures_source: 'complete',
    high_risk_ops: 5,
    high_risk_ops_source: 'complete',
    unreviewed_alerts: 1,
    alerts_total: 3,
    alerts_source: 'complete',
  },
  counts_fixed: false,
}
const enabledStatus = {
  enabled: true,
  timezone_state: TZ_STATE,
  yesterday: yesterdayLive,
  pending_count: 1,
  overdue_count: 0,
  earliest_pending_date: '2026-10-10',
  pending_dates: ['2026-10-10'],
  stats_30d: { sign_rate_percent: 100 },
}

// 能力以明細組出（聯集案例用），不經角色折疊
const grant = (perms) => setCapabilitiesForTests(perms)

const mountDashboard = () =>
  mount(Dashboard, {
    global: {
      plugins: [ElementPlus],
      mocks: { $router: { push: routerPushMock } },
      // 說明卡需要真實路由，其行為由 UpgradeGuidance.spec.js 與 DashboardCapabilities.spec.js 驗證
      stubs: { UpgradeGuidanceCard: true },
    },
  })

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    resetCapabilities()
    searchAlertsMock.mockResolvedValue({ data: [], total: 0 })
    cardOverrides = {}
    getDashboardCardMock.mockImplementation((key) => {
      const o = cardOverrides[key]
      if (o instanceof Error) return Promise.reject(o)
      return Promise.resolve({ key, value: 0, unit: 'count', filters: {}, ...(o || {}) })
    })
    getActiveSessionsMock.mockResolvedValue([])
    getMyConnectionsMock.mockResolvedValue({ data: [], total: 0 })
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: false } })
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [], total: 0 } })
  })

  it('renders statistics from APIs', async () => {
    setUserRoles(['admin'])
    setCards({
      assets: { value: 12 },
      'active-sessions': { value: 3 },
      'today-sessions': { value: 7 },
      'total-sessions': { value: 99 },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const valueOf = (k) => wrapper.find(`[data-card="${k}"] .stat-value`).text()
    expect(valueOf('assets')).toBe('12')
    expect(valueOf('active-sessions')).toBe('3')
    expect(valueOf('today-sessions')).toBe('7')
    expect(valueOf('total-sessions')).toBe('99')
  })

  it('今日告警與今日連線走逐卡 API，導覽沿用卡片回應的共用日界線', async () => {
    setUserRoles(['admin'])
    setCards({
      'today-alerts': { value: 5, filters: { start_time: DAY_START, end_time: DAY_END } },
      'today-sessions': { value: 2, filters: { start_time: DAY_START, end_time: DAY_END } },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardCalls()).toContain('today-alerts')
    // 不再各自用本地時間組參數查列表
    expect(searchAlertsMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ start_time: expect.any(String) })
    )
    const card = wrapper.find('[data-card="today-alerts"]')
    expect(card.text()).toContain('今日告警')
    expect(card.find('.stat-value').text()).toBe('5')
    await card.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith({
      path: '/alerts',
      query: { start_time: DAY_START, end_time: DAY_END },
    })
    routerPushMock.mockClear()
    await wrapper.find('[data-card="today-sessions"]').trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith({
      path: '/sessions',
      query: { start_time: DAY_START, end_time: DAY_END, tab: 'history' },
    })
  })

  // 擋：非規則類告警在首頁印出 rule_name 機器碼；指令為空時留下尾端冒號
  it('首頁告警行：非規則類顯示種類文案，規則類指令為空時不帶冒號', async () => {
    setUserRoles(['admin'])
    searchAlertsMock.mockResolvedValue({
      data: [
        { id: 1, kind: 'audit_degraded', rule_name: 'audit_degraded_span', command: '', severity: 'medium', username: 'u1', triggered_at: '2026-10-07T01:00:00Z' },
        { id: 2, kind: 'new_source_ip', rule_name: 'new_source_ip', command: '', severity: 'low', username: 'u2', triggered_at: '2026-10-07T01:00:00Z' },
        { id: 3, kind: 'rule', rule_name: '危險刪除', command: 'rm -rf /', severity: 'high', username: 'u3', triggered_at: '2026-10-07T01:00:00Z' },
        { id: 4, kind: 'rule', rule_name: '空指令規則', command: '', severity: 'high', username: 'u4', triggered_at: '2026-10-07T01:00:00Z' },
      ],
      total: 4,
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const lines = wrapper.findAll('.activity-main').map((n) => n.text())
    expect(lines).toContain('指令稽核降級')
    expect(lines).toContain('帳號新來源位址')
    expect(lines).toContain('危險刪除：rm -rf /')
    expect(lines).toContain('空指令規則')
    const text = wrapper.text()
    expect(text).not.toContain('audit_degraded_span')
    expect(text).not.toContain('new_source_ip')
    for (const line of lines) expect(line.endsWith('：')).toBe(false)
  })

  it('今日告警取不到時顯示「未取得」，不冒充 0', async () => {
    setUserRoles(['admin'])
    setCards({ 'today-alerts': new Error('network down') })

    const wrapper = mountDashboard()
    await flushPromises()

    const card = wrapper.find('[data-card="today-alerts"]')
    expect(card.text()).toContain('今日告警')
    expect(card.find('.stat-value').text()).toBe('未取得')
    expect(card.find('.stat-value').text()).not.toBe('0')
  })

  it('survives API failure without crashing and stops loading', async () => {
    setUserRoles(['admin'])
    const down = new Error('network down')
    setCards({
      assets: down,
      'active-sessions': down,
      'today-sessions': down,
      'total-sessions': down,
      'today-alerts': down,
      'recording-storage': down,
    })
    searchAlertsMock.mockRejectedValue(down)

    const wrapper = mountDashboard()
    await flushPromises()

    // 頁面仍渲染統計卡（未取得），不拋例外，沒有卡片停在載入中
    expect(wrapper.text()).toContain('資產總數')
    expect(wrapper.find('[data-card="assets"] .stat-value').text()).toBe('未取得')
    expect(wrapper.findAll('.stat-card').every((c) => c.find('.stat-value').exists())).toBe(true)
    expect(wrapper.findAll('.el-loading-mask').filter((m) => m.element.style.display !== 'none')).toHaveLength(0)
  })

  it('renders quick action cards', async () => {
    setUserRoles(['admin'])

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('快速操作')
    expect(text).toContain('資產管理')
    expect(text).toContain('連線管理')
    expect(text).toContain('操作日誌')
  })

  // —— 一般 user 的角色化儀表板——

  it('user role never calls privileged endpoints and shows my-connections summary', async () => {
    setUserRoles(['user'])
    setCards({ assets: { value: 4 }, 'my-connections': { value: 2 } })
    getMyConnectionsMock.mockResolvedValue({
      data: [
        { asset_name: 'web-server', protocol: 'ssh', status: 'active', duration_seconds: 60 },
        { asset_name: 'db-server', protocol: 'rdp', status: 'ended', duration_seconds: 300 },
      ],
      total: 2,
    })

    const wrapper = mountDashboard()
    await flushPromises()

    // 不呼叫需 session:view / alert:view 的端點（避免 403）
    expect(cardCalls().sort()).toEqual(['assets', 'my-connections', 'my-pending-requests'])
    expect(getActiveSessionsMock).not.toHaveBeenCalled()
    expect(searchAlertsMock).not.toHaveBeenCalled()

    const text = wrapper.text()
    // 自助摘要與統計卡
    expect(text).toContain('我的連線')
    expect(text).toContain('web-server')
    expect(text).toContain('進行中')
    // 稽核職能區塊不渲染
    expect(text).not.toContain('進行中連線')
    expect(text).not.toContain('最近告警')
    expect(text).not.toContain('今日告警')
    expect(text).not.toContain('連線管理')
    expect(text).not.toContain('操作日誌')
  })

  it('user role quick action links to my-connections', async () => {
    setUserRoles(['user'])

    const wrapper = mountDashboard()
    await flushPromises()

    const actionCards = wrapper.findAll('.action-card')
    const myConnCard = actionCards.find((card) => card.text().includes('我的連線'))
    expect(myConnCard).toBeTruthy()
    await myConnCard.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/my-connections')
  })

  it('混合 user＋auditor 能力取聯集：自助與稽核的卡、面板都出現', async () => {
    // 以能力明細表達（不經角色折疊）：稽核能力加上自助能力
    grant([...permissionsFor(['auditor']), 'ui:self-service-actions'])

    const wrapper = mountDashboard()
    await flushPromises()

    expect(getActiveSessionsMock).toHaveBeenCalled()
    expect(getMyConnectionsMock).toHaveBeenCalled()
    expect(cardCalls()).toEqual(
      expect.arrayContaining(['my-connections', 'my-pending-requests', 'active-sessions', 'today-alerts'])
    )
    // 每張卡只出現一次
    const keys = wrapper.findAll('[data-card]').map((n) => n.attributes('data-card'))
    expect(new Set(keys).size).toBe(keys.length)
    expect(wrapper.text()).toContain('進行中連線')
    expect(wrapper.find('[data-panel="my-connections"]').exists()).toBe(true)
  })

  // —— 人設待辦卡——

  it('auditor sees audit-backlog cards with counts from existing endpoints', async () => {
    setUserRoles(['auditor'])
    setCards({
      'unreviewed-alerts': { value: 7, filters: { unreviewed: 'true' } },
      // 錄影失敗件數是完整授權集合的全量，不由近期五列推算
      'recording-failures': { value: 2, filters: { status: 'active', recording_error: 'true' } },
      'last-access-review': { value: 200, unit: 'days', overdue: true, review_period_days: 180 },
    })
    getActiveSessionsMock.mockResolvedValue([
      { id: 1, protocol: 'ssh', recording_error: '磁碟滿' },
      { id: 2, protocol: 'rdp' },
      { id: 3, protocol: 'ssh' },
    ])

    const wrapper = mountDashboard()
    await flushPromises()

    const valueOf = (k) => wrapper.find(`[data-card="${k}"] .stat-value`).text()
    expect(valueOf('unreviewed-alerts')).toBe('7')
    expect(wrapper.find('[data-card="unreviewed-alerts"]').text()).toContain('未審閱告警')
    expect(valueOf('recording-failures')).toBe('2')
    expect(wrapper.find('[data-card="recording-failures"]').text()).toContain('錄影失敗連線')
    expect(valueOf('last-access-review')).toBe('200')
    expect(wrapper.find('[data-card="last-access-review"]').text()).toContain('上次存取複審（天，已逾期）')
    // auditor 非 approver/admin：不取待審卡、不見待審卡
    expect(cardCalls()).not.toContain('pending-approvals')
    expect(wrapper.text()).not.toContain('待審申請')
  })

  it('user+approver overlay adds pending-approvals card alongside self-service cards', async () => {
    setUserRoles(['user', 'approver'])
    setCards({
      'pending-approvals': { value: 4, count: 3, review_count: 1 },
      'my-pending-requests': { value: 1, filters: { status: 'pending' } },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    // 疊加聯集：自助卡與待審卡並存
    expect(text).toContain('我的申請待審')
    expect(text).toContain('待審申請')
    expect(wrapper.find('[data-card="pending-approvals"] .stat-value').text()).toBe('4') // 同源 count + review_count
    // 仍不取稽核與 session 的卡、不呼叫稽核端點
    expect(cardCalls()).not.toContain('active-sessions')
    expect(cardCalls()).not.toContain('today-alerts')
    expect(searchAlertsMock).not.toHaveBeenCalled()
  })

  it('admin 無審核資格：不打待審端點、不渲染待審卡（守衛端不認 admin 兜底）', async () => {
    // 後端 RequireApproverRole 走 evaluateEffectiveApprover，只認 approver 角色或
    // 審核方群組。以 isAdmin 決定要不要打，請求必 403 且失敗被靜默吞掉，
    // 卡片顯示 0——使用者會把「無資格」讀成「無待辦」。
    setUserRoles(['admin'], false)

    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardCalls()).not.toContain('pending-approvals')
    expect(wrapper.text()).not.toContain('待審申請')
  })

  it('群組審核方（roles 不含 approver、is_approver 為真）：打端點且渲染待審卡', async () => {
    setUserRoles(['user'], true)
    setCards({ 'pending-approvals': { value: 5, count: 2, review_count: 3 } })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardCalls()).toContain('pending-approvals')
    const text = wrapper.text()
    expect(text).toContain('待審申請')
    expect(wrapper.find('[data-card="pending-approvals"] .stat-value').text()).toBe('5') // count 2 + review_count 3
  })

  it('掛載後資格由假轉真（能力更新）：補打端點並補上卡片', async () => {
    setUserRoles(['user'], false)
    setCards({ 'pending-approvals': { value: 1, count: 1, review_count: 0 } })

    const wrapper = mountDashboard()
    await flushPromises()
    expect(cardCalls()).not.toContain('pending-approvals')
    expect(wrapper.text()).not.toContain('待審申請')

    setUserRoles(['user'], true) // 能力更新（例如重新取得 /auth/me）
    await flushPromises()

    expect(cardCalls()).toContain('pending-approvals')
    expect(wrapper.text()).toContain('待審申請')
  })

  it('掛載後資格由真轉假：卡片消失且不再取數', async () => {
    setUserRoles(['user'], true)
    setCards({ 'pending-approvals': { value: 6, count: 6, review_count: 0 } })

    const wrapper = mountDashboard()
    await flushPromises()
    expect(wrapper.text()).toContain('待審申請')
    const callsBefore = cardCalls().filter((k) => k === 'pending-approvals').length

    setUserRoles(['user'], false)
    await flushPromises()

    expect(wrapper.text()).not.toContain('待審申請')
    expect(cardCalls().filter((k) => k === 'pending-approvals').length).toBe(callsBefore)
  })

  it('快取殘留 approver 角色但能力不含審核點：不打端點、不出現卡片', async () => {
    setUserRoles(['user', 'approver'], false)

    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardCalls()).not.toContain('pending-approvals')
    expect(wrapper.text()).not.toContain('待審申請')
  })

  it('plain user sees my pending requests count card', async () => {
    setUserRoles(['user'])
    // 件數是 pending 全量，不再由前 200 筆的陣列長度推算
    setCards({ 'my-pending-requests': { value: 2, filters: { status: 'pending' } } })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('我的申請待審')
    expect(wrapper.find('[data-card="my-pending-requests"] .stat-value').text()).toBe('2')
    expect(text).toContain('可連資產')
    expect(cardCalls()).not.toContain('pending-approvals')
    await wrapper.find('[data-card="my-pending-requests"]').trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith({ path: '/my-requests', query: { status: 'pending' } })
  })

  // —— 每日安全審閱卡（只提醒與提供入口，簽核在操作日誌頁的抽屜）——

  const REVIEW_HISTORY_ROUTE = { path: '/audit-logs', query: { tab: 'reviews' } }
  const dayRoute = (date) => ({ path: '/audit-logs', query: { tab: 'reviews', date } })

  it('功能未開啟時卡片說明開啟方式；admin 有前往安全政策的連結', async () => {
    setUserRoles(['admin'])
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: false, timezone_state: TZ_STATE, pending_count: 0 } })

    const wrapper = mountDashboard()
    await flushPromises()

    const card = wrapper.find('.review-card')
    expect(card.exists()).toBe(true)
    expect(card.text()).toContain('每日審閱簽核尚未開啟')
    expect(card.text()).toContain('從開啟當天起算')
    expect(card.find('.review-count').exists()).toBe(false)
    const link = card.find('[data-test="dr-card-policy-link"]')
    expect(link.text()).toBe('到安全政策開啟')
    await link.trigger('click')
    expect(routerPushMock.mock.calls).toEqual([['/security-policies']])
  })

  it('功能未開啟時 auditor 只看到請洽管理員，沒有政策頁連結', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: false, timezone_state: TZ_STATE, pending_count: 0 } })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.find('[data-test="dr-card-policy-link"]').exists()).toBe(false)
    expect(wrapper.find('.review-card').text()).toContain('請洽系統管理員開啟')
  })

  it('renders three snapshot counts with links when enabled and unsigned', async () => {
    setUserRoles(['admin'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('每日安全審閱')
    expect(text).toContain('2026-10-10')
    expect(text).toContain('登入失敗')
    expect(text).toContain('未審閱告警')
    expect(text).toContain('高危操作')
    expect(text).toContain('待簽核')

    // 三計數可點（亦可鍵盤 Enter）導向各自原有頁面，不因卡片改版而改變
    const counts = wrapper.findAll('.review-count')
    expect(counts).toHaveLength(3)
    // 待簽：計數即時
    expect(wrapper.findAll('.review-count-value').map((v) => v.text())).toEqual(['3', '1', '5'])
    const expected = ['/audit-logs', '/alerts', '/audit-logs']
    for (const [i, target] of expected.entries()) {
      routerPushMock.mockClear()
      await counts[i].trigger('click')
      expect(routerPushMock.mock.calls).toEqual([[target]])
      routerPushMock.mockClear()
      await counts[i].trigger('keydown', { key: 'Enter' })
      expect(routerPushMock.mock.calls).toEqual([[target]])
    }
  })

  // 防：入口導向錯頁（例如只推 '/audit-logs' 落在操作日誌分頁），或入口不是真連結
  it('卡片標題是前往每日簽核分頁的真連結', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })

    const wrapper = mountDashboard()
    await flushPromises()

    const title = wrapper.find('a.review-title')
    expect(title.exists()).toBe(true)
    expect(title.attributes('href')).toBe('/audit-logs?tab=reviews')
    await title.trigger('click')
    expect(routerPushMock.mock.calls).toEqual([[REVIEW_HISTORY_ROUTE]])
    expect(title.text()).toContain('每日安全審閱')
    // 卡片日期載明所屬日，不以「今日」代稱
    expect(wrapper.find('.review-date').text()).toContain('2026-10-10')
    expect(wrapper.find('.review-card').text()).not.toContain('今日')
  })

  // 防：卡片上直接簽核，繞過「告警處置完才能簽」
  it('卡片不能直接簽：沒有備註欄與簽核按鈕，按鈕開啟該日抽屜', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })

    const wrapper = mountDashboard()
    await flushPromises()

    const card = wrapper.find('.review-card')
    expect(card.find('input').exists()).toBe(false)
    expect(card.find('textarea').exists()).toBe(false)
    expect(card.text()).not.toContain('簽核 2026-10-10')
    expect(card.find('[data-test="dr-card-hint"]').text()).toContain('還有 1 筆告警要先處置')
    const action = card.find('[data-test="dr-card-action"]')
    expect(action.text()).toBe('審閱並簽核')
    await action.trigger('click')
    expect(routerPushMock.mock.calls).toEqual([[dayRoute('2026-10-10')]])
    expect(signDailyReviewMock).not.toHaveBeenCalled()
  })

  // 防：卡片自己用「今天 −（所屬日＋1）」推算晚幾天，最早那天以舊時區切日時比清單多一天
  it('多日未簽的「晚幾天」取待簽清單第一列的值，與清單一致', async () => {
    setUserRoles(['auditor'])
    const multi = {
      ...enabledStatus,
      pending_count: 7,
      overdue_count: 6,
      earliest_pending_date: '2026-09-09',
      pending_dates: ['2026-09-09', '2026-10-05', '2026-10-06', '2026-10-07', '2026-10-08', '2026-10-09', '2026-10-10'],
    }
    getDailyReviewStatusMock.mockResolvedValue({ data: multi })
    // 今天 2026-10-11（UTC+8），但 09-09 以 UTC 切日、後端算出晚 30 天（前端推算會得 31）
    getDailyReviewPendingMock.mockResolvedValue({
      data: { items: [{ date: '2026-09-09', timezone: 'UTC', late_days: 30 }], total: 7 },
    })
    let wrapper = mountDashboard()
    await flushPromises()
    const line = () => wrapper.find('[data-test="dr-card-multi-line"]').text()
    expect(line()).toBe('有 7 天還沒簽核，最早的已晚 30 天：')
    expect(line()).not.toContain('31')
    wrapper.unmount()

    // 取不到清單時只寫天數，不自行推算晚幾天
    getDailyReviewPendingMock.mockRejectedValue(new Error('network down'))
    wrapper = mountDashboard()
    await flushPromises()
    expect(line()).toBe('有 7 天還沒簽核：')
  })

  it('只有昨日待簽時不查待簽清單', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })
    mountDashboard()
    await flushPromises()
    expect(getDailyReviewPendingMock).not.toHaveBeenCalled()
  })

  // 防：卡片按鈕落到昨日而跳過更早的未簽日
  it('多日未簽按鈕開啟最早一天', async () => {
    getDailyReviewPendingMock.mockResolvedValue({
      data: { items: [{ date: '2026-10-07', timezone: 'Asia/Taipei', late_days: 3 }], total: 4 },
    })
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({
      data: {
        ...enabledStatus,
        pending_count: 4,
        overdue_count: 3,
        earliest_pending_date: '2026-10-07',
        pending_dates: ['2026-10-07', '2026-10-08', '2026-10-09', '2026-10-10'],
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const card = wrapper.find('.review-card')
    expect(card.find('[data-test="dr-card-tag"]').text()).toBe('4 天未簽')
    expect(card.find('[data-test="dr-card-multi"]').text()).toContain('有 4 天還沒簽核，最早的已晚 3 天')
    expect(getDailyReviewPendingMock).toHaveBeenCalledWith({ page: 1, page_size: 1 }, { skipErrorToast: true })
    const chips = card.findAll('[data-test="dr-card-date"]')
    expect(chips.map((c) => c.text())).toEqual(['10-07', '10-08', '10-09', '10-10'])
    expect(chips[1].attributes('href')).toBe('/audit-logs?tab=reviews&date=2026-10-08')
    await chips[1].trigger('click')
    expect(routerPushMock.mock.calls).toEqual([[dayRoute('2026-10-08')]])

    routerPushMock.mockClear()
    const action = card.find('[data-test="dr-card-action"]')
    expect(action.text()).toBe('從 10-07 開始補簽')
    await action.trigger('click')
    expect(routerPushMock.mock.calls).toEqual([[{ path: '/audit-logs', query: { tab: 'reviews', date: '2026-10-07' } }]])
  })

  it('結算中提示可簽時刻，按鈕照常開抽屜', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({
      data: { ...enabledStatus, yesterday: { ...yesterdayLive, signable: false } },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.find('[data-test="dr-card-tag"]').text()).toBe('結算中')
    // 可簽時刻以該日的切日時區呈現：16:30Z＝00:30（UTC+8）
    expect(wrapper.find('[data-test="dr-card-hint"]').text()).toContain('00:30 起可簽')
    expect(wrapper.find('[data-test="dr-card-action"]').exists()).toBe(true)
  })

  // 防：已簽卡片若顯示即時計數，簽核後新增的事件會讓卡片數字與歷次簽核那筆不一致
  it('全部完成時顯示固化計數、簽核者、時刻與近 30 天簽核率，並有檢視簽核紀錄連結', async () => {
    setUserRoles(['admin'])
    getDailyReviewStatusMock.mockResolvedValue({
      data: {
        ...enabledStatus,
        pending_count: 0,
        earliest_pending_date: null,
        pending_dates: [],
        stats_30d: { sign_rate_percent: 96 },
        yesterday: {
          ...yesterdayLive,
          signed: true,
          counts_fixed: true,
          counts: { date: '2026-10-10', login_failures: 352, unreviewed_alerts: 0, high_risk_ops: 3 },
          review: {
            review_date: '2026-10-10',
            reviewer_name: 'auditor01',
            signed_at: '2026-10-11T01:05:00Z',
            timezone: 'Asia/Taipei',
          },
        },
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.findAll('.review-count-value').map((v) => v.text())).toEqual(['352', '0', '3'])
    const signed = wrapper.find('[data-test="dr-card-signed"]').text()
    expect(signed).toContain('auditor01 於 2026/10/11 09:05 (UTC+8) 簽核')
    expect(signed).toContain('近 30 天簽核率 96%')
    const link = wrapper.find('.review-signed a.review-link')
    expect(link.text()).toBe('檢視簽核紀錄')
    expect(link.attributes('href')).toBe('/audit-logs?tab=reviews')
    await link.trigger('click')
    expect(routerPushMock.mock.calls).toEqual([[REVIEW_HISTORY_ROUTE]])
    expect(wrapper.find('[data-test="dr-card-tag"]').text()).toBe('已簽核')
  })

  it('固化快照缺少某個計數時照實呈現「—」，不以即時值或 0 填補', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({
      data: {
        ...enabledStatus,
        pending_count: 0,
        yesterday: {
          ...yesterdayLive,
          signed: true,
          counts_fixed: true,
          counts: { date: '2026-10-10', login_failures: 352, unreviewed_alerts: 1 },
          review: { review_date: '2026-10-10', reviewer_name: 'a', signed_at: '2026-10-11T01:05:00Z', timezone: 'Asia/Taipei' },
        },
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.findAll('.review-count-value').map((v) => v.text())).toEqual(['352', '1', '—'])
  })

  // 防：剛開啟功能、昨日還不在範圍時，卡片套用「全部完成」版面而捏造出簽核者與簽核率
  it('剛開啟、昨日不在範圍時不捏造簽核者', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({
      data: {
        ...enabledStatus,
        pending_count: 0,
        overdue_count: 0,
        earliest_pending_date: null,
        pending_dates: [],
        stats_30d: { sign_rate_percent: null },
        yesterday: { ...yesterdayLive, in_scope: false, signed: false, review: null },
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.find('.review-card').text()
    expect(text).not.toMatch(/於 .* 簽核/)
    expect(text).not.toContain('%')
    expect(wrapper.find('[data-test="dr-card-none"]').exists()).toBe(true)
  })

  it('user role never queries daily review status nor renders the card', async () => {
    // 狀態端點掛 audit:view，一般 user 呼叫必 403 且全域攔截器會 toast
    //「權限不足」——根本不該發出請求
    setUserRoles(['user'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(getDailyReviewStatusMock).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('每日安全審閱')
    expect(wrapper.find('.review-card').exists()).toBe(false)
  })

  it('auditor keeps read-only review card (no sign controls without test double)', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })

    const wrapper = mountDashboard()
    await flushPromises()

    // auditor 有 audit:view 與 alert:manage：查詢照發、卡片照渲染
    expect(getDailyReviewStatusMock).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('每日安全審閱')
  })

  // —— 錄影佔用卡——

  it('auditor sees the recording-storage card with a formatted disk size', async () => {
    setUserRoles(['auditor'])
    // 931,724 B ＝ QUICKSTART 6.6 的對帳實測值（.cast 743,174 ＋ .guac 188,550）
    setCards({ 'recording-storage': { value: 931724, unit: 'bytes' } })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardCalls()).toContain('recording-storage')
    const text = wrapper.text()
    expect(text).toContain('錄影佔用')
    expect(text).toContain('909.9 KB')
    // 誠實邊界：不得以百分比／進度形態呈現，也不得宣稱代表可用磁碟空間
    expect(text).not.toContain('%')
    expect(text).not.toContain('可用空間')
    expect(text).not.toContain('使用率')
    expect(text).not.toContain('上限')
    expect(wrapper.find('.el-progress').exists()).toBe(false)
  })

  it('plain user neither renders the card nor issues the recordings/stats request', async () => {
    // 端點掛 audit:view：一般 user 呼叫必 403。**斷言請求未發生**而非只斷言
    // 卡片不顯示——「卡片不顯示但請求照發」是同型缺陷的常見形態
    setUserRoles(['user'])
    setCards({ 'recording-storage': { value: 931724, unit: 'bytes' } })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(cardCalls()).not.toContain('recording-storage')
    expect(wrapper.text()).not.toContain('錄影佔用')
  })

  it('storage card is not clickable while the other first-row cards still navigate', async () => {
    setUserRoles(['admin'])
    setCards({ 'recording-storage': { value: 1024, unit: 'bytes' } })

    const wrapper = mountDashboard()
    await flushPromises()

    const firstRowCards = wrapper.findAll('.stat-card')
    const storageCard = firstRowCards.find((card) => card.text().includes('錄影佔用'))
    expect(storageCard).toBeTruthy()
    expect(storageCard.classes()).not.toContain('stat-card-clickable')
    await storageCard.trigger('click')
    expect(routerPushMock).not.toHaveBeenCalled()

    // 對照組：既有卡的跳轉行為未變
    const assetCard = firstRowCards.find((card) => card.text().includes('資產總數'))
    expect(assetCard.classes()).toContain('stat-card-clickable')
    await assetCard.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith({ path: '/assets', query: {} })
  })

  it('renders 未取得 rather than 0 when the stats query fails', async () => {
    setUserRoles(['admin'])
    setCards({ 'recording-storage': new Error('network down') })

    const wrapper = mountDashboard()
    await flushPromises()

    const card = wrapper.find('[data-card="recording-storage"]')
    expect(card.find('.stat-value').text()).toBe('未取得')
    expect(card.text()).toContain('錄影佔用')
  })
})
