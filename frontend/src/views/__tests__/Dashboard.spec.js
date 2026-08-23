import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Dashboard from '../Dashboard.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const getAssetListMock = vi.fn()
const getSessionStatisticsMock = vi.fn()
const getActiveSessionsMock = vi.fn()
const getMyConnectionsMock = vi.fn()
const searchAlertsMock = vi.fn()
const getDailyReviewStatusMock = vi.fn()
const signDailyReviewMock = vi.fn()
const getMyAccessRequestsMock = vi.fn()
const getPendingAccessRequestCountMock = vi.fn()
const getAccessReviewsMock = vi.fn()
const getRecordingStatsMock = vi.fn()
const routerPushMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
}))

vi.mock('@/api/sessions', () => ({
  getSessionStatistics: (...args) => getSessionStatisticsMock(...args),
  getActiveSessions: (...args) => getActiveSessionsMock(...args),
  getRecordingStats: (...args) => getRecordingStatsMock(...args),
}))

vi.mock('@/api/myConnections', () => ({
  getMyConnections: (...args) => getMyConnectionsMock(...args),
}))

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
}))

vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: (...args) => getDailyReviewStatusMock(...args),
  signDailyReview: (...args) => signDailyReviewMock(...args),
}))

vi.mock('@/api/accessRequests', () => ({
  getMyAccessRequests: (...args) => getMyAccessRequestsMock(...args),
  getPendingAccessRequestCount: (...args) => getPendingAccessRequestCountMock(...args),
}))

vi.mock('@/api/access-reviews', () => ({
  getAccessReviews: (...args) => getAccessReviewsMock(...args),
}))

const setUserRoles = (roles) => {
  localStorage.setItem('user', JSON.stringify({ username: 'tester', roles }))
}

const enabledStatus = {
  enabled: true,
  signed: false,
  snapshot: {
    date: '2026-07-13',
    login_failures: 2,
    unreviewed_alerts: 1,
    high_risk_ops: 3,
  },
}

const mountDashboard = () =>
  mount(Dashboard, {
    global: {
      plugins: [ElementPlus],
      mocks: { $router: { push: routerPushMock } },
    },
  })

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    searchAlertsMock.mockResolvedValue({ data: [], total: 0 })
    getAssetListMock.mockResolvedValue({ total: 0, data: [] })
    getSessionStatisticsMock.mockResolvedValue({})
    getActiveSessionsMock.mockResolvedValue([])
    getMyConnectionsMock.mockResolvedValue({ data: [], total: 0 })
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: false } })
    getMyAccessRequestsMock.mockResolvedValue({ data: [] })
    getPendingAccessRequestCountMock.mockResolvedValue({ count: 0, review_count: 0 })
    getAccessReviewsMock.mockResolvedValue({
      data: [],
      last_review_days_ago: 10,
      review_period_days: 180,
      overdue: false,
    })
    getRecordingStatsMock.mockResolvedValue({
      total_size: 0,
      count: 0,
      oldest_date: '',
      newest_date: '',
    })
  })

  it('renders statistics from APIs', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({ total: 12, data: [] })
    getSessionStatisticsMock.mockResolvedValue({
      active_sessions: 3,
      today_sessions: 7,
      total_sessions: 99,
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('12')
    expect(text).toContain('3')
    expect(text).toContain('7')
    expect(text).toContain('99')
  })

  it('renders today alerts count from alerts API with start_time of today', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({ total: 0, data: [] })
    getSessionStatisticsMock.mockResolvedValue({})
    searchAlertsMock.mockResolvedValue({ data: [], total: 5 })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(searchAlertsMock).toHaveBeenCalledWith({
      start_time: expect.any(String),
      page: 1,
      page_size: 1,
    })
    expect(wrapper.text()).toContain('今日告警')
    expect(wrapper.text()).toContain('5')
  })

  it('falls back to 0 today alerts when alerts API fails', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({ total: 0, data: [] })
    getSessionStatisticsMock.mockResolvedValue({})
    searchAlertsMock.mockRejectedValue(new Error('network down'))

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.text()).toContain('今日告警')
    expect(wrapper.vm.todayAlerts).toBe(0)
  })

  it('survives API failure without crashing and stops loading', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockRejectedValue(new Error('network down'))
    getSessionStatisticsMock.mockRejectedValue(new Error('network down'))
    searchAlertsMock.mockRejectedValue(new Error('network down'))

    const wrapper = mountDashboard()
    await flushPromises()

    // 頁面仍渲染統計卡（零值），不拋例外
    expect(wrapper.text()).toContain('資產總數')
    expect(wrapper.vm.loading).toBe(false)
  })

  it('renders quick action cards', async () => {
    setUserRoles(['admin'])
    getAssetListMock.mockResolvedValue({ total: 0, data: [] })
    getSessionStatisticsMock.mockResolvedValue({})

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
    getAssetListMock.mockResolvedValue({ total: 4, data: [] })
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
    expect(getSessionStatisticsMock).not.toHaveBeenCalled()
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

  it('multi-role [user,auditor] account keeps the privileged dashboard', async () => {
    setUserRoles(['user', 'auditor'])

    const wrapper = mountDashboard()
    await flushPromises()

    // 有效角色為 auditor（admin > auditor > user），不落入自助模式
    expect(getSessionStatisticsMock).toHaveBeenCalled()
    expect(getActiveSessionsMock).toHaveBeenCalled()
    expect(getMyConnectionsMock).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('進行中連線')
  })

  // —— 人設待辦卡——

  it('auditor sees audit-backlog cards with counts from existing endpoints', async () => {
    setUserRoles(['auditor'])
    searchAlertsMock.mockImplementation((params) =>
      Promise.resolve(
        params?.unreviewed === 'true' ? { data: [], total: 7 } : { data: [], total: 0 }
      )
    )
    getActiveSessionsMock.mockResolvedValue([
      { id: 1, protocol: 'ssh', recording_error: '磁碟滿' },
      { id: 2, protocol: 'rdp' },
      { id: 3, protocol: 'ssh', recording_error: '目錄不可寫' },
    ])
    getAccessReviewsMock.mockResolvedValue({
      data: [],
      last_review_days_ago: 200,
      review_period_days: 180,
      overdue: true,
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(searchAlertsMock).toHaveBeenCalledWith({
      unreviewed: 'true',
      page: 1,
      page_size: 1,
    })
    const text = wrapper.text()
    expect(text).toContain('未審閱告警')
    expect(text).toContain('7')
    expect(text).toContain('錄影失敗連線')
    expect(text).toContain('2') // 三筆活動連線中兩筆帶 recording_error
    expect(text).toContain('上次存取複審（天，已逾期）')
    expect(text).toContain('200')
    // auditor 非 approver/admin：不打審核端點、不見待審卡
    expect(getPendingAccessRequestCountMock).not.toHaveBeenCalled()
    expect(text).not.toContain('待審申請')
  })

  it('user+approver overlay adds pending-approvals card alongside self-service cards', async () => {
    setUserRoles(['user', 'approver'])
    getPendingAccessRequestCountMock.mockResolvedValue({ count: 3, review_count: 1 })
    getMyAccessRequestsMock.mockResolvedValue({
      data: [
        { id: 1, status: 'pending' },
        { id: 2, status: 'approved' },
      ],
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    // 疊加聯集：自助卡與待審卡並存
    expect(text).toContain('我的申請待審')
    expect(text).toContain('待審申請')
    expect(text).toContain('4') // count 3 + review_count 1
    // 仍不呼叫稽核端點
    expect(getSessionStatisticsMock).not.toHaveBeenCalled()
    expect(searchAlertsMock).not.toHaveBeenCalled()
  })

  it('plain user sees my pending requests count card', async () => {
    setUserRoles(['user'])
    getMyAccessRequestsMock.mockResolvedValue({
      data: [
        { id: 1, status: 'pending' },
        { id: 2, status: 'pending' },
        { id: 3, status: 'rejected' },
      ],
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('我的申請待審')
    expect(text).toContain('2')
    expect(text).toContain('可連資產')
    expect(getPendingAccessRequestCountMock).not.toHaveBeenCalled()
  })

  // —— 每日安全審閱簽核卡——

  it('does not render daily review card when feature disabled', async () => {
    setUserRoles(['admin'])
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: false } })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.text()).not.toContain('每日安全審閱')
    expect(wrapper.find('.review-card').exists()).toBe(false)
  })

  it('renders three snapshot counts with links when enabled and unsigned', async () => {
    setUserRoles(['admin'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })

    const wrapper = mountDashboard()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('每日安全審閱')
    expect(text).toContain('2026-07-13')
    expect(text).toContain('登入失敗')
    expect(text).toContain('未審閱告警')
    expect(text).toContain('高危操作')
    expect(text).toContain('待簽核')

    // 三計數可點導向對應頁面
    const counts = wrapper.findAll('.review-count')
    expect(counts).toHaveLength(3)
    await counts[0].trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/audit-logs')
    await counts[1].trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/alerts')
  })

  it('signs review with note and switches to signed state', async () => {
    setUserRoles(['admin'])
    getDailyReviewStatusMock
      .mockResolvedValueOnce({ data: enabledStatus })
      .mockResolvedValueOnce({
        data: {
          ...enabledStatus,
          signed: true,
          review: {
            reviewer_name: 'admin',
            created_at: '2026-07-13T09:30:00Z',
            note: '一切正常',
          },
        },
      })
    signDailyReviewMock.mockResolvedValue({})

    const wrapper = mountDashboard()
    await flushPromises()

    wrapper.vm.reviewNote = '一切正常'
    const signButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('簽核今日審閱'))
    expect(signButton).toBeTruthy()

    await signButton.trigger('click')
    await flushPromises()

    expect(signDailyReviewMock).toHaveBeenCalledWith({ note: '一切正常' })
    const text = wrapper.text()
    expect(text).toContain('已簽核')
    expect(text).toContain('admin')
    expect(text).toContain('一切正常')
  })

  it('refreshes status when sign conflicts with 409 (他人已先簽核)', async () => {
    setUserRoles(['auditor'])
    getDailyReviewStatusMock.mockResolvedValue({ data: enabledStatus })
    const conflictError = new Error('conflict')
    conflictError.response = {
      status: 409,
      data: { error: '當日已完成簽核（09:30 由 admin 簽核）' },
    }
    signDailyReviewMock.mockRejectedValue(conflictError)

    const wrapper = mountDashboard()
    await flushPromises()
    expect(getDailyReviewStatusMock).toHaveBeenCalledTimes(1)

    await wrapper.vm.handleSignReview()
    await flushPromises()

    // 409：刷新簽核狀態（後端訊息由全域攔截器 toast）
    expect(getDailyReviewStatusMock).toHaveBeenCalledTimes(2)
    expect(wrapper.vm.signing).toBe(false)
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
    getRecordingStatsMock.mockResolvedValue({ total_size: 931724, count: 12 })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(getRecordingStatsMock).toHaveBeenCalled()
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
    getRecordingStatsMock.mockResolvedValue({ total_size: 931724, count: 12 })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(getRecordingStatsMock).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('錄影佔用')
  })

  it('storage card is not clickable while the other first-row cards still navigate', async () => {
    setUserRoles(['admin'])
    getRecordingStatsMock.mockResolvedValue({ total_size: 1024, count: 1 })

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
    expect(routerPushMock).toHaveBeenCalledWith('/assets')
  })

  it('renders a dash rather than 0 when the stats query fails', async () => {
    setUserRoles(['admin'])
    getRecordingStatsMock.mockRejectedValue(new Error('network down'))

    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.vm.recordingStorageBytes).toBe(null)
    expect(wrapper.text()).toContain('錄影佔用')
  })
})
