import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { reactive } from 'vue'
import ElementPlus from 'element-plus'
import AuditLogs from '../AuditLogs.vue'

// 本檔每測掛整頁且從不卸載，殘留元件在 document 上累積，單測耗時隨進度單調
// 上升——全量並行時末幾格逼近 vitest 20s 上限而間歇轉紅（單跑穩綠）。
// 與 Assets.spec.js 同型根因，治法相同：逐測卸載使成本不隨測試序遞增。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（不影響渲染結果驗證）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

// 全量 ElementPlus + 多 el-table 掛載貼近預設 5s 上限，放寬本檔 timeout
vi.setConfig({ testTimeout: 20_000 })

// 由某個設定的記錄連結進頁時，網址上的篩選要被讀走。逐測改寫 query 即可。
// reactive：頁面監聽 route.query，同頁改網址（側欄徽章、抽屜連結）也要套用
const routeState = reactive({ query: {} })
const routerPushMock = vi.fn()
vi.mock('vue-router', () => ({
  useRoute: () => routeState,
  useRouter: () => ({ push: routerPushMock }),
}))

const getAuditLogsMock = vi.fn()
const exportAuditEvidenceMock = vi.fn()
const getDailyReviewsMock = vi.fn()
const getDailyReviewStatusMock = vi.fn()
const getDailyReviewPendingMock = vi.fn()
const getDailyReviewPendingCountMock = vi.fn()
const getDailyReviewDayMock = vi.fn()
const getDailyReviewStatsMock = vi.fn()
const getAuditFailuresMock = vi.fn()
const verifyAuditIntegrityMock = vi.fn()

vi.mock('@/api/audit', () => ({
  getAuditLogs: (...args) => getAuditLogsMock(...args),
}))

vi.mock('@/api/auditExport', () => ({
  exportAuditEvidence: (...args) => exportAuditEvidenceMock(...args),
}))

vi.mock('@/api/dailyReviews', () => ({
  getDailyReviews: (...args) => getDailyReviewsMock(...args),
  getDailyReviewStatus: (...args) => getDailyReviewStatusMock(...args),
  getDailyReviewPending: (...args) => getDailyReviewPendingMock(...args),
  getDailyReviewPendingCount: (...args) => getDailyReviewPendingCountMock(...args),
  getDailyReviewDay: (...args) => getDailyReviewDayMock(...args),
  getDailyReviewStats: (...args) => getDailyReviewStatsMock(...args),
  signDailyReview: vi.fn(),
}))

vi.mock('@/api/auditFailures', () => ({
  getAuditFailures: (...args) => getAuditFailuresMock(...args),
}))

vi.mock('@/api/auditIntegrity', () => ({
  verifyAuditIntegrity: (...args) => verifyAuditIntegrityMock(...args),
}))

const sampleReviews = [
  {
    review_date: '2026-07-12T00:00:00Z',
    reviewer_name: 'auditor1',
    snapshot_json:
      '{"date":"2026-07-12","login_failures":2,"unreviewed_alerts":1,"high_risk_ops":3}',
    note: '無異常',
    created_at: '2026-07-12T09:30:00Z',
  },
]

const sampleFailures = [
  {
    mechanism: 'syslog',
    started_at: '2026-07-12T08:00:00Z',
    ended_at: null,
    cause: 'connection refused',
    details: 'dial tcp 10.0.0.9:514',
  },
  {
    mechanism: 'audit_db',
    started_at: '2026-07-10T02:00:00Z',
    ended_at: '2026-07-10T02:05:00Z',
    cause: 'disk full',
    details: '',
  },
]

const setUserRoles = (roles) => {
  localStorage.setItem('user', JSON.stringify({ username: 'tester', roles }))
}

const mountAuditLogs = () =>
  mount(AuditLogs, {
    global: {
      plugins: [ElementPlus],
    },
  })

describe('AuditLogs', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    routeState.query = {}
    getAuditLogsMock.mockResolvedValue({ data: [], total: 0 })
    getDailyReviewsMock.mockResolvedValue({ data: { items: [], total: 0 } })
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: true, pending_count: 0, overdue_count: 0 } })
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [], total: 0 } })
    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 0, overdue_count: 0 } })
    getDailyReviewStatsMock.mockResolvedValue({ data: null })
    getDailyReviewDayMock.mockResolvedValue({ data: { date: '2026-10-07', status: 'pending', unreviewed_alerts: [], login_failures: { total: 0, items: [] }, high_risk_ops: { total: 0, items: [] } } })
    getAuditFailuresMock.mockResolvedValue({ data: { items: [], total: 0 } })
  })

  // 首用路徑實走發現：成功的操作也可能帶訊息，掛在「錯誤訊息」底下並塗紅，
  // 會讓一筆成功的紀錄在稽核眼裡讀成失敗
  it('成功的紀錄把訊息放在附註，失敗的仍是錯誤訊息', async () => {
    setUserRoles(['auditor'])
    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.showDetails({
      id: 1,
      status: 'success',
      action: 'update',
      resource: 'security_policy',
      created_at: '2026-09-09T01:02:03Z',
      error_msg: '已改以備援管道送出',
    })
    await flushPromises()

    let labels = wrapper.findAll('.el-descriptions__label').map((n) => n.text())
    expect(labels).toContain('附註')
    expect(labels).not.toContain('錯誤訊息')
    expect(wrapper.find('.el-alert').classes()).toContain('el-alert--info')

    wrapper.vm.showDetails({
      id: 2,
      status: 'failure',
      action: 'update',
      resource: 'security_policy',
      created_at: '2026-09-09T01:02:03Z',
      error_msg: '寫入失敗',
    })
    await flushPromises()

    labels = wrapper.findAll('.el-descriptions__label').map((n) => n.text())
    expect(labels).toContain('錯誤訊息')
    expect(labels).not.toContain('附註')
    expect(wrapper.find('.el-alert').classes()).toContain('el-alert--error')
  })

  it('fetches logs on mount and renders three tabs', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAuditLogs()
    await flushPromises()

    expect(getAuditLogsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })

    const tabLabels = wrapper.findAll('.el-tabs__item').map((tab) => tab.text())
    expect(tabLabels).toContain('操作日誌')
    expect(tabLabels).toContain('每日簽核')
    expect(tabLabels).toContain('失效事件')
    // 頁籤切換前不預載其他頁籤資料
    expect(getDailyReviewsMock).not.toHaveBeenCalled()
    expect(getAuditFailuresMock).not.toHaveBeenCalled()
  })

  // 每日簽核分頁的內容是工作區元件（清單、統計與抽屜的細節在元件自己的 spec）。
  // 頁面這一層要保證：切到分頁才掛載並取數，切回來會重取
  it('切到每日簽核分頁才掛載工作區並取數，再切回來會重取', async () => {
    setUserRoles(['auditor'])
    getDailyReviewsMock.mockResolvedValue({ data: { items: sampleReviews, total: 1 } })

    const wrapper = mountAuditLogs()
    await flushPromises()
    expect(wrapper.find('[data-test="dr-workspace"]').exists()).toBe(false)

    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.handleTabChange('reviews')
    await flushPromises()

    expect(wrapper.find('[data-test="dr-workspace"]').exists()).toBe(true)
    expect(getDailyReviewsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(getDailyReviewPendingMock).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('auditor1')

    wrapper.vm.activeTab = 'logs'
    wrapper.vm.handleTabChange('logs')
    await flushPromises()
    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.handleTabChange('reviews')
    await flushPromises()
    expect(getDailyReviewPendingMock).toHaveBeenCalledTimes(2)
  })

  // cause_code 為權威表述，散文 cause 降為 fallback
  it('renders cause from cause_code lexicon, falling back to prose for unknown/absent codes', async () => {
    setUserRoles(['auditor'])
    getAuditFailuresMock.mockResolvedValue({
      data: {
        items: [
          {
            mechanism: 'syslog_forward',
            started_at: '2026-07-12T08:00:00Z',
            ended_at: null,
            cause_code: 'syslog_connect_failed',
            // 散文刻意與詞庫短語不同字，才驗得出「碼優先於散文」
            cause: '存量散文不應顯示',
            cause_params: { detail: 'dial tcp 10.0.0.9:514' },
            details: 'dial tcp 10.0.0.9:514',
          },
          {
            mechanism: 'audit_write',
            started_at: '2026-07-11T02:00:00Z',
            ended_at: '2026-07-11T02:05:00Z',
            cause_code: 'future_unmapped_cause',
            cause: '未來新增但前端未跟上的散文',
            details: '',
          },
          {
            mechanism: 'audit_write',
            started_at: '2026-07-10T02:00:00Z',
            ended_at: '2026-07-10T02:05:00Z',
            cause: '存量列只有散文',
            details: '',
          },
        ],
        total: 3,
      },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()
    wrapper.vm.activeTab = 'failures'
    wrapper.vm.handleTabChange('failures')
    await flushPromises()

    const text = wrapper.text()
    // 已知碼：顯示詞庫短語，不顯裸碼、不顯後端散文
    expect(text).toContain('syslog 轉發連線失敗')
    expect(text).not.toContain('syslog_connect_failed')
    expect(text).not.toContain('存量散文不應顯示')
    // 未知碼／無碼：退回散文欄（不吞資訊、不顯裸碼）
    expect(text).toContain('未來新增但前端未跟上的散文')
    expect(text).not.toContain('future_unmapped_cause')
    expect(text).toContain('存量列只有散文')
  })

  it('renders audit failures distinguishing ongoing from recovered', async () => {
    setUserRoles(['auditor'])
    getAuditFailuresMock.mockResolvedValue({
      data: { items: sampleFailures, total: 2 },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.activeTab = 'failures'
    wrapper.vm.handleTabChange('failures')
    await flushPromises()

    expect(getAuditFailuresMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    const text = wrapper.text()
    expect(text).toContain('syslog')
    expect(text).toContain('connection refused')
    // 進行中（ended_at 為 null）標紅 tag；已結束顯示已恢復
    expect(text).toContain('進行中')
    expect(text).toContain('已恢復')
    expect(wrapper.find('.el-tag--danger').exists()).toBe(true)
    expect(wrapper.find('.el-tag--success').exists()).toBe(true)
  })

  it('hides integrity verify button for non-admin users', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAuditLogs()
    await flushPromises()

    const verifyButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('完整性驗證'))
    expect(verifyButton).toBeFalsy()
  })

  it('shows integrity verify button for admin and defaults range to last 7 days', async () => {
    setUserRoles(['admin'])

    const wrapper = mountAuditLogs()
    await flushPromises()

    const verifyButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('完整性驗證'))
    expect(verifyButton).toBeTruthy()

    await verifyButton.trigger('click')
    await flushPromises()

    expect(wrapper.vm.integrityDialogVisible).toBe(true)
    const range = wrapper.vm.integrityRange
    expect(range).toHaveLength(2)
    expect(range[0]).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(range[1]).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    const spanDays =
      (new Date(range[1]) - new Date(range[0])) / (24 * 60 * 60 * 1000)
    expect(spanDays).toBe(6)
  })

  it('runs integrity verify and renders four counts with success state', async () => {
    setUserRoles(['admin'])
    verifyAuditIntegrityMock.mockResolvedValue({
      data: {
        from: '2026-07-07',
        to: '2026-07-13',
        checked: 15,
        passed: 2,
        mismatched: 0,
        mismatched_ids: [],
        legacy: 13,
      },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.openIntegrityDialog()
    await wrapper.vm.runIntegrityVerify()
    await flushPromises()

    expect(verifyAuditIntegrityMock).toHaveBeenCalledWith({
      from: wrapper.vm.integrityRange[0],
      to: wrapper.vm.integrityRange[1],
    })
    const text = wrapper.text()
    expect(text).toContain('已檢查')
    expect(text).toContain('15')
    expect(text).toContain('通過')
    expect(text).toContain('歷史列')
    expect(text).toContain('13')
    expect(text).toContain('受檢列完整性驗證全數通過')
    // legacy 標註說明
    expect(text).toContain('無完整性標記')
  })

  it('shows red alert with mismatched ids when integrity check fails', async () => {
    setUserRoles(['admin'])
    verifyAuditIntegrityMock.mockResolvedValue({
      data: {
        from: '2026-07-07',
        to: '2026-07-13',
        checked: 10,
        passed: 8,
        mismatched: 2,
        mismatched_ids: [5, 9],
        legacy: 0,
      },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.openIntegrityDialog()
    await wrapper.vm.runIntegrityVerify()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('發現 2 筆完整性不符')
    expect(text).toContain('5、9')
    expect(wrapper.find('.el-alert--error').exists()).toBe(true)
    expect(wrapper.find('.integrity-stat-danger').exists()).toBe(true)
  })

  // 儀表板每日審閱卡片的「歷次簽核」入口以 ?tab=reviews 連進本頁。落地若停在
  // 操作日誌分頁，使用者會以為沒有簽核記錄——入口形同不存在
  it('帶 ?tab=reviews 進頁即落在每日簽核分頁，且只取簽核資料', async () => {
    setUserRoles(['auditor'])
    routeState.query = { tab: 'reviews' }
    getDailyReviewsMock.mockResolvedValue({
      data: { items: sampleReviews, total: 1 },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()

    expect(wrapper.vm.activeTab).toBe('reviews')
    expect(wrapper.find('.el-tabs__item.is-active').text()).toBe('每日簽核')
    // 分頁內容是每日簽核工作區
    expect(wrapper.find('[data-test="dr-workspace"]').exists()).toBe(true)
    expect(getDailyReviewsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(getAuditLogsMock).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('auditor1')
  })

  // 防：側欄徽章與抽屜內的「在操作日誌查看全部」都是同頁改 query；
  // 只在掛載時讀一次網址的話，這些入口等於失效
  it('同頁改 query 切換分頁並開啟指定日抽屜', async () => {
    setUserRoles(['auditor'])
    routeState.query = { tab: 'logs' }

    const wrapper = mountAuditLogs()
    await flushPromises()
    expect(wrapper.vm.activeTab).toBe('logs')

    routeState.query = { tab: 'reviews', date: '2026-10-07' }
    await flushPromises()

    expect(wrapper.vm.activeTab).toBe('reviews')
    expect(wrapper.find('.el-tabs__item.is-active').text()).toContain('每日簽核')
    expect(getDailyReviewDayMock).toHaveBeenCalledWith('2026-10-07')

    // 格式錯的日期不開抽屜
    getDailyReviewDayMock.mockClear()
    routeState.query = { tab: 'reviews', date: '2026-1-7' }
    await flushPromises()
    expect(getDailyReviewDayMock).not.toHaveBeenCalled()
  })

  it('同頁帶入排他尾端並清除舊篩選', async () => {
    setUserRoles(['auditor'])
    routeState.query = { tab: 'logs', start_time: '2026-10-01T00:00:00+08:00', end_time: '2026-10-01T12:00:00+08:00' }

    const wrapper = mountAuditLogs()
    await flushPromises()
    expect(getAuditLogsMock).toHaveBeenLastCalledWith(expect.objectContaining({
      start_time: '2026-10-01T00:00:00+08:00',
      end_time: '2026-10-01T12:00:00+08:00',
    }))
    expect(wrapper.find('[data-test="end-before-tag"]').exists()).toBe(false)

    getAuditLogsMock.mockClear()
    routeState.query = {
      tab: 'logs',
      start_time: '2026-10-10T00:00:00+08:00',
      end_before: '2026-10-11T00:00:00+08:00',
    }
    await flushPromises()

    const params = getAuditLogsMock.mock.calls.at(-1)[0]
    expect(params.start_time).toBe('2026-10-10T00:00:00+08:00')
    expect(params.end_before).toBe('2026-10-11T00:00:00+08:00')
    expect(params).not.toHaveProperty('end_time')
    expect(wrapper.find('[data-test="end-before-tag"]').text()).toBe('不含結束時刻')

    // 手動改時間：回到含尾端的一般篩選，標示消失
    getAuditLogsMock.mockClear()
    wrapper.vm.timeRange = ['2026-10-10T00:00:00+08:00', '2026-10-10T12:00:00+08:00']
    wrapper.vm.onTimeRangeChange()
    await flushPromises()
    const manual = getAuditLogsMock.mock.calls.at(-1)[0]
    expect(manual.end_time).toBe('2026-10-10T12:00:00+08:00')
    expect(manual).not.toHaveProperty('end_before')
    expect(wrapper.find('[data-test="end-before-tag"]').exists()).toBe(false)
  })

  // 三步追證的最後一步：由設定名的記錄連結落地，這一頁要直接只看那個設定的變更。
  // 不預填的話連結會停在一份未篩選的日誌上，最後一步變成一場搜尋。
  it('帶 resource 與 key query 進頁即預填篩選並查詢', async () => {
    setUserRoles(['auditor'])
    routeState.query = { resource: 'security_policy', key: 'password_min_length' }

    const wrapper = mountAuditLogs()
    await flushPromises()

    expect(getAuditLogsMock).toHaveBeenCalledWith({
      page: 1,
      page_size: 20,
      resource: 'security_policy',
      key: 'password_min_length',
    })
    // 畫面要說得出現在只看什麼，否則使用者會以為日誌本來就只有這幾列
    expect(wrapper.find('.applied-filter').text()).toContain('密碼最小長度')
  })

  it('套用中的設定篩選可一鍵清除，清除後重新查詢且不再帶鍵', async () => {
    setUserRoles(['auditor'])
    routeState.query = { resource: 'security_policy', key: 'password_min_length' }

    const wrapper = mountAuditLogs()
    await flushPromises()
    getAuditLogsMock.mockClear()

    await wrapper.find('.applied-filter button').trigger('click')
    await flushPromises()

    expect(getAuditLogsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(wrapper.find('.applied-filter').exists()).toBe(false)
  })

  // 第二個值刻意取物件原型上的名字：以 `in` 比對會誤判為命中，
  // 把一個不是分類的字串原樣送給端點
  it.each(['not_a_resource', 'constructor'])(
    '網址上的分類不在值域內就不採用（%s）',
    async (resource) => {
      setUserRoles(['auditor'])
      routeState.query = { resource, key: 'password_min_length' }

      mountAuditLogs()
      await flushPromises()

      expect(getAuditLogsMock).toHaveBeenCalledWith({
        page: 1,
        page_size: 20,
        key: 'password_min_length',
      })
    }
  )
})
