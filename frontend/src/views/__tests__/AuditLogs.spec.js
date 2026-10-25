import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { reactive } from 'vue'
import ElementPlus, { ElMessage, ElNotification } from 'element-plus'
import AuditLogs from '../AuditLogs.vue'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { grantFor, permissionsFor } from '@/composables/__tests__/capabilityFixtures'

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
const createAuditExportJobMock = vi.fn()
const getDailyReviewsMock = vi.fn()
const getDailyReviewStatusMock = vi.fn()
const getDailyReviewPendingMock = vi.fn()
const getDailyReviewPendingCountMock = vi.fn()
const getDailyReviewDayMock = vi.fn()
const getDailyReviewStatsMock = vi.fn()
const getAuditFailuresMock = vi.fn()
const acceptPermissionStateMock = vi.fn()
const verifyAuditIntegrityMock = vi.fn()

vi.mock('@/api/audit', () => ({
  getAuditLogs: (...args) => getAuditLogsMock(...args),
}))

vi.mock('@/api/auditExport', () => ({
  createAuditExportJob: (...args) => createAuditExportJobMock(...args),
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
  acceptPermissionState: (...args) => acceptPermissionStateMock(...args),
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
  grantFor(roles)
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
    resetCapabilities()
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

  // 擋：沒有變更明細的系統紀錄（保留清除等）只剩一個空的「變更詳情」標題
  it('沒有 changes 的紀錄列原因與格式化的詳細資訊，不列變更詳情', async () => {
    setUserRoles(['auditor'])
    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.showDetails({
      id: 11,
      status: 'success',
      action: 'delete',
      resource: 'retention',
      created_at: '2026-10-07T01:00:00Z',
      details: '{"target":"audit_logs","deleted":42,"days":180}',
      reason_code: 'retention_purge',
      reason_params: { target: 'audit_logs', deleted: '42', days: '180' },
    })
    await flushPromises()

    const labels = wrapper.findAll('.el-descriptions__label').map((n) => n.text())
    expect(labels).toContain('原因')
    expect(labels).toContain('詳細資訊')
    expect(labels).not.toContain('變更詳情')
    expect(wrapper.find('[data-test="log-reason"]').text()).toBe('保留期限清除：操作日誌超過 180 天的資料，刪除 42 筆')
    expect(wrapper.find('[data-test="log-details-raw"]').text()).toBe('{\n  "target": "audit_logs",\n  "deleted": 42,\n  "days": 180\n}')
  })

  it('有 changes 的紀錄照舊列變更詳情，不列原因與詳細資訊', async () => {
    setUserRoles(['auditor'])
    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.showDetails({
      id: 12,
      status: 'success',
      action: 'update',
      resource: 'asset',
      created_at: '2026-10-07T01:00:00Z',
      path: '/api/v1/assets/3',
      details: JSON.stringify({ changes: [{ field: 'name', old: 'web-1', new: 'web-2' }] }),
    })
    await flushPromises()

    const labels = wrapper.findAll('.el-descriptions__label').map((n) => n.text())
    expect(labels).toContain('變更詳情')
    expect(labels).not.toContain('原因')
    expect(labels).not.toContain('詳細資訊')
    expect(wrapper.find('.change-item').text()).toContain('web-1')
    expect(wrapper.find('.change-item').text()).toContain('web-2')
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

  it('offers the permission-state confirmation to admins only, on an open alert of that item only', async () => {
    const alert = (over) => ({
      id: 7, mechanism: 'principal_state_integrity', started_at: '2026-10-16T01:00:00Z', ended_at: null,
      cause_code: 'principal_state_mismatch', cause: '', details: '',
      cause_params: { table: 'permission_state' }, ...over,
    })
    getAuditFailuresMock.mockResolvedValue({
      data: { items: [alert({}), alert({ id: 8, cause_params: { table: 'principals' } }), alert({ id: 9, ended_at: '2026-10-16T02:00:00Z' })], total: 3 },
    })
    acceptPermissionStateMock.mockResolvedValue({ data: { op_id: 'x', event_seq: 3 } })

    // 稽核員：沒有確認欄
    setUserRoles(['auditor'])
    const auditorView = mountAuditLogs()
    await flushPromises()
    auditorView.vm.activeTab = 'failures'
    auditorView.vm.handleTabChange('failures')
    await flushPromises()
    expect(auditorView.find('[data-test="permission-accept-open"]').exists()).toBe(false)

    // 超管：只有進行中的權限狀態告警那一列有鈕
    setUserRoles(['admin'])
    const wrapper = mountAuditLogs()
    await flushPromises()
    wrapper.vm.activeTab = 'failures'
    wrapper.vm.handleTabChange('failures')
    await flushPromises()
    const openButtons = wrapper.findAll('[data-test="permission-accept-open"]')
    expect(openButtons).toHaveLength(1)

    // 原因為空不可送出；填原因後送出，帶原因呼叫 API 並重新載入列表
    wrapper.vm.openPermissionAccept()
    wrapper.vm.permissionAcceptReason = '   '
    await wrapper.vm.submitPermissionAccept()
    expect(acceptPermissionStateMock).not.toHaveBeenCalled()
    wrapper.vm.permissionAcceptReason = '  已與維運人員核對  '
    await wrapper.vm.submitPermissionAccept()
    expect(acceptPermissionStateMock).toHaveBeenCalledWith({ reason: '已與維運人員核對' })
    expect(wrapper.vm.permissionAcceptVisible).toBe(false)
    expect(getAuditFailuresMock.mock.calls.length).toBeGreaterThanOrEqual(2)

    // 比對無法完成的告警：同一入口，對話框改說「重設比對基準」
    wrapper.vm.openPermissionAccept(alert({ cause_params: { table: 'permission_state', actual_hash: 'unknown' } }))
    await flushPromises()
    expect(wrapper.vm.permissionAcceptRebase).toBe(true)
    for (const locale of [zhTW, enUS, jaJP]) {
      for (const key of ['titleUnknown', 'hintUnknown', 'successUnknown']) {
        expect(locale.auditLogs.permissionAccept[key]).toBeTruthy()
      }
    }
    wrapper.vm.openPermissionAccept(alert({}))
    expect(wrapper.vm.permissionAcceptRebase).toBe(false)
  })

  it('ties the permission-state confirmation to the super-admin point, not to the connect bypass', async () => {
    getAuditFailuresMock.mockResolvedValue({
      data: {
        items: [{
          id: 7, mechanism: 'principal_state_integrity', started_at: '2026-10-16T01:00:00Z', ended_at: null,
          cause_code: 'principal_state_mismatch', cause: '', details: '', cause_params: { table: 'permission_state' },
        }],
        total: 1,
      },
    })
    const openButtonsWith = async (perms) => {
      resetCapabilities()
      setCapabilitiesForTests(perms)
      const view = mountAuditLogs()
      await flushPromises()
      view.vm.activeTab = 'failures'
      view.vm.handleTabChange('failures')
      await flushPromises()
      return view.findAll('[data-test="permission-accept-open"]').length
    }
    const admin = permissionsFor(['admin'])

    // 超管的完整投影：看得到
    expect(await openButtonsWith(admin)).toBe(1)
    // 連線豁免規則調整（拿掉 ui:connect-bypass）不影響超管
    expect(await openButtonsWith(admin.filter((p) => p !== 'ui:connect-bypass'))).toBe(1)
    // 只有連線豁免、沒有超管身分點：看不到
    expect(await openButtonsWith(admin.filter((p) => p !== 'ui:super-admin'))).toBe(0)
    // 勾滿可指派權限的非超管：看不到
    expect(await openButtonsWith(admin.filter((p) => !p.startsWith('ui:')))).toBe(0)
  })

  it('hides integrity verify button for non-admin users', async () => {
    // 按鈕依 audit:integrity_view 顯示；一般使用者範本不持有。auditor 範本持有該鍵
    //（後端 /audit-integrity/verify 本就放行），其顯示與否待裁決
    setUserRoles(['user'])

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

  describe('授權分級標記與同一請求篩選', () => {
    const markedRows = [
      {
        id: 21, user_id: 5, username: 'ops-lee', action: 'update', resource: 'user', status: 'success',
        created_at: '2026-10-07T01:00:00Z', client_ip: '10.0.0.5', path: '/api/v1/users/9/roles',
        request_id: 'abcdef12-3456-7890-abcd-ef1234567890',
        details: '{"event":"grant_change_graded","grant_marks":["management_grant"]}',
        reason_code: 'event.grant_change_graded', reason_params: { marks: 'management_grant' },
      },
      {
        id: 22, user_id: 5, username: 'ops-lee', action: 'update', resource: 'user', status: 'success',
        created_at: '2026-10-07T01:00:01Z', client_ip: '10.0.0.5', path: '/api/v1/users/5/roles',
        request_id: 'ffffffff-0000-0000-0000-000000000000',
        details: '{"event":"grant_change_graded","grant_marks":["self_authorization"]}',
      },
      {
        id: 23, user_id: 5, username: 'ops-lee', action: 'read', resource: 'asset', status: 'success',
        created_at: '2026-10-07T01:00:02Z', client_ip: '10.0.0.5', path: '/api/v1/assets', details: '',
      },
    ]

    it('帶授權分級標記的列顯示標籤，沒有標記的列沒有標籤', async () => {
      setUserRoles(['auditor'])
      getAuditLogsMock.mockResolvedValue({ data: markedRows, total: 3 })
      const wrapper = mountAuditLogs()
      await flushPromises()

      const rows = wrapper.findAll('.el-table__body tbody tr')
      expect(rows).toHaveLength(3)
      expect(rows[0].findAll('[data-test="grant-mark"]').map((n) => n.text())).toEqual(['管理類發放'])
      expect(rows[1].findAll('[data-test="grant-mark"]').map((n) => n.text())).toEqual(['自我授權'])
      expect(rows[2].findAll('[data-test="grant-mark"]')).toHaveLength(0)
    })

    it('詳情的連結以 request_id 篩選，關閉標籤後不再帶參數', async () => {
      setUserRoles(['auditor'])
      getAuditLogsMock.mockResolvedValue({ data: markedRows, total: 3 })
      const wrapper = mountAuditLogs()
      await flushPromises()
      expect(getAuditLogsMock.mock.calls[0][0]).not.toHaveProperty('request_id')

      wrapper.vm.showDetails(markedRows[0])
      await flushPromises()
      getAuditLogsMock.mockClear()
      await wrapper.find('[data-test="same-request"]').trigger('click')
      await flushPromises()

      expect(getAuditLogsMock).toHaveBeenCalledWith({
        page: 1, page_size: 20, request_id: 'abcdef12-3456-7890-abcd-ef1234567890',
      })
      const chip = wrapper.find('[data-test="request-chip"]')
      expect(chip.text()).toBe('同一請求：abcdef12')

      getAuditLogsMock.mockClear()
      await chip.find('.el-tag__close').trigger('click')
      await flushPromises()
      expect(getAuditLogsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
      expect(wrapper.find('[data-test="request-chip"]').exists()).toBe(false)
    })

    it('帶 ?request_id= 進頁時第一次請求即帶參數；過長的值忽略', async () => {
      setUserRoles(['auditor'])
      routeState.query = { request_id: 'abc' }
      mountAuditLogs()
      await flushPromises()
      expect(getAuditLogsMock.mock.calls[0][0]).toEqual({ page: 1, page_size: 20, request_id: 'abc' })

      getAuditLogsMock.mockClear()
      routeState.query = { request_id: 'x'.repeat(101) }
      mountAuditLogs()
      await flushPromises()
      expect(getAuditLogsMock.mock.calls[0][0]).not.toHaveProperty('request_id')
    })
  })

  // 證據包只走非同步 job：同步端點對證據包回 400，對話框要送 job 並導引到下載中心
  describe('匯出稽核證據包', () => {
    const RANGE = ['2026-10-01T00:00:00+08:00', '2026-10-08T00:00:00+08:00']

    const lastNotice = () => {
      const all = document.querySelectorAll('[data-test="export-queued-notice"]')
      return all[all.length - 1]
    }

    const submitWithTimeOnly = async () => {
      setUserRoles(['auditor'])
      const wrapper = mountAuditLogs()
      await flushPromises()
      wrapper.vm.openExportDialog()
      wrapper.vm.exportTimeRange = [...RANGE]
      await flushPromises()
      const submit = wrapper.findAll('button').find((b) => b.text() === '送出打包')
      expect(submit).toBeTruthy()
      await submit.trigger('click')
      await flushPromises()
      return wrapper
    }

    afterEach(() => {
      ElNotification.closeAll()
    })

    it('只填時間送出時以 job API 發起證據包（pack=evidence_bundle）並關閉對話框', async () => {
      createAuditExportJobMock.mockResolvedValue({ data: { id: 7 }, deduplicated: false })
      const wrapper = await submitWithTimeOnly()

      expect(createAuditExportJobMock).toHaveBeenCalledTimes(1)
      expect(createAuditExportJobMock.mock.calls[0][0]).toEqual({
        start_time: RANGE[0],
        end_time: RANGE[1],
        pack: 'evidence_bundle',
      })
      expect(wrapper.vm.exportDialogVisible).toBe(false)
    })

    it('成功提示「已送出打包」並附前往下載中心的連結', async () => {
      createAuditExportJobMock.mockResolvedValue({ data: { id: 8 }, deduplicated: false })
      await submitWithTimeOnly()

      const notice = lastNotice()
      expect(notice).toBeTruthy()
      expect(document.body.textContent).toContain('已送出打包')
      expect(notice.textContent).toContain('完成後可到下載中心取件')
      const link = notice.querySelector('[data-test="export-go-downloads"]')
      expect(link.textContent).toBe('前往下載中心')
      expect(link.getAttribute('href')).toBe('/audit/exports')
      link.click()
      expect(routerPushMock).toHaveBeenCalledWith('/audit/exports')
    })

    it('同範圍已有進行中的工作（deduplicated）時改提示不會重複打包', async () => {
      createAuditExportJobMock.mockResolvedValue({ data: { id: 8 }, deduplicated: true })
      await submitWithTimeOnly()

      const notice = lastNotice()
      expect(document.body.textContent).toContain('同一範圍已有打包中的工作')
      expect(notice.textContent).toContain('不會重複打包')
      expect(notice.querySelector('[data-test="export-go-downloads"]')).toBeTruthy()
    })

    it('400 時顯示後端回傳的錯誤文案、對話框保留', async () => {
      const errorSpy = vi.spyOn(ElMessage, 'error')
      createAuditExportJobMock.mockRejectedValue({
        response: { status: 400, data: { error: '時間窗起點須早於終點' } },
      })
      const wrapper = await submitWithTimeOnly()

      expect(createAuditExportJobMock.mock.calls[0][1]).toEqual({ skipErrorToast: true })
      expect(errorSpy).toHaveBeenCalledWith('時間窗起點須早於終點')
      expect(wrapper.vm.exportDialogVisible).toBe(true)
      errorSpy.mockRestore()
    })
  })
})
