import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
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

const getAuditLogsMock = vi.fn()
const exportAuditEvidenceMock = vi.fn()
const getDailyReviewsMock = vi.fn()
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
    getAuditLogsMock.mockResolvedValue({ data: [], total: 0 })
    getDailyReviewsMock.mockResolvedValue({ data: { items: [], total: 0 } })
    getAuditFailuresMock.mockResolvedValue({ data: { items: [], total: 0 } })
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

  it('fetches and renders daily review history with parsed snapshot counts', async () => {
    setUserRoles(['auditor'])
    getDailyReviewsMock.mockResolvedValue({
      data: { items: sampleReviews, total: 1 },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()

    // C8：切換即 refetch 走 tab-change 事件（watch 首載模式已移除）
    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.handleTabChange('reviews')
    await flushPromises()

    expect(getDailyReviewsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    const text = wrapper.text()
    expect(text).toContain('2026-07-12')
    expect(text).toContain('auditor1')
    expect(text).toContain('登入失敗 2')
    expect(text).toContain('未審閱告警 1')
    expect(text).toContain('高危操作 3')
    expect(text).toContain('無異常')
  })

  it('shows dash when snapshot_json is unparsable', async () => {
    setUserRoles(['auditor'])
    getDailyReviewsMock.mockResolvedValue({
      data: {
        items: [{ ...sampleReviews[0], snapshot_json: '{broken' }],
        total: 1,
      },
    })

    const wrapper = mountAuditLogs()
    await flushPromises()

    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.handleTabChange('reviews')
    await flushPromises()

    expect(wrapper.text()).not.toContain('登入失敗')
    expect(wrapper.vm.snapshotCounts({ snapshot_json: '{broken' })).toEqual([])
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
})
