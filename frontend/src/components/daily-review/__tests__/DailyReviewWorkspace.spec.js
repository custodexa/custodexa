import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewWorkspace from '../DailyReviewWorkspace.vue'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const routerPushMock = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const getDailyReviewStatusMock = vi.fn()
const getDailyReviewPendingMock = vi.fn()
const getDailyReviewsMock = vi.fn()
const getDailyReviewStatsMock = vi.fn()
const getDailyReviewDayMock = vi.fn()
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: (...a) => getDailyReviewStatusMock(...a),
  getDailyReviewPending: (...a) => getDailyReviewPendingMock(...a),
  getDailyReviews: (...a) => getDailyReviewsMock(...a),
  getDailyReviewStats: (...a) => getDailyReviewStatsMock(...a),
  getDailyReviewDay: (...a) => getDailyReviewDayMock(...a),
  signDailyReview: vi.fn(),
}))

const TZ = 'Asia/Taipei'
const counts = { login_failures: 3, login_failures_source: 'complete', high_risk_ops: 5, high_risk_ops_source: 'complete', unreviewed_alerts: 1, alerts_source: 'complete' }
// 所屬日（UTC+8）的起點是前一日 16:00Z，準時期限是次日 16:00Z
const pendingDay = (date, { overdue = true, lateDays = 0, basis = 'recorded' } = {}) => {
  const start = new Date(`${date}T00:00:00+08:00`)
  const iso = (offsetDays) => new Date(start.getTime() + offsetDays * 86400000).toISOString()
  return {
    date,
    timezone: TZ,
    timezone_inferred: false,
    window_start: iso(0),
    window_end: iso(1),
    due_at: iso(2),
    signable_at: new Date(start.getTime() + 86400000 + 1800000).toISOString(),
    signable: true,
    overdue,
    late_days: lateDays,
    enabled_basis: basis,
    counts,
  }
}

const signedRow = (overrides = {}) => ({
  id: 1,
  review_date: '2026-10-09',
  reviewer_name: 'auditor01',
  signed_at: '2026-10-10T01:12:00Z',
  timezone: TZ,
  timezone_inferred: false,
  window_start: '2026-10-08T16:00:00Z',
  window_end: '2026-10-09T16:00:00Z',
  late: false,
  late_days: 0,
  delay_reason: null,
  note: '',
  coverage: 'full_day',
  source_status: 'complete',
  enabled_basis: 'recorded',
  snapshot_json: JSON.stringify({ date: '2026-10-09', login_failures: 4, login_failures_source: 'complete', high_risk_ops: 2, high_risk_ops_source: 'complete', unreviewed_alerts: 0, alerts_total: 0, alerts_source: 'complete' }),
  ...overrides,
})

const status = (overrides = {}) => ({
  enabled: true,
  timezone_state: { active: TZ, today: { date: '2026-10-11' }, pending: null },
  pending_count: 0,
  overdue_count: 0,
  earliest_pending_date: null,
  ...overrides,
})

const mountWorkspace = (props = {}) =>
  mount(DailyReviewWorkspace, {
    props: { canSign: true, ...props },
    global: { plugins: [ElementPlus] },
  })

describe('DailyReviewWorkspace', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getDailyReviewStatusMock.mockResolvedValue({ data: status() })
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [], total: 0 } })
    getDailyReviewsMock.mockResolvedValue({ data: { items: [], total: 0 } })
    getDailyReviewStatsMock.mockResolvedValue({ data: null })
  })

  // 防：清單由新到舊排，補簽順序與期限判斷錯位
  it('逾期多日依日期由早到晚、逾期列動作為補簽', async () => {
    getDailyReviewStatusMock.mockResolvedValue({
      data: status({ pending_count: 4, overdue_count: 3, earliest_pending_date: '2026-10-07' }),
    })
    getDailyReviewPendingMock.mockResolvedValue({
      data: {
        items: [
          pendingDay('2026-10-07', { lateDays: 3 }),
          pendingDay('2026-10-08', { lateDays: 2 }),
          pendingDay('2026-10-09', { lateDays: 1 }),
          pendingDay('2026-10-10', { overdue: false }),
        ],
        total: 4,
      },
    })

    const wrapper = mountWorkspace()
    await flushPromises()

    const dates = wrapper.findAll('[data-test="dr-pending-date"]').map((n) => n.text())
    expect(dates.map((d) => d.slice(0, 10))).toEqual(['2026-10-07', '2026-10-08', '2026-10-09', '2026-10-10'])
    const actions = wrapper.findAll('[data-test="dr-pending-action"]').map((n) => n.text())
    expect(actions).toEqual(['補簽', '補簽', '補簽', '審閱並簽核'])
    const table = wrapper.find('[data-test="dr-pending-table"]').text()
    expect(table).toContain('已晚 3 天，簽了算補簽')
    expect(table).toContain('今天 23:59 前簽核算準時')
    expect(table).toContain('昨日')
    expect(wrapper.find('[data-test="dr-overdue-banner"]').text()).toBe(
      '有 4 天還沒簽核，其中 3 天已過準時期限，最早是 2026-10-07。補簽沒有期限，系統每天提醒，直到全部補齊。'
    )
  })

  it('只有昨日待簽時沒有逾期橫幅，全部簽完時說明下一個待簽日何時出現', async () => {
    getDailyReviewStatusMock.mockResolvedValue({ data: status({ pending_count: 1 }) })
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [pendingDay('2026-10-10', { overdue: false })], total: 1 } })
    let wrapper = mountWorkspace()
    await flushPromises()
    expect(wrapper.find('[data-test="dr-overdue-banner"]').exists()).toBe(false)
    wrapper.unmount()

    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [], total: 0 } })
    wrapper = mountWorkspace()
    await flushPromises()
    expect(wrapper.find('[data-test="dr-all-done"]').text()).toContain('今天（2026-10-11）結束後')
  })

  it('功能關閉時已簽紀錄仍列出', async () => {
    getDailyReviewStatusMock.mockResolvedValue({ data: status({ enabled: false }) })
    getDailyReviewsMock.mockResolvedValue({ data: { items: [signedRow()], total: 1 } })

    const wrapper = mountWorkspace({ canOpenPolicies: true })
    await flushPromises()

    expect(wrapper.find('[data-test="dr-disabled"]').text()).toContain('每日審閱簽核尚未開啟')
    expect(wrapper.find('[data-test="dr-disabled-link"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="dr-pending-table"]').exists()).toBe(false)
    const signed = wrapper.find('[data-test="dr-signed-table"]').text()
    expect(signed).toContain('2026-10-09')
    expect(signed).toContain('auditor01')
    expect(signed).toContain('2026/10/10 09:12 (UTC+8)')
  })

  // 防：來源已被保留政策清除的日子把未知寫成 0，讀起來像「那天什麼都沒發生」
  it('source_status=purged 的紀錄計數顯示已清除而非 0', async () => {
    getDailyReviewsMock.mockResolvedValue({
      data: {
        items: [signedRow({
          review_date: '2026-04-12',
          late: true,
          late_days: 181,
          delay_reason: '升級後補列的日子',
          source_status: 'purged',
          snapshot_json: JSON.stringify({ date: '2026-04-12', login_failures: null, login_failures_source: 'purged', high_risk_ops: null, high_risk_ops_source: 'purged', unreviewed_alerts: null, alerts_total: null, alerts_source: 'purged' }),
        })],
        total: 1,
      },
    })

    const wrapper = mountWorkspace()
    await flushPromises()

    const counts = wrapper.find('[data-test="dr-signed-counts"]').text()
    expect(counts).toBe('登入失敗 已清除・告警 已清除・高危 已清除')
    expect(counts).not.toMatch(/\b0\b/)
    expect(wrapper.find('[data-test="dr-signed-type"]').text()).toBe('補簽・晚 181 天')
    expect(wrapper.find('[data-test="dr-signed-table"]').text()).toContain('延遲原因：升級後補列的日子')
    const notes = wrapper.findAll('[data-test="dr-signed-note"]').map((n) => n.text())
    expect(notes).toContain('簽核時來源已依保留政策清除')
  })

  it('enabled_basis=presumed_purged 的待簽列與已簽列加註啟用狀態為推定，recorded 者不加', async () => {
    getDailyReviewStatusMock.mockResolvedValue({ data: status({ pending_count: 2, overdue_count: 2 }) })
    getDailyReviewPendingMock.mockResolvedValue({
      data: {
        items: [
          pendingDay('2026-04-04', { lateDays: 189, basis: 'presumed_purged' }),
          pendingDay('2026-04-13', { lateDays: 180, basis: 'recorded' }),
        ],
        total: 2,
      },
    })
    getDailyReviewsMock.mockResolvedValue({
      data: {
        items: [
          signedRow({ id: 2, review_date: '2026-04-12', enabled_basis: 'presumed_purged' }),
          signedRow({ id: 3, review_date: '2026-10-09', enabled_basis: 'recorded' }),
        ],
        total: 2,
      },
    })

    const wrapper = mountWorkspace()
    await flushPromises()

    const pendingTags = wrapper.findAll('[data-test="dr-pending-inferred"]')
    expect(pendingTags).toHaveLength(1)
    expect(pendingTags[0].text()).toBe('啟用狀態為推定')
    const pendingRows = wrapper.find('[data-test="dr-pending-table"]').findAll('.el-table__row')
    expect(pendingRows[0].text()).toContain('啟用狀態為推定')
    expect(pendingRows[1].text()).not.toContain('啟用狀態為推定')

    const signedTags = wrapper.findAll('[data-test="dr-signed-inferred"]')
    expect(signedTags).toHaveLength(1)
    const signedRows = wrapper.find('[data-test="dr-signed-table"]').findAll('.el-table__row')
    expect(signedRows[0].text()).toContain('啟用狀態為推定')
    expect(signedRows[1].text()).not.toContain('啟用狀態為推定')
  })

  it('改過時區的舊紀錄加註當時的切日時區；升級推定的時區另行加註', async () => {
    getDailyReviewsMock.mockResolvedValue({
      data: {
        items: [
          signedRow({ id: 4, review_date: '2026-09-30', timezone: 'UTC', window_start: '2026-09-30T00:00:00Z', signed_at: '2026-10-01T00:47:00Z' }),
          signedRow({ id: 5, review_date: '2026-09-28', timezone_inferred: true }),
        ],
        total: 2,
      },
    })

    const wrapper = mountWorkspace()
    await flushPromises()

    const rows = wrapper.find('[data-test="dr-signed-table"]').findAll('.el-table__row')
    expect(rows[0].text()).toContain('當時以 UTC 切日')
    expect(rows[0].text()).toContain('2026/10/01 00:47 (UTC)')
    expect(rows[1].text()).toContain('時區為升級時推定')
    expect(rows[1].text()).not.toContain('當時以')
  })

  it('只看補簽以 late_only 查詢', async () => {
    const wrapper = mountWorkspace()
    await flushPromises()
    getDailyReviewsMock.mockClear()

    const lateButton = wrapper.find('[data-test="dr-signed-filter"]').findAll('label').find((n) => n.text() === '只看補簽')
    await lateButton.find('input').setValue(true)
    await flushPromises()
    expect(getDailyReviewsMock).toHaveBeenLastCalledWith({ page: 1, page_size: 20, late_only: true })
  })

  // 元件權限 stub：有檢視、無簽核（目前沒有真帳號可達這一態）
  it('無簽核權限時頂端說明唯讀，待簽日動作為查看', async () => {
    getDailyReviewStatusMock.mockResolvedValue({ data: status({ pending_count: 1 }) })
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [pendingDay('2026-10-10', { overdue: false })], total: 1 } })

    const wrapper = mountWorkspace({ canSign: false })
    await flushPromises()

    expect(wrapper.find('[data-test="dr-readonly-notice"]').text()).toContain('簽核需要稽核員權限')
    expect(wrapper.findAll('[data-test="dr-pending-action"]').map((n) => n.text())).toEqual(['查看'])
  })

  it('帶入所屬日時直接開該日抽屜', async () => {
    getDailyReviewDayMock.mockResolvedValue({ data: { date: '2026-10-07', status: 'pending' } })
    mountWorkspace({ openDate: '2026-10-07' })
    await flushPromises()
    expect(getDailyReviewDayMock).toHaveBeenCalledWith('2026-10-07')
  })
})
