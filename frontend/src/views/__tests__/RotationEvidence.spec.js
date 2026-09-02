import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import RotationEvidence from '../RotationEvidence.vue'
import { ROTATION_BUCKETS, BUCKET_SUMMARY_FIELD } from '@/constants/rotationEvidence'

// 輪替證據頁。
//
// 斷言重心在四件「錯了就讓稽核讀出不存在的結論」的事：
// 1) 摘要與表格同源——篩選某一桶之後的列數必須等於摘要那一格的數字；
// 2) 分母為零時說「不適用」而不是 0%（後者是一個關於母體的斷言）；
// 3) 排程管理是 admin 專屬區，auditor 一格都不該渲染；
// 4) 產出成功後把人帶到取件的地方，且送出的範圍與區間就是表單上那一份。

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.stubGlobal('ResizeObserver', MutationObserverStub)

const reportMock = vi.fn()
const recordsMock = vi.fn()
const createJobMock = vi.fn()
const listSchedulesMock = vi.fn()
const createScheduleMock = vi.fn()
const updateScheduleMock = vi.fn()
const deleteScheduleMock = vi.fn()
const runScheduleMock = vi.fn()

vi.mock('@/api/rotationReport', () => ({
  getRotationReport: (...a) => reportMock(...a),
  getRotationReportRecords: (...a) => recordsMock(...a),
  createRotationReportJob: (...a) => createJobMock(...a),
  listRotationReportSchedules: (...a) => listSchedulesMock(...a),
  createRotationReportSchedule: (...a) => createScheduleMock(...a),
  updateRotationReportSchedule: (...a) => updateScheduleMock(...a),
  deleteRotationReportSchedule: (...a) => deleteScheduleMock(...a),
  runRotationReportSchedule: (...a) => runScheduleMock(...a),
}))

vi.mock('@/api/assets', () => ({
  getAssetGroups: () => Promise.resolve({ data: [] }),
}))

const listJobsMock = vi.fn()
const downloadJobMock = vi.fn()
vi.mock('@/api/auditExport', () => ({
  listAuditExportJobs: (...a) => listJobsMock(...a),
  downloadAuditExportJob: (...a) => downloadJobMock(...a),
}))

const downloadBlobMock = vi.fn()
vi.mock('@/utils/download', () => ({
  downloadBlob: (...a) => downloadBlobMock(...a),
}))

vi.mock('@/api/changeSecret', () => ({
  getChangeSecretPlans: () => Promise.resolve({ data: [{ id: 3, name: '週度改密' }] }),
}))

const pushMock = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
  useRoute: () => ({ path: '/rotation-evidence', query: {} }),
}))

const account = (over = {}) => ({
  account_id: 1,
  asset_id: 1,
  asset_name: 'db-01',
  asset_address: '10.0.0.11',
  protocol: 'ssh',
  username: 'root',
  credential_type: 'password',
  privileged: true,
  shared_credential: false,
  plans: ['週度改密'],
  multi_plan: false,
  max_age_days: 90,
  max_age_source: 'global',
  last_success_at: '2026-06-01T00:00:00Z',
  last_record_status: 'success',
  remaining_days_a: 5,
  next_schedule_at: '2026-09-08T01:00:00Z',
  remaining_days_b: 6,
  candidate_state: 'none',
  bucket: 'compliant',
  ...over,
})

const summaryOf = (over = {}) => ({
  total_accounts: 4,
  compliant: 1,
  overdue: 2,
  due_within_30: 1,
  no_record: 0,
  unverified: 0,
  no_policy: 0,
  shared_credential: 1,
  multi_plan: 1,
  rate_excluding_no_record: 0.25,
  rate_counting_no_record: 0.25,
  ...over,
})

const dataset = (over = {}) => ({
  data: {
    meta: {
      scope_kind: 'all',
      scope_id: 0,
      period_start: '2026-06-01T00:00:00Z',
      period_end: '2026-09-01T00:00:00Z',
      as_of: '2026-09-02T00:00:00Z',
      global_max_age_days: 90,
      due_soon_window_days: 30,
      language: 'zh-TW',
    },
    summary: summaryOf(),
    rows: [
      account({ account_id: 1, bucket: 'compliant' }),
      account({ account_id: 2, bucket: 'overdue', remaining_days_a: -3 }),
      account({ account_id: 3, bucket: 'overdue', remaining_days_a: -9, shared_credential: true }),
      account({ account_id: 4, bucket: 'due_soon', multi_plan: true, plans: ['甲', '乙'] }),
    ],
    records: null,
    truncation: { rows_cap: 20000, rows_truncated: false, records_cap: 50000, records_truncated: false },
    ...over,
  },
})

const setRoles = (roles) => {
  localStorage.setItem('user', JSON.stringify({ id: 5, username: 'tester', roles }))
}

const mountPage = async () => {
  const wrapper = mount(RotationEvidence, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  reportMock.mockResolvedValue(dataset())
  recordsMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20, truncated: false })
  listSchedulesMock.mockResolvedValue({ data: [] })
  createJobMock.mockResolvedValue({ data: { id: 18, status: 'pending' } })
  listJobsMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 3 })
  downloadJobMock.mockResolvedValue(new Blob(['zip']))
})

const reportJob = (over = {}) => ({
  id: 91,
  status: 'done',
  requested_at: '2026-09-01T01:00:00Z',
  expires_at: '2027-09-01T01:00:00Z',
  artifact_size: 4096,
  report: { schedule_name: '月報', scope_kind: 'all' },
  ...over,
})

describe('摘要與表格同源', () => {
  it('篩選逾期後的列數等於摘要的逾期數（兩者出自同一次建構）', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    expect(wrapper.findAll('[data-test^="rotation-account-"]').length).toBe(4)

    await wrapper.find('[data-test="rotation-summary-overdue"]').trigger('click')
    const listed = wrapper.findAll('[data-test^="rotation-account-"]').length
    expect(listed).toBe(2)
    expect(String(listed)).toBe(
      wrapper.find('[data-test="rotation-summary-overdue"] .summary-value').text()
    )
    // 篩選在既有資料上做：不得為了一次篩選重打資料集端點
    expect(reportMock).toHaveBeenCalledTimes(1)
  })

  it('六個狀態桶都有摘要格與譯名（後端多一個桶而畫面沒跟上時這裡會缺格）', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    for (const bucket of ROTATION_BUCKETS) {
      const cell = wrapper.find(`[data-test="rotation-summary-${bucket}"]`)
      expect(cell.exists(), `缺少 ${bucket} 的摘要格`).toBe(true)
      expect(cell.text()).not.toContain(`rotationEvidence.bucket.${bucket}`)
      expect(BUCKET_SUMMARY_FIELD[bucket], `${bucket} 未對應摘要欄位`).toBeTruthy()
    }
  })

  it('共用憑證、多計劃與特權各自以標籤標出（讀者要能一眼認出這幾類帳號）', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-shared-3"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="rotation-multiplan-4"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="rotation-privileged-1"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="rotation-shared-1"]').exists()).toBe(false)
  })
})

describe('合規率的分母', () => {
  it('分母為零時顯示「不適用」，不得顯示 0%（後者會被讀成一個都不合規）', async () => {
    setRoles(['auditor'])
    reportMock.mockResolvedValue(
      dataset({
        summary: summaryOf({
          compliant: 0,
          overdue: 0,
          due_within_30: 0,
          no_policy: 4,
          rate_excluding_no_record: null,
          rate_counting_no_record: null,
        }),
      })
    )
    const wrapper = await mountPage()
    const excluding = wrapper.find('[data-test="rotation-rate-rate_excluding_no_record"]')
    const counting = wrapper.find('[data-test="rotation-rate-rate_counting_no_record"]')
    expect(excluding.text()).toContain('不適用')
    expect(counting.text()).toContain('不適用')
    expect(excluding.text()).not.toContain('0.0%')
  })

  it('有分母時以百分比呈現', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-rate-rate_counting_no_record"]').text()).toContain('25.0%')
  })
})

describe('排程管理是 admin 專屬區', () => {
  it('auditor 不渲染排程區，也不打排程端點', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-schedules"]').exists()).toBe(false)
    expect(listSchedulesMock).not.toHaveBeenCalled()
  })

  it('admin 看得到排程區與其中的排程列', async () => {
    setRoles(['admin'])
    listSchedulesMock.mockResolvedValue({
      data: [
        {
          id: 1,
          name: '月報',
          cron: '0 1 1 * *',
          enabled: true,
          scope_kind: 'all',
          scope_id: 0,
          retention_days: 400,
          language: 'zh-TW',
          period_anchor: '2026-09-01T00:00:00Z',
        },
      ],
    })
    const wrapper = await mountPage()
    // 排程區預設收起，由右欄的「管理」展開（版面 A：主區只留摘要與表格）
    await wrapper.find('[data-test="rotation-schedule-manage"]').trigger('click')
    expect(wrapper.find('[data-test="rotation-schedules"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="rotation-schedule-name-1"]').text()).toBe('月報')
    expect(wrapper.find('[data-test="rotation-schedule-run-1"]').exists()).toBe(true)
  })

  it('排程送出的 payload 不含唯讀的區間錨點（送了也不採用，送出即誤導）', async () => {
    setRoles(['admin'])
    createScheduleMock.mockResolvedValue({ data: { id: 2 } })
    const wrapper = await mountPage()
    Object.assign(wrapper.vm.scheduleForm, { name: '季報', cron: '0 2 1 */3 *' })
    await wrapper.vm.submitSchedule()
    expect(createScheduleMock).toHaveBeenCalledWith({
      name: '季報',
      cron: '0 2 1 */3 *',
      enabled: true,
      scope_kind: 'all',
      scope_id: 0,
      retention_days: 400,
      language: 'zh-TW',
    })
    expect(Object.keys(createScheduleMock.mock.calls[0][0])).not.toContain('period_anchor')
  })
})

describe('右欄：報告本身的狀態', () => {
  it('auditor 沒有排程的「管理」入口，也不渲染排程區', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-schedule-manage"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="rotation-schedules"]').exists()).toBe(false)
    // 看不到排程資料時要說得出那是誰在管，不能留一片空白
    expect(wrapper.find('[data-test="rotation-schedule-admin-only"]').exists()).toBe(true)
  })

  it('最近產出取共用清單最新三筆（多回的不進畫面，要看全部去下載中心）', async () => {
    setRoles(['auditor'])
    listJobsMock.mockResolvedValue({
      data: [reportJob({ id: 91 }), reportJob({ id: 90 }), reportJob({ id: 89 }), reportJob({ id: 88 })],
      total: 12,
    })
    const wrapper = await mountPage()
    expect(listJobsMock).toHaveBeenCalledWith({ kind: 'rotation_report', page: 1, page_size: 3 })
    expect(wrapper.findAll('[data-test^="rotation-recent-"]').filter((el) =>
      /rotation-recent-\d+$/.test(el.attributes('data-test'))
    ).length).toBe(3)
    expect(wrapper.find('[data-test="rotation-recent-88"]').exists()).toBe(false)
  })

  it('已完成且未過期的那一筆可下載，取的是該列的產物', async () => {
    setRoles(['auditor'])
    listJobsMock.mockResolvedValue({ data: [reportJob({ id: 91 })], total: 1 })
    const wrapper = await mountPage()
    await wrapper.find('[data-test="rotation-recent-download-91"]').trigger('click')
    await flushPromises()
    expect(downloadJobMock).toHaveBeenCalledWith(91)
    expect(downloadBlobMock).toHaveBeenCalledWith(expect.anything(), 'rotation-report-job-91.zip')
  })

  it('打包中的那一筆不給下載鈕，改說目前的狀態（按下去只會拿到 404）', async () => {
    setRoles(['auditor'])
    listJobsMock.mockResolvedValue({ data: [reportJob({ id: 92, status: 'running' })], total: 1 })
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-recent-download-92"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="rotation-recent-status-92"]').text()).toBe('打包中')
  })

  it('沒有任何產出時走共用的空狀態元件，並留下往下載中心的去路', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    const empty = wrapper.find('[data-test="rotation-aside-recent-empty"]')
    expect(empty.exists()).toBe(true)
    expect(empty.classes()).toContain('empty-state')
    expect(wrapper.find('[data-test="rotation-recent-all"]').exists()).toBe(true)
  })

  it('比例條的分母是六桶之和：畫面認不得的桶會留下缺口，而不是被均分掉', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    const bar = wrapper.find('[data-test="rotation-bucket-bar"]')
    expect(bar.exists()).toBe(true)
    expect(wrapper.find('[data-test="rotation-bar-overdue"]').attributes('style')).toContain('50.00%')
    expect(wrapper.find('[data-test="rotation-bar-no_record"]').exists()).toBe(false)
  })
})

describe('產出報告', () => {
  it('送出後導向下載中心的輪替報告分頁，且範圍與區間就是表單上那一份', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    wrapper.vm.openGenerate()
    Object.assign(wrapper.vm.generateForm, {
      scope_kind: 'all',
      period: ['2026-07-01', '2026-09-30'],
      language: 'ja-JP',
    })
    await wrapper.vm.submitGenerate()
    await flushPromises()

    const payload = createJobMock.mock.calls[0][0]
    expect(payload.scope_kind).toBe('all')
    expect(payload.scope_id).toBe(0)
    expect(payload.language).toBe('ja-JP')
    expect(new Date(payload.period_start).getTime()).toBeLessThan(
      new Date(payload.period_end).getTime()
    )
    expect(pushMock).toHaveBeenCalledWith({ path: '/audit/exports', query: { tab: 'reports' } })
  })

  it('節點範圍要帶節點識別碼（少帶就會靜默產出一份全系統報告）', async () => {
    setRoles(['auditor'])
    const wrapper = await mountPage()
    Object.assign(wrapper.vm.generateForm, {
      scope_kind: 'node',
      scope_id: 7,
      period: ['2026-07-01', '2026-09-30'],
      language: 'zh-TW',
    })
    await wrapper.vm.submitGenerate()
    expect(createJobMock).toHaveBeenCalledWith(
      expect.objectContaining({ scope_kind: 'node', scope_id: 7 })
    )
  })
})

describe('記錄明細的區間', () => {
  it('資料集回的區間長度為零時改用預設回看窗（直接沿用會被記錄端點以參數不合法擋下）', async () => {
    setRoles(['auditor'])
    const sameMoment = '2026-09-02T00:00:00Z'
    reportMock.mockResolvedValue(
      dataset({
        meta: {
          period_start: sameMoment,
          period_end: sameMoment,
          as_of: sameMoment,
          global_max_age_days: 90,
          due_soon_window_days: 30,
        },
      })
    )
    await mountPage()
    const params = recordsMock.mock.calls[0][0]
    expect(new Date(params.period_start).getTime()).toBeLessThan(
      new Date(params.period_end).getTime()
    )
  })

  it('資料集回的區間有長度時就照用', async () => {
    setRoles(['auditor'])
    await mountPage()
    expect(recordsMock).toHaveBeenCalledWith(
      expect.objectContaining({
        period_start: '2026-06-01T00:00:00Z',
        period_end: '2026-09-01T00:00:00Z',
      })
    )
  })
})

describe('前提與邊界要說出來', () => {
  it('全域政策未設定時明說（報告照產，但讀者要知道那些「無政策」是怎麼來的）', async () => {
    setRoles(['auditor'])
    reportMock.mockResolvedValue(
      dataset({
        meta: {
          period_start: '2026-06-01T00:00:00Z',
          period_end: '2026-09-01T00:00:00Z',
          as_of: '2026-09-02T00:00:00Z',
          global_max_age_days: 0,
          due_soon_window_days: 30,
        },
      })
    )
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-no-global-policy"]').exists()).toBe(true)
  })

  it('列數達上限時標明只是其中一部分', async () => {
    setRoles(['auditor'])
    reportMock.mockResolvedValue(
      dataset({
        truncation: { rows_cap: 20000, rows_truncated: true, records_cap: 50000, records_truncated: false },
      })
    )
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-truncated"]').text()).toContain('20000')
  })

  it('資料集載入失敗要說出來（不得留一片看起來像「沒有帳號」的空白）', async () => {
    setRoles(['auditor'])
    reportMock.mockRejectedValue(new Error('boom'))
    const wrapper = await mountPage()
    expect(wrapper.find('[data-test="rotation-load-failed"]').exists()).toBe(true)
  })
})
