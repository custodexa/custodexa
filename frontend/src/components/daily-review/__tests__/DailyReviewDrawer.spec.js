import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, DOMWrapper } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { defineComponent, h } from 'vue'
import DailyReviewDrawer from '../DailyReviewDrawer.vue'

enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

const routerPushMock = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const getDailyReviewDayMock = vi.fn()
const getDailyReviewPendingMock = vi.fn()
const signDailyReviewMock = vi.fn()
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewDay: (...a) => getDailyReviewDayMock(...a),
  getDailyReviewPending: (...a) => getDailyReviewPendingMock(...a),
  signDailyReview: (...a) => signDailyReviewMock(...a),
}))

const reviewAlertMock = vi.fn()
vi.mock('@/api/alerts', () => ({
  reviewAlert: (...a) => reviewAlertMock(...a),
  searchAlerts: vi.fn(),
}))

// 批次審閱對話框的逐筆送出流程在它自己的 spec；這裡只需要它「處置完成」的事件
const batchOpenMock = vi.fn()
const BatchDialogStub = defineComponent({
  name: 'AlertBatchReviewDialog',
  props: { alerts: { type: Array, default: () => [] } },
  emits: ['settled', 'finished'],
  setup(_, { expose }) {
    expose({ open: batchOpenMock })
    return () => h('div', { 'data-test': 'batch-dialog-stub' })
  },
})

const ME = 7
const TZ = 'Asia/Taipei'

const eventList = (total, n = Math.min(total, 20), source = 'complete') => ({
  total,
  source_status: source,
  items: Array.from({ length: n }, (_, i) => ({
    id: 100 + i,
    created_at: '2026-10-07T02:11:00Z',
    username: 'ops-lin',
    client_ip: '10.20.4.17',
    error_msg: '密碼錯誤',
  })),
})

const alert = (id, overrides = {}) => ({
  id,
  rule_name: `規則 ${id}`,
  kind: 'rule',
  severity: 'medium',
  user_id: 99,
  triggered_at: '2026-10-07T10:14:00Z',
  ...overrides,
})

// 所屬日 2026-10-07（UTC+8）：[10-06 16:00Z, 10-07 16:00Z)，準時期限 10-08 16:00Z
const dayDetail = (overrides = {}) => ({
  date: '2026-10-07',
  status: 'pending',
  timezone: TZ,
  timezone_inferred: false,
  window_start: '2026-10-06T16:00:00Z',
  window_end: '2026-10-07T16:00:00Z',
  due_at: '2099-10-08T16:00:00Z',
  signable_at: '2026-10-07T16:30:00Z',
  enabled_basis: 'recorded',
  overdue: false,
  late_days: 0,
  sources: { audit_log: 'complete', command_alert: 'complete' },
  counts: {
    login_failures: 3,
    login_failures_source: 'complete',
    high_risk_ops: 35,
    high_risk_ops_source: 'complete',
    unreviewed_alerts: 0,
    alerts_total: 0,
    alerts_benign: 0,
    alerts_escalated: 0,
    alerts_source: 'complete',
  },
  unreviewed_alerts: [],
  login_failures: eventList(3),
  high_risk_ops: eventList(35),
  review: null,
  signed_snapshot: null,
  alerts_after_sign: null,
  ...overrides,
})

const lateDetail = (overrides = {}) =>
  dayDetail({ due_at: '2026-10-08T16:00:00Z', overdue: true, late_days: 3, ...overrides })

const signedRecord = (overrides = {}) => ({
  id: 9,
  review_date: '2026-10-07',
  reviewer_name: 'auditor01',
  signed_at: '2026-10-11T02:42:18Z',
  timezone: TZ,
  timezone_inferred: false,
  window_start: '2026-10-06T16:00:00Z',
  window_end: '2026-10-07T16:00:00Z',
  late: true,
  late_days: 3,
  delay_reason: '10-08 至 10-10 稽核人員請假',
  note: '',
  coverage: 'full_day',
  source_status: 'complete',
  enabled_basis: 'recorded',
  snapshot_json: JSON.stringify({
    date: '2026-10-07', login_failures: 2, login_failures_source: 'complete', high_risk_ops: 4,
    high_risk_ops_source: 'complete', unreviewed_alerts: 0, alerts_total: 4, alerts_benign: 3,
    alerts_escalated: 1, alerts_source: 'complete',
  }),
  ...overrides,
})

const mountDrawer = async ({ canSign = true, detail = dayDetail(), date = '2026-10-07' } = {}) => {
  getDailyReviewDayMock.mockResolvedValue({ data: detail })
  const wrapper = mount(DailyReviewDrawer, {
    props: {
      modelValue: false,
      canSign,
      'onUpdate:modelValue': (v) => wrapper.setProps({ modelValue: v }),
    },
    global: {
      plugins: [ElementPlus],
      stubs: { AlertBatchReviewDialog: BatchDialogStub },
    },
  })
  // 抽屜掛在 body（append-to-body）：查詢改從 body 找，元件樹查詢照舊
  const root = new DOMWrapper(document.body)
  wrapper.find = (selector) => root.find(selector)
  wrapper.findAll = (selector) => root.findAll(selector)
  wrapper.text = () => root.find('[data-test="dr-drawer"]').text()
  await wrapper.vm.openDay(date)
  await flushPromises()
  return wrapper
}

const signButton = (wrapper) => wrapper.find('[data-test="dr-sign"]')
const apiError = (status, code, params = {}) => {
  const error = new Error(code)
  error.response = { status, data: { code, params, error: code } }
  return error
}

describe('DailyReviewDrawer', () => {
  let eventSpy

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'auditor01', roles: ['auditor'] }))
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [], total: 0 } })
    eventSpy = vi.fn()
    window.addEventListener('ot-daily-reviews-changed', eventSpy)
  })

  afterEach(() => {
    window.removeEventListener('ot-daily-reviews-changed', eventSpy)
    localStorage.clear()
  })

  it('標題載明所屬日、實際起訖與準時期限，簽核按鈕帶所屬日', async () => {
    const wrapper = await mountDrawer()
    expect(getDailyReviewDayMock).toHaveBeenCalledWith('2026-10-07')
    expect(wrapper.find('.dr-drawer__title').text()).toContain('審閱 2026-10-07（三）')
    expect(wrapper.find('[data-test="dr-window"]').text()).toContain('00:00–23:59（UTC+8）')
    expect(signButton(wrapper).text()).toBe('簽核 2026-10-07')
    expect(wrapper.text()).toContain('簽核時間由系統記錄，不能自行填寫或事後修改')
  })

  it('改時區的轉換日照實寫出起訖與長度，不寫成整天', async () => {
    const wrapper = await mountDrawer({
      detail: dayDetail({ window_start: '2026-10-11T16:00:00Z', window_end: '2026-10-13T00:00:00Z', timezone: 'UTC' }),
    })
    const text = wrapper.find('[data-test="dr-window"]').text()
    expect(text).toContain('共 32 小時')
    expect(text).not.toContain('00:00–23:59')
  })

  // 防：連結用含尾端的 end_time，把恰在下一日起點的事件也列進來；
  // 以及連結文字承諾「全部 35 筆」，落地卻是這一天全部操作紀錄，使用者以為數字對不上
  it('查看全部連結用排他尾端，文字照實說落地是這一天的全部操作紀錄', async () => {
    const wrapper = await mountDrawer()
    const links = wrapper.findAll('[data-test="dr-events-view-all"]')
    // 登入失敗 3 筆全列出，不給連結；高危操作 35 筆只列 20 筆，給連結
    expect(links).toHaveLength(1)
    const link = links[0]
    expect(link.text()).toBe('到操作日誌查看這一天的全部操作紀錄')
    expect(link.text()).not.toMatch(/35/)
    const hint = wrapper.find('[data-test="dr-events-high_risk_ops"] [data-test="dr-events-view-all-hint"]')
    expect(hint.text()).toBe('這裡只列前 20 筆高危操作。操作日誌會列出這一天的全部操作紀錄，不只高危操作，筆數通常比這裡的 35 筆多。')
    const url = new URL(link.attributes('href'), 'http://x')
    expect(url.pathname).toBe('/audit-logs')
    expect(url.searchParams.get('tab')).toBe('logs')
    expect(url.searchParams.get('start_time')).toBe('2026-10-06T16:00:00Z')
    expect(url.searchParams.get('end_before')).toBe('2026-10-07T16:00:00Z')
    expect(url.searchParams.has('end_time')).toBe(false)

    await link.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith({
      path: '/audit-logs',
      query: { tab: 'logs', start_time: '2026-10-06T16:00:00Z', end_before: '2026-10-07T16:00:00Z' },
    })
    expect(wrapper.emitted('update:modelValue').at(-1)).toEqual([false])
  })

  // 防：簽核前要看的登入失敗／高危操作明細預設藏起來，或列出來卻沒有欄名看不懂
  it('登入失敗與高危操作明細預設展開並帶欄名', async () => {
    const wrapper = await mountDrawer()
    const login = wrapper.find('[data-test="dr-events-login_failures"]')
    const loginHeads = login.findAll('[data-test="dr-events-table"] th').map((th) => th.text())
    expect(loginHeads).toEqual(['時間', '帳號', '來源位址', '原因'])
    expect(login.findAll('[data-test="dr-events-table"] tbody tr')).toHaveLength(3)
    expect(login.text()).toContain('10:11')
    expect(login.text()).toContain('密碼錯誤')
    const high = wrapper.find('[data-test="dr-events-high_risk_ops"]')
    expect(high.findAll('[data-test="dr-events-table"] th').map((th) => th.text()))
      .toEqual(['時間', '帳號', '來源位址', '操作'])
    expect(high.findAll('[data-test="dr-events-table"] tbody tr')).toHaveLength(20)
    // 仍可收合
    await login.find('.dr-events__toggle').trigger('click')
    expect(login.find('[data-test="dr-events-table"]').exists()).toBe(false)
  })

  // 防：介面讓人在告警未處置時按下簽核，或處置後按鈕不恢復而卡住
  it('告警未處置時簽核停用且說明筆數，處置後啟用', async () => {
    const pendingAlerts = dayDetail({
      unreviewed_alerts: [alert(1), alert(2)],
      counts: { ...dayDetail().counts, unreviewed_alerts: 2, alerts_total: 3, alerts_benign: 1 },
    })
    const wrapper = await mountDrawer({ detail: pendingAlerts })

    expect(signButton(wrapper).attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="dr-block"]').text()).toBe('還有 2 筆未審閱告警，處置完才能簽核。')
    expect(wrapper.find('[data-test="dr-alerts-pending"]').text()).toBe('3 筆中還有 2 筆要處置')

    // 勾兩筆、批次處置完成 → 重取明細，未審閱歸零
    const boxes = wrapper.findAll('[data-test="dr-alert-select"] input')
    await boxes[0].setValue(true)
    await boxes[1].setValue(true)
    expect(wrapper.find('[data-test="dr-alerts-batch-bar"]').text()).toContain('已選 2 筆')
    getDailyReviewDayMock.mockResolvedValue({
      data: dayDetail({ counts: { ...dayDetail().counts, alerts_total: 3, alerts_benign: 2, alerts_escalated: 1 } }),
    })
    wrapper.findComponent(BatchDialogStub).vm.$emit('finished')
    await flushPromises()

    expect(getDailyReviewDayMock).toHaveBeenCalledTimes(2)
    expect(signButton(wrapper).attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-test="dr-alerts-done"]').text()).toContain('未審閱告警：3 筆都已處置')
    expect(wrapper.find('[data-test="dr-alerts-done"]').text()).toContain('無害 2・需升級處理 1')
    expect(eventSpy).toHaveBeenCalledTimes(1)
  })

  // 防：結果列已寫「成功 2 筆」，上方仍寫「還有 2 筆要處置」、簽核鈕停用，要按「完成」才更新
  it('批次送完、結果列出現時就重取明細，按完成不再重取', async () => {
    const wrapper = await mountDrawer({
      detail: dayDetail({
        unreviewed_alerts: [alert(1), alert(2)],
        counts: { ...dayDetail().counts, unreviewed_alerts: 2, alerts_total: 3, alerts_benign: 1 },
      }),
    })
    const boxes = wrapper.findAll('[data-test="dr-alert-select"] input')
    await boxes[0].setValue(true)
    await boxes[1].setValue(true)
    getDailyReviewDayMock.mockResolvedValue({
      data: dayDetail({ counts: { ...dayDetail().counts, alerts_total: 3, alerts_benign: 3 } }),
    })
    const batch = wrapper.findComponent(BatchDialogStub)
    batch.vm.$emit('settled')
    await flushPromises()
    expect(getDailyReviewDayMock).toHaveBeenCalledTimes(2)
    expect(signButton(wrapper).attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-test="dr-alerts-pending"]').exists()).toBe(false)
    expect(eventSpy).toHaveBeenCalledTimes(1)

    batch.vm.$emit('finished')
    await flushPromises()
    expect(getDailyReviewDayMock).toHaveBeenCalledTimes(2)
    expect(eventSpy).toHaveBeenCalledTimes(1)
  })

  it('本人觸發的告警走單筆、批次部分失敗後重取', async () => {
    const detail = dayDetail({
      unreviewed_alerts: [alert(1, { user_id: ME }), alert(2), alert(3), alert(4)],
      counts: { ...dayDetail().counts, unreviewed_alerts: 4, alerts_total: 4 },
    })
    const wrapper = await mountDrawer({ detail })

    const cells = wrapper.findAll('[data-test="dr-alert-select"]')
    const selfBox = cells.find((c) => c.attributes('data-id') === '1')
    expect(selfBox.find('input').attributes('disabled')).toBeDefined()
    // 本人觸發者另有逐筆審閱入口
    const single = wrapper.find('[data-test="dr-alert-1"] [data-test="dr-alert-single"]')
    expect(single.exists()).toBe(true)

    for (const id of ['2', '3', '4']) {
      await cells.find((c) => c.attributes('data-id') === id).find('input').setValue(true)
    }
    const batch = wrapper.findComponent(BatchDialogStub)
    expect(batch.props('alerts').map((a) => a.id)).toEqual([2, 3, 4])

    // 三筆其中一筆失敗：伺服器仍有本人觸發的 1 筆與失敗的 1 筆未審閱
    getDailyReviewDayMock.mockResolvedValue({
      data: dayDetail({
        unreviewed_alerts: [alert(1, { user_id: ME }), alert(4)],
        counts: { ...dayDetail().counts, unreviewed_alerts: 2, alerts_total: 4 },
      }),
    })
    batch.vm.$emit('finished')
    await flushPromises()
    expect(getDailyReviewDayMock).toHaveBeenCalledTimes(2)
    expect(signButton(wrapper).attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="dr-block"]').text()).toContain('還有 2 筆未審閱告警')

    // 本人觸發的那筆逐筆審閱：不帶批次關聯碼
    reviewAlertMock.mockResolvedValue({})
    await wrapper.find('[data-test="dr-alert-1"] [data-test="dr-alert-single"]').trigger('click')
    await wrapper.find('[data-test="dr-alert-single-submit"]').trigger('click')
    await flushPromises()
    expect(reviewAlertMock).toHaveBeenCalledWith(1, { disposition: 'benign', note: '' })
    expect(getDailyReviewDayMock).toHaveBeenCalledTimes(3)
  })

  // 防：遲簽可以不留原因就送出，或後端拒絕後使用者已填的內容被清空
  it('補簽未填原因不送出', async () => {
    const wrapper = await mountDrawer({ detail: lateDetail() })
    expect(wrapper.find('[data-test="dr-late-tag"]').text()).toBe('補簽')
    expect(wrapper.find('[data-test="dr-late-notice"]').text()).toContain('準時期限是 2026-10-08 23:59，已經過了')
    expect(wrapper.find('.dr-form__label').text()).toBe('延遲原因（必填）')
    expect(signButton(wrapper).text()).toBe('補簽 2026-10-07')

    await signButton(wrapper).trigger('click')
    await flushPromises()
    expect(signDailyReviewMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="dr-delay-error"]').text()).toBe('請填寫延遲原因，才能補簽。')
  })

  it('後端回延遲原因必填時切成補簽版面，已填的備註保留', async () => {
    const wrapper = await mountDrawer()
    expect(wrapper.find('.dr-form__label').text()).toBe('簽核備註（選填）')
    await wrapper.find('textarea[data-test="dr-text"]').setValue('需升級的一筆已轉資安窗口')
    signDailyReviewMock.mockRejectedValue(apiError(400, 'VALIDATION_DAILY_REVIEW_DELAY_REASON_REQUIRED'))

    await signButton(wrapper).trigger('click')
    await flushPromises()

    expect(signDailyReviewMock).toHaveBeenCalledWith(
      { review_date: '2026-10-07', note: '需升級的一筆已轉資安窗口', delay_reason: '' },
      { skipErrorToast: true }
    )
    expect(wrapper.find('.dr-form__label').text()).toBe('延遲原因（必填）')
    expect(wrapper.find('[data-test="dr-late-tag"]').exists()).toBe(true)
    expect(wrapper.find('textarea[data-test="dr-text"]').element.value).toBe('需升級的一筆已轉資安窗口')
    expect(signButton(wrapper).text()).toBe('補簽 2026-10-07')
  })

  // 防：簽完抽屜關閉或停在表單，使用者不知道簽成了沒有、下一天要自己找
  it('送出後顯示固化紀錄與下一天', async () => {
    const wrapper = await mountDrawer({ detail: lateDetail() })
    await wrapper.find('textarea[data-test="dr-text"]').setValue('10-08 至 10-10 稽核人員請假')
    const record = signedRecord()
    signDailyReviewMock.mockResolvedValue({ data: { ...record, late_days: undefined } })
    getDailyReviewPendingMock.mockResolvedValue({
      data: { items: [{ date: '2026-10-08' }, { date: '2026-10-09' }, { date: '2026-10-10' }], total: 3 },
    })
    getDailyReviewDayMock.mockResolvedValue({ data: lateDetail({ status: 'signed', review: record, signed_snapshot: JSON.parse(record.snapshot_json) }) })

    await signButton(wrapper).trigger('click')
    await flushPromises()

    expect(signDailyReviewMock).toHaveBeenCalledWith(
      { review_date: '2026-10-07', note: '', delay_reason: '10-08 至 10-10 稽核人員請假' },
      { skipErrorToast: true }
    )
    expect(wrapper.find('[data-test="dr-result"]').text()).toBe('已補簽 2026-10-07。 還有 3 天待簽。')
    // 成功框帶勾號圖示
    expect(wrapper.find('[data-test="dr-result"] [data-test="dr-result-icon"]').exists()).toBe(true)
    // 簽核時間來自回應（伺服器寫入），以該日的切日時區呈現
    expect(wrapper.find('[data-test="dr-record-signed-at"]').text()).toBe('2026/10/11 10:42:18 (UTC+8)')
    expect(wrapper.find('[data-test="dr-record-type"]').text()).toBe('補簽・晚 3 天')
    expect(wrapper.find('[data-test="dr-record"]').text()).toContain('4 筆都已處置：無害 3、需升級處理 1')
    expect(wrapper.find('[data-test="dr-next"]').text()).toBe('下一天：2026-10-08')
    expect(wrapper.find('[data-test="dr-back"]').exists()).toBe(true)
    expect(eventSpy).toHaveBeenCalledTimes(1)
    expect(wrapper.emitted('changed')).toHaveLength(1)

    getDailyReviewDayMock.mockResolvedValue({ data: lateDetail({ date: '2026-10-08' }) })
    await wrapper.find('[data-test="dr-next"]').trigger('click')
    await flushPromises()
    expect(getDailyReviewDayMock).toHaveBeenLastCalledWith('2026-10-08')
  })

  // 防：搶簽時畫面只跳錯誤提示，使用者以為是自己失敗而重填重送
  it('409 改顯示對方紀錄並刷新清單', async () => {
    const wrapper = await mountDrawer({ detail: lateDetail({ date: '2026-10-08' }), date: '2026-10-08' })
    await wrapper.find('textarea[data-test="dr-text"]').setValue('稽核人員請假')
    signDailyReviewMock.mockRejectedValue(apiError(409, 'CONFLICT_DAILY_REVIEW_SIGNED', {
      date: '2026-10-08',
      signer: 'mia',
      signed_at: '2026-10-11T10:44:05+08:00',
      timezone: TZ,
    }))
    const other = signedRecord({ review_date: '2026-10-08', reviewer_name: 'mia', delay_reason: '稽核人員請假，由代理人補簽', late_days: 2 })
    getDailyReviewDayMock.mockClear()
    getDailyReviewDayMock.mockResolvedValue({ data: lateDetail({ date: '2026-10-08', status: 'signed', review: other }) })
    getDailyReviewPendingMock.mockResolvedValue({ data: { items: [{ date: '2026-10-09' }, { date: '2026-10-10' }], total: 2 } })

    await signButton(wrapper).trigger('click')
    await flushPromises()

    const banner = wrapper.find('[data-test="dr-conflict"]').text()
    expect(banner).toContain('2026-10-08 已由 mia 於 2026/10/11 10:44:05 (UTC+8) 簽核')
    expect(banner).toContain('你這次的簽核沒有送出，填寫的內容也沒有儲存')
    // 說明帶上重取後還剩幾天待簽，並有警示圖示
    expect(banner).toContain('待簽清單已重新整理。 還有 2 天待簽。')
    expect(wrapper.find('[data-test="dr-conflict"] [data-test="dr-conflict-icon"]').exists()).toBe(true)
    expect(getDailyReviewDayMock).toHaveBeenCalledTimes(1)
    expect(getDailyReviewPendingMock).toHaveBeenCalledTimes(1)
    expect(eventSpy).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-test="dr-record"]').text()).toContain('mia')
    expect(wrapper.find('[data-test="dr-record"]').text()).toContain('稽核人員請假，由代理人補簽')
    expect(wrapper.find('[data-test="dr-next"]').text()).toBe('下一天：2026-10-09')
    expect(wrapper.find('[data-test="dr-sign"]').exists()).toBe(false)
  })

  // 元件權限 stub：有檢視、無簽核（目前沒有真帳號可達這一態）
  it('無簽核權限時唯讀', async () => {
    const wrapper = await mountDrawer({
      canSign: false,
      detail: dayDetail({ unreviewed_alerts: [alert(1)], counts: { ...dayDetail().counts, unreviewed_alerts: 1, alerts_total: 1 } }),
    })
    expect(wrapper.find('textarea').exists()).toBe(false)
    expect(wrapper.find('input[type="checkbox"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="dr-sign"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="dr-alert-single"]').exists()).toBe(false)
    // 明細與處置情形仍可查看
    expect(wrapper.find('[data-test="dr-alert-1"]').text()).toContain('未審閱')
    expect(wrapper.text()).toContain('高危操作 35')
  })

  it('舊制紀錄顯示涵蓋註記', async () => {
    const legacy = signedRecord({
      late: false,
      late_days: 0,
      coverage: 'until_signed',
      timezone_inferred: true,
      snapshot_json: JSON.stringify({ date: '2026-10-07', login_failures: 2, unreviewed_alerts: 0, high_risk_ops: 1 }),
    })
    const wrapper = await mountDrawer({
      detail: dayDetail({ status: 'signed', review: legacy, signed_snapshot: JSON.parse(legacy.snapshot_json), alerts_after_sign: 0 }),
    })
    expect(wrapper.find('[data-test="dr-compare-legacy"]').text()).toBe('舊制：計數只涵蓋到簽核時刻')
    expect(wrapper.find('.dr-drawer__title').text()).toContain('2026-10-07')
    expect(wrapper.find('.dr-drawer__title').text()).toContain('的簽核紀錄')
    expect(wrapper.find('[data-test="dr-record"]').text()).toContain('時區為升級時推定')
    expect(wrapper.find('[data-test="dr-sign"]').exists()).toBe(false)
  })

  // 防：升級前的簽核不檢查告警處置，此刻仍未審閱的告警被說成「簽核後才寫入」，替簽核者開脫
  it('舊制紀錄的未審閱告警不說成簽核後出現', async () => {
    const legacy = signedRecord({
      late: false,
      late_days: 0,
      coverage: 'until_signed',
      snapshot_json: JSON.stringify({ date: '2026-10-07', login_failures: 2, unreviewed_alerts: 1, high_risk_ops: 1 }),
    })
    const wrapper = await mountDrawer({
      detail: dayDetail({
        status: 'signed',
        review: legacy,
        signed_snapshot: JSON.parse(legacy.snapshot_json),
        alerts_after_sign: null,
        unreviewed_alerts: [alert(5)],
      }),
    })
    expect(wrapper.find('[data-test="dr-after-sign"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('簽核之後才寫入')
    const box = wrapper.find('[data-test="dr-legacy-unreviewed"]')
    expect(box.text()).toContain('此刻仍未審閱的告警 1 筆')
    expect(box.text()).toContain('無法區分這些告警出現在簽核之前或之後')
    expect(box.find('[data-test="dr-legacy-unreviewed-link"]').attributes('href')).toBe('/alerts')
  })

  // 防：日終剛過就讓人送出，後端拒絕後使用者不知道何時能簽
  it('結算中停用並顯示可簽時刻', async () => {
    const wrapper = await mountDrawer({ detail: dayDetail({ status: 'settling', signable_at: '2026-10-07T16:30:00Z' }) })
    expect(signButton(wrapper).attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="dr-block"]').text()).toContain('00:30 起可簽')
    expect(wrapper.find('[data-test="dr-settling"]').text()).toContain('00:30 起可簽')
    wrapper.unmount()

    // 後端回結算中（抽屜開著時日終剛過）：同樣呈現
    const pending = await mountDrawer()
    expect(signButton(pending).attributes('disabled')).toBeUndefined()
    signDailyReviewMock.mockRejectedValue(apiError(400, 'RULE_DAILY_REVIEW_DAY_SETTLING', { signable_at: '2026-10-08T00:30:00+08:00' }))
    await signButton(pending).trigger('click')
    await flushPromises()
    expect(signButton(pending).attributes('disabled')).toBeDefined()
    expect(pending.find('[data-test="dr-block"]').text()).toContain('00:30 起可簽')
  })

  it('已清除來源不顯示為零', async () => {
    const purged = lateDetail({
      date: '2026-04-13',
      sources: { audit_log: 'purged', command_alert: 'purged' },
      counts: {
        login_failures: null, login_failures_source: 'purged', high_risk_ops: null, high_risk_ops_source: 'purged',
        unreviewed_alerts: null, alerts_total: null, alerts_source: 'purged',
      },
      unreviewed_alerts: [],
      login_failures: { total: 0, items: [], source_status: 'purged' },
      high_risk_ops: { total: 0, items: [], source_status: 'purged' },
    })
    const wrapper = await mountDrawer({ detail: purged, date: '2026-04-13' })
    const text = wrapper.text()
    expect(text).not.toMatch(/0 筆/)
    expect(wrapper.find('[data-test="dr-events-login_failures"]').text()).toContain('登入失敗 已清除')
    expect(wrapper.find('[data-test="dr-events-high_risk_ops"]').text()).toContain('高危操作 已清除')
    expect(wrapper.find('[data-test="dr-alerts-purged"]').text()).toContain('無法確認當時是否全部處置')
    expect(wrapper.find('[data-test="dr-source-notice"]').exists()).toBe(true)
    // 仍可輸入延遲原因並送出
    await wrapper.find('textarea[data-test="dr-text"]').setValue('升級後補列的日子，見工單 SEC-2291')
    expect(signButton(wrapper).attributes('disabled')).toBeUndefined()
    expect(text).toContain('請寫明外部證據在哪裡')
  })

  it('已簽日顯示簽後出現的告警', async () => {
    const record = signedRecord({ late: false, late_days: 0 })
    const wrapper = await mountDrawer({
      detail: dayDetail({
        status: 'signed',
        review: record,
        signed_snapshot: JSON.parse(record.snapshot_json),
        alerts_after_sign: 1,
        unreviewed_alerts: [alert(5)],
      }),
    })
    const box = wrapper.find('[data-test="dr-after-sign"]')
    expect(box.text()).toContain('簽核後出現的未審閱告警 1 筆')
    const link = box.find('[data-test="dr-after-sign-link"]')
    expect(link.attributes('href')).toBe('/alerts')
    await link.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/alerts')
    // 簽核時與目前可查分開列
    const compare = wrapper.find('[data-test="dr-compare"]').text()
    expect(compare).toContain('簽核時的計數')
    expect(compare).toContain('目前可查')
  })

  // 防：告警列「簽核時」帶「（都已處置）」字樣，與目前可查逐字比對永遠不同，
  // 0 與 0 也被著上「與簽核時不同」的警示色
  it('唯讀對照只在計數與簽核時不同時著色', async () => {
    const snapshot = {
      date: '2026-10-07', login_failures: 3, login_failures_source: 'complete', high_risk_ops: 4,
      high_risk_ops_source: 'complete', unreviewed_alerts: 0, alerts_total: 0, alerts_benign: 0,
      alerts_escalated: 0, alerts_source: 'complete',
    }
    const record = signedRecord({ late: false, late_days: 0, snapshot_json: JSON.stringify(snapshot) })
    const wrapper = await mountDrawer({
      detail: dayDetail({
        status: 'signed',
        review: record,
        signed_snapshot: snapshot,
        alerts_after_sign: 0,
        high_risk_ops: eventList(6),
      }),
    })
    const alertsNow = wrapper.find('[data-test="dr-compare-now-alerts"]')
    expect(alertsNow.text()).toBe('0')
    expect(alertsNow.classes()).not.toContain('dr-compare__diff')
    expect(wrapper.find('[data-test="dr-compare-now-login"]').classes()).not.toContain('dr-compare__diff')
    // 高危操作簽核時 4、目前 6：不同才著色
    expect(wrapper.find('[data-test="dr-compare-now-high"]').classes()).toContain('dr-compare__diff')
  })

  // 防：推定日被做成唯讀而永遠簽不掉，或可簽卻沒有任何推定說明、讓人以為那天確定開著
  it('推定日顯示推定說明且可簽', async () => {
    const wrapper = await mountDrawer({ detail: lateDetail({ date: '2026-04-04', enabled_basis: 'presumed_gap' }), date: '2026-04-04' })
    const notice = wrapper.find('[data-test="dr-inferred-notice"]').text()
    expect(notice).toContain('這一天的啟用狀態由推定而來')
    expect(notice).toContain('前後紀錄銜接不上')
    const textarea = wrapper.find('textarea[data-test="dr-text"]')
    expect(textarea.exists()).toBe(true)
    await textarea.setValue('升級前紀錄銜接不上，依推定補簽')
    expect(signButton(wrapper).attributes('disabled')).toBeUndefined()
    signDailyReviewMock.mockResolvedValue({ data: signedRecord({ review_date: '2026-04-04', enabled_basis: 'presumed_gap' }) })
    await signButton(wrapper).trigger('click')
    await flushPromises()
    expect(signDailyReviewMock).toHaveBeenCalledTimes(1)
    wrapper.unmount()

    // 已簽日帶同值：唯讀抽屜顯示同一說明
    const record = signedRecord({ review_date: '2026-04-04', enabled_basis: 'presumed_gap' })
    const signed = await mountDrawer({
      detail: lateDetail({ date: '2026-04-04', status: 'signed', enabled_basis: 'presumed_gap', review: record, signed_snapshot: JSON.parse(record.snapshot_json) }),
      date: '2026-04-04',
    })
    expect(signed.find('[data-test="dr-inferred-notice"]').text()).toContain('前後紀錄銜接不上')
    expect(signed.find('[data-test="dr-record-inferred"]').text()).toBe('啟用狀態為推定')
    expect(signed.find('[data-test="dr-sign"]').exists()).toBe(false)
  })

  it('文字過長的錯誤以欄位名呈現，不露出機器值', async () => {
    const { ElMessage } = await import('element-plus')
    const errorSpy = vi.spyOn(ElMessage, 'error')
    const wrapper = await mountDrawer({ detail: lateDetail() })
    await wrapper.find('textarea[data-test="dr-text"]').setValue('x')
    signDailyReviewMock.mockRejectedValue(apiError(400, 'VALIDATION_DAILY_REVIEW_TEXT_TOO_LONG', { field: 'delay_reason' }))
    await signButton(wrapper).trigger('click')
    await flushPromises()
    expect(errorSpy).toHaveBeenCalledWith('延遲原因超過 500 字上限')
    errorSpy.mockRestore()
  })
})
