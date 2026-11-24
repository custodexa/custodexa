import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, DOMWrapper } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewWorkspace from '../DailyReviewWorkspace.vue'
import DailyReviewDrawer from '../DailyReviewDrawer.vue'
import { BATCH_LIMIT } from '@/composables/useBatchReview'
import { clearSession } from '@/utils/session'
import { DAILY_REVIEWS_CHANGED, formatInZone } from '../dailyReviewFormat'
import { setLanguage } from '@/i18n'
import { CONFIRM_LIST_MAX_HEIGHT, CONFIRM_LIST_MIN_HEIGHT, fitListHeight } from '../multiSign'

// 每日簽核的多日簽核：勾選多個待簽日 → 確認（開啟時重取）→ 前端逐日呼叫單日簽核端點。
// 斷言以「實際發出的請求序列」為準：哪幾天送了、順序、關聯碼、延遲原因帶不帶。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 30_000 })

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

const api = {
  status: vi.fn(),
  pending: vi.fn(),
  list: vi.fn(),
  stats: vi.fn(),
  day: vi.fn(),
  sign: vi.fn(),
}
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: (...a) => api.status(...a),
  getDailyReviewPending: (...a) => api.pending(...a),
  getDailyReviews: (...a) => api.list(...a),
  getDailyReviewStats: (...a) => api.stats(...a),
  getDailyReviewDay: (...a) => api.day(...a),
  signDailyReview: (...a) => api.sign(...a),
  getDailyReviewPendingCount: vi.fn().mockResolvedValue({ data: { count: 0, overdue_count: 0 } }),
}))

// 告警處置的替身端點（跨日處置）：不打任何真實服務
const alertApi = { batch: vi.fn(), search: vi.fn(), review: vi.fn() }
vi.mock('@/api/alerts', () => ({
  batchReviewAlerts: (...a) => alertApi.batch(...a),
  searchAlerts: (...a) => alertApi.search(...a),
  reviewAlert: (...a) => alertApi.review(...a),
}))
vi.mock('@/api/systemAlerts', () => ({ getSystemAlertDetail: vi.fn() }))

const ME = 7
const T905 = formatInZone('2026-10-11T01:05:00Z', 'Asia/Taipei', { seconds: true })
const T912 = formatInZone('2026-10-11T09:12:30+08:00', 'Asia/Taipei', { seconds: true })
const STORAGE_KEY = 'ot-batch-review:daily-review'
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const TZ = 'Asia/Taipei'

const okCounts = (extra = {}) => ({
  login_failures: 2, login_failures_source: 'complete',
  high_risk_ops: 1, high_risk_ops_source: 'complete',
  unreviewed_alerts: 0, alerts_total: 3, alerts_source: 'complete',
  ...extra,
})

const day = (date, { overdue = true, lateDays = 3, signable = true, counts = okCounts() } = {}) => {
  const start = new Date(`${date}T00:00:00+08:00`)
  const iso = (offsetDays) => new Date(start.getTime() + offsetDays * 86400000).toISOString()
  return {
    date, timezone: TZ, timezone_inferred: false,
    window_start: iso(0), window_end: iso(1), due_at: iso(2),
    signable_at: new Date(start.getTime() + 86400000 + 1800000).toISOString(),
    signable, overdue, late_days: overdue ? lateDays : 0, enabled_basis: 'recorded', counts,
  }
}

// n 天，由 startISO 起每天一個（全部已逾期、可簽）
const series = (n, startISO = '2026-08-01') => Array.from({ length: n }, (_, i) => {
  const d = new Date(`${startISO}T00:00:00Z`)
  d.setUTCDate(d.getUTCDate() + i)
  return day(d.toISOString().slice(0, 10), { lateDays: n - i })
})

// 待簽清單替身：依 page 參數分頁（每頁 31 天）
let pendingDays = []
const servePending = () => api.pending.mockImplementation(async (params = {}) => {
  const page = params.page || 1
  const size = params.page_size || 31
  return { data: { items: pendingDays.slice((page - 1) * size, page * size), total: pendingDays.length, page, page_size: size } }
})

const httpError = (status, code, params) => ({ response: { status, data: { code, error: code, params } } })
const networkError = () => ({ request: {}, message: 'Network Error' })

const mountWorkspace = (props = {}) =>
  mount(DailyReviewWorkspace, {
    props: { canSign: true, ...props },
    global: { plugins: [ElementPlus], stubs: { RouterLink: true, 'router-link': true } },
    attachTo: document.body,
  })

const cell = (w, date) => w.find(`[data-test="dr-select-cell"][data-id="${date}"] input`)
const dialog = (w) => w.find('[data-test="dr-multi-dialog"]')
const signedDates = () => api.sign.mock.calls.map(([body]) => body.review_date)

const goPage = async (w, page) => {
  const pager = w.findComponent({ name: 'ElPagination' })
  pager.vm.$emit('update:current-page', page)
  pager.vm.$emit('current-change', page)
  await flushPromises()
}
const select = async (w, dates) => {
  for (const date of dates) await cell(w, date).setValue(true)
  await flushPromises()
}
const openConfirm = async (w) => {
  await w.find('[data-test="dr-multi-open"]').trigger('click')
  await flushPromises()
}
const fillAndSubmit = async (w, { reason = '連假期間無人值班', note = '' } = {}) => {
  const delay = dialog(w).find('[data-test="dr-multi-delay"] textarea')
  if (delay.exists() && reason !== null) await delay.setValue(reason)
  if (note) await dialog(w).find('[data-test="dr-multi-note"] textarea').setValue(note)
  await dialog(w).find('[data-test="dr-multi-submit"]').trigger('click')
  await flushPromises()
}
const resultRows = (w) => dialog(w).findAll('[data-test="batch-item"]').map((n) => ({
  id: n.attributes('data-id'), state: n.attributes('data-state'), text: n.text(),
}))

describe('每日簽核的多日簽核', () => {
  beforeEach(() => {
    Object.values(api).forEach((m) => m.mockReset())
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'auditor1' }))
    api.status.mockResolvedValue({ data: { enabled: true, timezone_state: { active: TZ, today: { date: '2026-10-11' } }, overdue_count: 0 } })
    api.list.mockResolvedValue({ data: { items: [], total: 0 } })
    api.stats.mockResolvedValue({ data: null })
    api.sign.mockImplementation(async (body) => ({ data: { review_date: body.review_date, late: Boolean(body.delay_reason) } }))
    pendingDays = []
    servePending()
  })

  describe('待簽清單的勾選', () => {
    // 有未審閱告警的日子也可以勾，勾了先處置、不能直接簽
    it('可簽的日子可勾選（含有未審閱告警的日子，並寫明處置完才能簽核）；尚在落庫寬限的日子停用並寫明原因', async () => {
      pendingDays = [
        day('2026-10-06'),
        day('2026-10-07', { counts: okCounts({ unreviewed_alerts: 2 }) }),
        day('2026-10-10', { overdue: false, signable: false }),
      ]
      const w = mountWorkspace()
      await flushPromises()
      expect(cell(w, '2026-10-06').attributes('disabled')).toBeUndefined()
      expect(cell(w, '2026-10-07').attributes('disabled')).toBeUndefined()
      expect(cell(w, '2026-10-10').attributes('disabled')).toBeDefined()
      const table = w.find('[data-test="dr-pending-table"]').text()
      expect(table).toContain('有 2 筆告警，處置完才能簽核')
      expect(table).toContain('00:30 起可簽，讓日終前後的紀錄先寫進來')
      expect(table).toContain('今天 00:30 起可簽')
      // 停用的原因也是勾選框的可讀名稱
      expect(w.find('[data-test="dr-select-cell"][data-id="2026-10-10"]').text()).toContain('00:30 起可簽')
    })

    it(`全選只選本頁可勾的日子且不超過上限（沿用 BATCH_LIMIT＝${BATCH_LIMIT}）`, async () => {
      pendingDays = [day('2026-07-01', { counts: okCounts({ unreviewed_alerts: 1 }) }), ...series(BATCH_LIMIT + 5)]
      // 一頁放得下全部（替身不受 31 天限制），檢查上限而不是分頁
      api.pending.mockImplementation(async () => ({ data: { items: pendingDays, total: pendingDays.length } }))
      const w = mountWorkspace()
      await flushPromises()
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await flushPromises()
      const checked = w.findAll('[data-test="dr-select-cell"] input').filter((n) => n.element.checked)
      expect(checked).toHaveLength(BATCH_LIMIT)
      // 有告警的日子也勾進來（勾了先處置）
      expect(cell(w, '2026-07-01').element.checked).toBe(true)
      const bar = w.find('[data-test="dr-batch-bar"]')
      expect(bar.text()).toContain(`已選 ${BATCH_LIMIT} 天`)
      expect(bar.text()).toContain(`一次最多 ${BATCH_LIMIT} 天，其餘請簽完這一批再選`)
      expect(bar.text()).toContain('其中 1 天有 1 筆告警，要先處置才能簽核')
      const rest = pendingDays[pendingDays.length - 1].date
      expect(cell(w, rest).attributes('disabled')).toBeDefined()
      expect(w.find(`[data-test="dr-select-cell"][data-id="${rest}"]`).text()).toContain(`已選滿 ${BATCH_LIMIT} 天，這一天請下一批再簽`)
    })

    // 情境「超過單次上限時分次處理」：期望值寫死 50，不引用常數
    it('60 天跨兩頁：勾滿 50 天後第 51 天不能勾；簽完這 50 天後可再勾剩下的', async () => {
      pendingDays = series(60)
      const w = mountWorkspace()
      await flushPromises()
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await flushPromises()
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('已選 31 天')
      // 換到第 2 頁再全選：補到 50 天為止
      await goPage(w, 2)
      await flushPromises()
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await flushPromises()
      const bar = w.find('[data-test="dr-batch-bar"]').text()
      expect(bar).toContain('已選 50 天')
      expect(bar).toContain('其中 31 天在其他頁')
      expect(bar).toContain('一次最多 50 天')
      const page2 = pendingDays.slice(31)
      expect(page2.filter((d) => cell(w, d.date).element.checked)).toHaveLength(19)
      const fifty1 = page2[19].date
      expect(cell(w, fifty1).attributes('disabled')).toBeDefined()
      await cell(w, fifty1).setValue(true)
      await flushPromises()
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('已選 50 天')

      await openConfirm(w)
      expect(dialog(w).findAll('[data-test="dr-multi-date"]')).toHaveLength(50)
      expect(dialog(w).find('[data-test="dr-multi-list-count"]').text()).toBe('共 50 天，捲動清單可看全部')
      // 伺服器端：每簽一天就從待簽清單消失
      api.sign.mockImplementation(async (body) => {
        pendingDays = pendingDays.filter((d) => d.date !== body.review_date)
        return { data: { review_date: body.review_date, late: true } }
      })
      await fillAndSubmit(w)
      expect(api.sign).toHaveBeenCalledTimes(50)
      await dialog(w).find('[data-test="dr-multi-done"]').trigger('click')
      await flushPromises()
      expect(pendingDays).toHaveLength(10)
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await flushPromises()
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('已選 10 天')
    })

    it('跨頁勾選後可以取消其中一天（以所屬日為識別）', async () => {
      pendingDays = series(40)
      const w = mountWorkspace()
      await flushPromises()
      await select(w, [pendingDays[0].date, pendingDays[1].date])
      await goPage(w, 2)
      await flushPromises()
      await select(w, [pendingDays[35].date])
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('已選 3 天')
      await goPage(w, 1)
      await flushPromises()
      // 回到第 1 頁時列物件是新取的，仍認得是已勾選的那一天
      expect(cell(w, pendingDays[1].date).element.checked).toBe(true)
      await cell(w, pendingDays[1].date).setValue(false)
      await flushPromises()
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('已選 2 天')
      await openConfirm(w)
      expect(dialog(w).findAll('[data-test="dr-multi-date"]').map((n) => n.text().slice(0, 10)))
        .toEqual([pendingDays[0].date, pendingDays[35].date])
    })

    it('已勾選的日子之後變成不可簽，仍可以取消勾選', async () => {
      pendingDays = [day('2026-10-06'), day('2026-10-07')]
      const w = mountWorkspace()
      await flushPromises()
      await select(w, ['2026-10-07'])
      pendingDays = [day('2026-10-06'), day('2026-10-07', { signable: false })]
      window.dispatchEvent(new Event(DAILY_REVIEWS_CHANGED))
      await flushPromises()
      expect(cell(w, '2026-10-07').element.checked).toBe(true)
      expect(cell(w, '2026-10-07').attributes('disabled')).toBeUndefined()
      await cell(w, '2026-10-07').setValue(false)
      await flushPromises()
      expect(w.find('[data-test="dr-batch-bar"]').exists()).toBe(false)
      expect(cell(w, '2026-10-07').attributes('disabled')).toBeDefined()
    })

    it('只有查看權限時沒有勾選欄、批次列與多日簽核的說明', async () => {
      pendingDays = [day('2026-10-06'), day('2026-10-07')]
      const w = mountWorkspace({ canSign: false })
      await flushPromises()
      expect(w.find('[data-test="dr-select-cell"]').exists()).toBe(false)
      expect(w.find('[data-test="dr-select-all"]').exists()).toBe(false)
      expect(w.find('[data-test="dr-multi-hint"]').exists()).toBe(false)
      expect(w.find('[data-test="dr-multi-dialog"]').exists()).toBe(false)
    })
  })

  describe('確認步驟', () => {
    // 情境「確認步驟列出每天的計數」
    it('逐日列出所屬日、補簽與晚的天數、三項計數，可開明細（唯讀）；未確認不送出', async () => {
      pendingDays = [
        day('2026-10-04', { lateDays: 5 }), day('2026-10-05', { lateDays: 4 }), day('2026-10-06', { lateDays: 3 }),
        day('2026-10-07', { lateDays: 2 }), day('2026-10-08', { lateDays: 1 }),
      ]
      api.day.mockResolvedValue({ data: { date: '2026-10-06', status: 'pending', timezone: TZ, counts: okCounts(), unreviewed_alerts: [] } })
      const w = mountWorkspace()
      await flushPromises()
      await select(w, pendingDays.map((d) => d.date))
      api.pending.mockClear()
      await openConfirm(w)
      // 開啟時重取所選日子
      expect(api.pending).toHaveBeenCalled()
      const d = dialog(w)
      expect(d.text()).toContain('簽核 5 天的每日審閱')
      expect(d.findAll('[data-test="dr-multi-type"]').map((n) => n.text())).toEqual(
        ['補簽・晚 5 天', '補簽・晚 4 天', '補簽・晚 3 天', '補簽・晚 2 天', '補簽・晚 1 天'])
      expect(d.findAll('[data-test="dr-multi-login"]').map((n) => n.text())).toEqual(['2', '2', '2', '2', '2'])
      expect(d.findAll('[data-test="dr-multi-alerts"]').map((n) => n.text())).toEqual(['0', '0', '0', '0', '0'])
      expect(d.findAll('[data-test="dr-multi-high"]').map((n) => n.text())).toEqual(['1', '1', '1', '1', '1'])
      expect(d.find('[data-test="dr-multi-as-of"]').text()).toMatch(/^以下是 \d{2}:\d{2} 查詢的數字；每一天的簽核紀錄記下的，是送出當下由系統重新計算的數字。$/)
      expect(d.text()).toContain('延遲原因（必填，套用到 5 天補簽）')
      expect(d.text()).toContain('逐日簽核 5 天')

      await d.findAll('[data-test="dr-multi-view"]')[2].trigger('click')
      await flushPromises()
      expect(api.day).toHaveBeenCalledWith('2026-10-06')
      const drawer = w.findComponent(DailyReviewDrawer)
      expect(document.body.querySelector('[data-test="dr-from-batch"]')?.textContent).toContain('只供查看')
      expect(document.body.querySelector('[data-test="dr-sign"]')).toBeNull()
      expect(document.body.querySelector('[data-test="dr-back-to-batch"]')).not.toBeNull()
      expect(drawer.exists()).toBe(true)
      expect(api.sign).not.toHaveBeenCalled()

      // 取消：一天都不送，勾選保留
      await d.find('[data-test="dr-multi-cancel"]').trigger('click')
      await flushPromises()
      expect(api.sign).not.toHaveBeenCalled()
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('已選 5 天')
    })

    // 情境「開啟確認時移出已不可簽的日子」與「來源已清除的計數不顯示為 0」
    it('開啟確認時重取：已被簽、多了告警的日子移出並說明；已清除的計數照實標示；只送留下的日子', async () => {
      pendingDays = [day('2026-10-04'), day('2026-10-05'), day('2026-10-06'), day('2026-10-07')]
      const w = mountWorkspace()
      await flushPromises()
      await select(w, pendingDays.map((d) => d.date))
      // 勾選之後：10-05 被別人簽了、10-06 多了 2 筆告警、10-07 的告警來源已清除
      pendingDays = [
        day('2026-10-04'),
        day('2026-10-06', { counts: okCounts({ unreviewed_alerts: 2 }) }),
        day('2026-10-07', { counts: okCounts({ unreviewed_alerts: null, alerts_total: null, alerts_source: 'purged' }) }),
      ]
      api.day.mockImplementation(async (date) => (date === '2026-10-05'
        ? { data: { date, status: 'signed', review: { reviewer_id: 99, reviewer_name: 'auditor-b', signed_at: '2026-10-11T01:05:00Z', timezone: TZ } } }
        : { data: { date, status: 'pending' } }))
      await openConfirm(w)
      const d = dialog(w)
      expect(d.find('[data-test="dr-multi-removed"]').text()).toContain('有 2 天已從這一批移出，不會送出：')
      const removed = d.findAll('[data-test="dr-multi-removed-item"]')
      expect(removed.map((n) => n.attributes('data-date'))).toEqual(['2026-10-05', '2026-10-06'])
      expect(removed[0].text()).toBe(`2026-10-05\u3000已由 auditor-b 於 ${T905} 簽核，不需要再簽`)
      expect(removed[1].text()).toBe('2026-10-06\u3000出現 2 筆未審閱告警，請先處置再簽')
      expect(d.findAll('[data-test="dr-multi-date"]').map((n) => n.text().slice(0, 10))).toEqual(['2026-10-04', '2026-10-07'])
      expect(d.findAll('[data-test="dr-multi-alerts"]').map((n) => n.text())).toEqual(['0', '已清除'])
      const note = d.find('[data-test="dr-multi-source-note"]').text()
      expect(note).toContain('2026-10-07 的紀錄已依保留政策清除，查不到筆數，不代表當天沒有發生；')
      expect(note).toContain('簽核前可以按該列的「查看明細」了解詳情。')
      // 來源已清除時，延遲原因的提示請寫明外部證據在哪裡
      expect(d.text()).toContain('紀錄已清除時，請寫明外部證據在哪裡')
      expect(d.text()).toContain('簽核 2 天的每日審閱')
      await fillAndSubmit(w)
      expect(signedDates()).toEqual(['2026-10-04', '2026-10-07'])
    })

    it('重取完成前不能送出', async () => {
      pendingDays = [day('2026-10-04')]
      const w = mountWorkspace()
      await flushPromises()
      await select(w, ['2026-10-04'])
      let release
      api.pending.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
      await w.find('[data-test="dr-multi-open"]').trigger('click')
      await flushPromises()
      expect(dialog(w).find('[data-test="dr-multi-refetching"]').exists()).toBe(true)
      expect(dialog(w).find('[data-test="dr-multi-submit"]').attributes('disabled')).toBeDefined()
      release({ data: { items: pendingDays, total: 1 } })
      await flushPromises()
      expect(dialog(w).find('[data-test="dr-multi-submit"]').attributes('disabled')).toBeUndefined()
    })

    it('含補簽而未填延遲原因時一天都不送，顯示與單日相同的錯誤', async () => {
      pendingDays = [day('2026-10-04'), day('2026-10-10', { overdue: false })]
      const w = mountWorkspace()
      await flushPromises()
      await select(w, ['2026-10-04', '2026-10-10'])
      await openConfirm(w)
      await fillAndSubmit(w, { reason: null })
      expect(api.sign).not.toHaveBeenCalled()
      expect(dialog(w).find('[data-test="dr-multi-delay-error"]').text()).toBe('請填寫延遲原因，才能補簽。')
    })
  })

  describe('逐日送出與結果', () => {
    // 情境「一次補簽多天」
    it('全部成功：由最早的一天依序送出，同一批同一個 UUID 關聯碼，補簽的日子帶延遲原因', async () => {
      pendingDays = [day('2026-10-06', { lateDays: 3 }), day('2026-10-04', { lateDays: 5 }), day('2026-10-05', { lateDays: 4 })]
        .sort((a, b) => a.date.localeCompare(b.date))
      let releaseFirst
      api.sign
        .mockImplementationOnce((body) => new Promise((resolve) => { releaseFirst = () => resolve({ data: { review_date: body.review_date, late: true } }) }))
      const w = mountWorkspace()
      await flushPromises()
      await select(w, ['2026-10-06', '2026-10-04', '2026-10-05'])
      await openConfirm(w)
      await fillAndSubmit(w, { reason: '連假期間無人值班', note: '已逐日看過' })
      // 循序：第一天沒回應前不送第二天
      expect(api.sign).toHaveBeenCalledTimes(1)
      expect(dialog(w).text()).toContain('第 1／3 天')
      expect(dialog(w).text()).toContain('正在簽核 3 天')
      releaseFirst()
      await flushPromises()
      expect(signedDates()).toEqual(['2026-10-04', '2026-10-05', '2026-10-06'])
      const bodies = api.sign.mock.calls.map(([body]) => body)
      const batchId = bodies[0].batch_id
      expect(batchId).toMatch(UUID_V4)
      for (const body of bodies) {
        expect(body).toEqual({ review_date: body.review_date, batch_id: batchId, note: '已逐日看過', delay_reason: '連假期間無人值班' })
      }
      expect(api.sign.mock.calls[0][1]).toEqual({ skipErrorToast: true })
      expect(dialog(w).find('[data-test="dr-multi-summary"]').text()).toBe('成功 3 天 · 被拒 0 天 · 未送出 0 天 · 待確認 0 天')
      expect(resultRows(w).map((r) => r.text)).toEqual([
        expect.stringContaining('已補簽（晚 5 天）'),
        expect.stringContaining('已補簽（晚 4 天）'),
        expect.stringContaining('已補簽（晚 3 天）'),
      ])
    })

    // 情境「準時與補簽混選」
    it('準時與補簽混選：延遲原因必填，只帶給補簽的日子；昨日的請求不帶延遲原因', async () => {
      pendingDays = [day('2026-10-08', { lateDays: 2 }), day('2026-10-09', { lateDays: 1 }), day('2026-10-10', { overdue: false })]
      const w = mountWorkspace()
      await flushPromises()
      await select(w, pendingDays.map((d) => d.date))
      expect(w.find('[data-test="dr-batch-bar"]').text()).toContain('（補簽 2 天、準時 1 天）')
      await openConfirm(w)
      const d = dialog(w)
      expect(d.text()).toContain('延遲原因（必填，套用到 2 天補簽）')
      expect(d.text()).toContain('準時簽核的 2026-10-10 不會保存延遲原因。')
      expect(d.findAll('[data-test="dr-multi-type"]').map((n) => n.text())).toEqual(['補簽・晚 2 天', '補簽・晚 1 天', '準時'])
      await fillAndSubmit(w, { reason: '週末補簽' })
      const bodies = api.sign.mock.calls.map(([body]) => body)
      expect(bodies.map((b) => [b.review_date, b.delay_reason])).toEqual([
        ['2026-10-08', '週末補簽'], ['2026-10-09', '週末補簽'], ['2026-10-10', undefined],
      ])
      expect('delay_reason' in bodies[2]).toBe(false)
      expect(resultRows(w)[2].text).toContain('已簽核（準時）')
    })

    // 情境「部分完成時逐日回報」
    it('第二天回 409：寫明對方與時刻，其餘照送', async () => {
      pendingDays = [day('2026-10-04'), day('2026-10-05'), day('2026-10-06'), day('2026-10-07')]
      api.sign.mockImplementation(async (body) => {
        if (body.review_date === '2026-10-05') {
          throw httpError(409, 'CONFLICT_DAILY_REVIEW_SIGNED', { date: '2026-10-05', signer: 'auditor-b', signed_at: '2026-10-11T09:12:30+08:00', timezone: TZ })
        }
        return { data: { review_date: body.review_date, late: true } }
      })
      const w = mountWorkspace()
      await flushPromises()
      await select(w, pendingDays.map((d) => d.date))
      await openConfirm(w)
      await fillAndSubmit(w)
      expect(signedDates()).toEqual(['2026-10-04', '2026-10-05', '2026-10-06', '2026-10-07'])
      const rows = resultRows(w)
      expect(rows.map((r) => r.state)).toEqual(['success', 'rejected', 'success', 'success'])
      expect(rows[1].text).toContain(`被拒：已由 auditor-b 於 ${T912} 簽核，不需要再簽`)
      expect(dialog(w).find('[data-test="dr-multi-summary"]').text()).toBe('成功 3 天 · 被拒 1 天 · 未送出 0 天 · 待確認 0 天')
      expect(dialog(w).find('[data-test="dr-multi-leftover-other"]').text()).toBe('已由別人簽核的日子不需要再簽，對方的紀錄在已簽紀錄裡。')
      expect(dialog(w).find('[data-test="dr-multi-refreshed"]').exists()).toBe(true)
      expect(dialog(w).find('[data-test="dr-multi-leftover-not-sent"]').exists()).toBe(false)
    })

    it('某天送出時又出現未審閱告警：被拒並寫明筆數', async () => {
      pendingDays = [day('2026-10-04'), day('2026-10-05')]
      api.sign.mockImplementation(async (body) => {
        if (body.review_date === '2026-10-04') throw httpError(400, 'RULE_DAILY_REVIEW_ALERTS_PENDING', { count: 2 })
        return { data: { review_date: body.review_date, late: true } }
      })
      const w = mountWorkspace()
      await flushPromises()
      await select(w, ['2026-10-04', '2026-10-05'])
      await openConfirm(w)
      await fillAndSubmit(w)
      const rows = resultRows(w)
      expect(rows[0].text).toContain('被拒：這一天又出現 2 筆未審閱告警，請先處置再簽')
      expect(dialog(w).find('[data-test="dr-multi-leftover-alerts"]').exists()).toBe(true)
      expect(rows[1].state).toBe('success')
    })

    // 情境「某一天沒有回應時其餘照送」
    it('沒有回應的日子記為待確認、其餘照送；重新查詢依該日簽核紀錄分為本人、他人、查無三種', async () => {
      pendingDays = ['2026-10-03', '2026-10-04', '2026-10-05', '2026-10-06', '2026-10-07'].map((d) => day(d))
      const noResponse = new Set(['2026-10-04', '2026-10-05', '2026-10-06'])
      api.sign.mockImplementation(async (body) => {
        if (noResponse.has(body.review_date)) throw networkError()
        return { data: { review_date: body.review_date, late: true } }
      })
      const w = mountWorkspace()
      await flushPromises()
      await select(w, pendingDays.map((d) => d.date))
      await openConfirm(w)
      await fillAndSubmit(w)
      // 第三天無回應，第四、第五天的請求照常發出
      expect(signedDates()).toEqual(['2026-10-03', '2026-10-04', '2026-10-05', '2026-10-06', '2026-10-07'])
      expect(resultRows(w).map((r) => r.state)).toEqual(['success', 'unconfirmed', 'unconfirmed', 'unconfirmed', 'success'])
      expect(dialog(w).find('[data-test="dr-multi-unconfirmed-hint"]').text()).toContain('按「重新查詢」會以該日的簽核紀錄確認')
      expect(dialog(w).find('[data-test="dr-multi-leftover-not-sent"]').exists()).toBe(false) // 未送出只出現在離開頁面

      const review = (reviewerId, name) => ({ reviewer_id: reviewerId, reviewer_name: name, signed_at: '2026-10-11T01:05:00Z', timezone: TZ, late: true, late_days: 3 })
      api.day.mockImplementation(async (date) => {
        if (date === '2026-10-04') return { data: { date, status: 'signed', review: review(ME, 'auditor1') } }
        if (date === '2026-10-05') return { data: { date, status: 'signed', review: review(99, 'auditor-b') } }
        return { data: { date, status: 'pending', review: null } }
      })
      await dialog(w).find('[data-test="dr-multi-recheck"]').trigger('click')
      await flushPromises()
      const rows = resultRows(w)
      expect(rows.map((r) => r.state)).toEqual(['success', 'success', 'rejected', 'unconfirmed', 'success'])
      expect(rows[1].text).toContain(`已補簽（晚 3 天），${T905} 由你簽核`)
      expect(rows[2].text).toContain(`被拒：已由 auditor-b 於 ${T905} 簽核`)
      expect(rows[3].text).toContain('待確認：目前查無簽核紀錄')
      expect(dialog(w).find('[data-test="dr-multi-none-found-hint"]').text()).toContain('按「完成」後回清單重新勾選')
      // 重新查詢只讀，不重送
      expect(api.sign).toHaveBeenCalledTimes(5)
      expect(dialog(w).find('[data-test="dr-multi-recheck"]').exists()).toBe(true)
    })

    it('結果一出現就重取清單、統計與徽章（不等按完成）；最後一頁變空時回到有效頁碼', async () => {
      pendingDays = series(33)
      const w = mountWorkspace()
      await flushPromises()
      await goPage(w, 2)
      await flushPromises()
      await select(w, [pendingDays[31].date, pendingDays[32].date])
      await openConfirm(w)
      const changed = vi.fn()
      window.addEventListener(DAILY_REVIEWS_CHANGED, changed)
      api.pending.mockClear()
      api.stats.mockClear()
      api.status.mockClear()
      // 送出後伺服器端第 2 頁的兩天都簽掉
      api.sign.mockImplementation(async (body) => {
        pendingDays = pendingDays.filter((d) => d.date !== body.review_date)
        return { data: { review_date: body.review_date, late: true } }
      })
      await fillAndSubmit(w)
      window.removeEventListener(DAILY_REVIEWS_CHANGED, changed)
      expect(dialog(w).find('[data-test="dr-multi-done"]').exists()).toBe(true) // 還沒按完成
      expect(changed).toHaveBeenCalled() // 徽章依此事件重算
      expect(api.status).toHaveBeenCalled()
      expect(api.stats).toHaveBeenCalled()
      const pages = api.pending.mock.calls.map(([p]) => p.page)
      expect(pages).toContain(2)
      expect(pages[pages.length - 1]).toBe(1) // 第 2 頁空了，回到第 1 頁
      expect(w.findAll('[data-test="dr-pending-date"]')).toHaveLength(31)
    })
  })

  describe('重新載入與登出', () => {
    const savedBatch = (userId, items) => JSON.stringify({
      v: 1, batchId: '0d6f8b1c-2a3e-4f50-8a61-7b8c9d0e1f2a', kind: 'daily-review', params: {}, userId,
      startedAt: '2026-10-11T01:00:00Z', items,
    })
    const item = (id, state) => ({ id, label: id, late: true, lateDays: 3, state, message: '' })

    // 情境「重新載入後不自動續送」
    it('重新載入後顯示上一批結果並查詢實際狀態，不自動發出任何簽核請求', async () => {
      sessionStorage.setItem(STORAGE_KEY, savedBatch(ME, [
        item('2026-10-04', 'success'), item('2026-10-05', 'inflight'), item('2026-10-06', 'queued'), item('2026-10-07', 'queued'),
      ]))
      pendingDays = [day('2026-10-05'), day('2026-10-06'), day('2026-10-07')]
      api.day.mockResolvedValue({ data: { status: 'pending', review: null } })
      const w = mountWorkspace()
      await flushPromises()
      expect(api.sign).not.toHaveBeenCalled()
      expect(api.day).toHaveBeenCalledWith('2026-10-05', { skipErrorToast: true })
      expect(dialog(w).find('[data-test="dr-multi-recovered"]').text()).toBe('頁面重新載入時，上一批多日簽核還沒處理完。')
      expect(resultRows(w).map((r) => r.state)).toEqual(['success', 'unconfirmed', 'notSent', 'notSent'])
      expect(dialog(w).find('[data-test="dr-multi-leftover-not-sent"]').exists()).toBe(true)
      await dialog(w).find('[data-test="dr-multi-done"]').trigger('click')
      await flushPromises()
      expect(api.sign).not.toHaveBeenCalled()
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
    })

    // 情境「登出後進度不留給下一位使用者」
    it('登出時清掉分頁暫存；換人登入不出現上一批', async () => {
      sessionStorage.setItem(STORAGE_KEY, savedBatch(ME, [item('2026-10-04', 'success')]))
      sessionStorage.setItem('ot-batch-review:alerts', 'other-surface')
      clearSession()
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
      // 其他面的進度不受影響
      expect(sessionStorage.getItem('ot-batch-review:alerts')).toBe('other-surface')

      // 另一位使用者留下的批次（例如登出清除失敗）：不接手並清掉
      sessionStorage.setItem(STORAGE_KEY, savedBatch(99, [item('2026-10-04', 'inflight')]))
      localStorage.setItem('user', JSON.stringify({ id: ME, username: 'auditor1' }))
      const w = mountWorkspace()
      await flushPromises()
      expect(dialog(w).exists() && dialog(w).find('[data-test="batch-item"]').exists()).toBe(false)
      expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
      expect(api.day).not.toHaveBeenCalled()
    })

    it('使用者身分尚未載入時不接手上一批', async () => {
      localStorage.removeItem('user')
      sessionStorage.setItem(STORAGE_KEY, savedBatch(ME, [item('2026-10-04', 'inflight')]))
      const w = mountWorkspace()
      await flushPromises()
      expect(dialog(w).exists() && dialog(w).find('[data-test="batch-item"]').exists()).toBe(false)
      // 不接手也不刪：等身分載入後再判斷
      expect(sessionStorage.getItem(STORAGE_KEY)).not.toBeNull()
      expect(api.day).not.toHaveBeenCalled()
    })
  })

  // 確認與結果兩步的版面：清單高度、欄位標題與結果區的配置
  describe('確認與結果的版面', () => {
    it('清單高度依視窗收放：清單以外的部分要整個留在視窗內，夾在上下限之間', () => {
      // 1440×900：清單以外 500，可給清單 900-48-500=352，封頂 320
      expect(fitListHeight({ viewport: 900, dialogHeight: 820, listHeight: 320 })).toBe(CONFIRM_LIST_MAX_HEIGHT)
      // 1024×768：清單以外 560，清單收到 768-48-560=160
      expect(fitListHeight({ viewport: 768, dialogHeight: 880, listHeight: 320 })).toBe(160)
      // 清單收放不影響結果（量的是清單以外的高度）
      expect(fitListHeight({ viewport: 768, dialogHeight: 720, listHeight: 160 })).toBe(160)
      // 視窗矮到放不下下限時才停在下限
      expect(fitListHeight({ viewport: 500, dialogHeight: 900, listHeight: 320 })).toBe(CONFIRM_LIST_MIN_HEIGHT)
    })

    it('開啟確認後依視窗高度把逐日清單的 max-height 收到放得下其餘欄位與按鈕', async () => {
      pendingDays = series(50)
      const proto = HTMLElement.prototype
      const original = Object.getOwnPropertyDescriptor(proto, 'offsetHeight')
      const originalInner = window.innerHeight
      // jsdom 不排版：以替身高度模擬 1024×768，對話框 880 高、其中清單 320
      Object.defineProperty(proto, 'offsetHeight', {
        configurable: true,
        get() {
          if (this.classList?.contains('el-dialog')) return 880
          if (this.classList?.contains('el-table')) return 320
          return 0
        },
      })
      Object.defineProperty(window, 'innerHeight', { configurable: true, value: 768 })
      try {
        const w = mountWorkspace()
        await flushPromises()
        await w.find('[data-test="dr-select-all"] input').setValue(true)
        await goPage(w, 2)
        await w.find('[data-test="dr-select-all"] input').setValue(true)
        await flushPromises()
        await openConfirm(w)
        await flushPromises()
        const table = dialog(w).findComponent({ name: 'ElTable' })
        expect(table.props('maxHeight')).toBe(160)
        // 對話框上緣留白與計算一致
        expect(dialog(w).classes()).toContain('mds-dialog')
      } finally {
        if (original) Object.defineProperty(proto, 'offsetHeight', original)
        else delete proto.offsetHeight
        Object.defineProperty(window, 'innerHeight', { configurable: true, value: originalInner })
      }
    })

    it('確認表：準時是綠色標籤、補簽提醒條有警示圖示、延遲原因有必填星號', async () => {
      pendingDays = [day('2026-10-09', { lateDays: 1 }), day('2026-10-10', { overdue: false })]
      const w = mountWorkspace()
      await flushPromises()
      await select(w, pendingDays.map((d) => d.date))
      await openConfirm(w)
      const d = dialog(w)
      const types = d.findAll('[data-test="dr-multi-type"]')
      expect(types[1].text()).toBe('準時')
      const tagClass = (n) => (n.element.closest('.el-tag') || n.element.querySelector('.el-tag'))?.className || ''
      expect(tagClass(types[1])).toContain('el-tag--success')
      expect(tagClass(types[0])).toContain('el-tag--warning')
      expect(d.find('[data-test="dr-multi-late-notice"] [data-test="dr-multi-late-icon"]').exists()).toBe(true)
      const label = d.find('[data-test="dr-multi-delay-label"]')
      expect(label.find('[data-test="dr-multi-delay-required"]').text()).toBe('*')
      expect(label.find('.mds-label__aside').text()).toBe('（必填，套用到 1 天補簽）')
    })

    it('50 天結果：「沒簽成的日子」在摘要正下方、逐日清單上方', async () => {
      pendingDays = series(50)
      const w = mountWorkspace()
      await flushPromises()
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await goPage(w, 2)
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await flushPromises()
      await openConfirm(w)
      const rejectDate = pendingDays[10].date
      api.sign.mockImplementation(async (body) => {
        if (body.review_date === rejectDate) throw httpError(409, 'CONFLICT_DAILY_REVIEW_SIGNED', { signer: 'auditor-b' })
        return { data: { review_date: body.review_date, late: true } }
      })
      await fillAndSubmit(w)
      const summary = dialog(w).find('[data-test="dr-multi-summary"]')
      const notDone = dialog(w).find('[data-test="dr-multi-not-done"]')
      expect(summary.text()).toBe('成功 49 天 · 被拒 1 天 · 未送出 0 天 · 待確認 0 天')
      expect(notDone.text()).toContain(rejectDate)
      expect(summary.element.nextElementSibling).toBe(notDone.element)
      const firstItem = dialog(w).find('[data-test="batch-item"]').element
      // DOCUMENT_POSITION_FOLLOWING：清單在「沒簽成的日子」之後
      expect(notDone.element.compareDocumentPosition(firstItem) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    })

    // 「沒簽成的日子」的括號與分隔符依介面語言：英文用半形括號與逗號，繁中與日文用全形括號與頓號
    it.each([
      ['en-US', (a, b) => `${a} (rejected), ${b} (rejected)`],
      ['ja-JP', (a, b) => `${a}（拒否）、${b}（拒否）`],
      ['zh-TW', (a, b) => `${a}（被拒）、${b}（被拒）`],
    ])('沒簽成的日子在 %s 使用該語言的標點', async (lang, expected) => {
      setLanguage(lang)
      pendingDays = series(10)
      const w = mountWorkspace()
      await flushPromises()
      await w.find('[data-test="dr-select-all"] input').setValue(true)
      await flushPromises()
      await openConfirm(w)
      const rejected = [pendingDays[2].date, pendingDays[5].date]
      api.sign.mockImplementation(async (body) => {
        if (rejected.includes(body.review_date)) throw httpError(409, 'CONFLICT_DAILY_REVIEW_SIGNED', { signer: 'auditor-b' })
        return { data: { review_date: body.review_date, late: true } }
      })
      await fillAndSubmit(w)
      const text = dialog(w).find('[data-test="dr-multi-not-done"]').text()
      expect(text).toContain(expected(rejected[0], rejected[1]))
      if (lang === 'en-US') expect(text).not.toMatch(/[（）、]/)
    })
  })

  // 情境「單日簽核不受影響」的前端面：單日抽屜的請求不帶批次關聯碼
  it('單日抽屜簽核的請求不帶批次關聯碼', async () => {
    api.day.mockResolvedValue({ data: { ...day('2026-10-10', { overdue: false }), status: 'pending', unreviewed_alerts: [], login_failures: { total: 0, items: [] }, high_risk_ops: { total: 0, items: [] }, sources: {} } })
    api.sign.mockResolvedValue({ data: { review_date: '2026-10-10', late: false } })
    pendingDays = []
    const w = mount(DailyReviewDrawer, { props: { modelValue: true, canSign: true }, global: { plugins: [ElementPlus], stubs: { RouterLink: true, 'router-link': true } }, attachTo: document.body })
    await w.vm.openDay('2026-10-10')
    await flushPromises()
    // 這一天已過準時期限（相對於現在）：填延遲原因後送出
    const texts = document.body.querySelectorAll('[data-test="dr-text"]')
    await new DOMWrapper(texts[texts.length - 1]).setValue('補簽')
    const buttons = document.body.querySelectorAll('[data-test="dr-sign"]')
    buttons[buttons.length - 1].click()
    await flushPromises()
    expect(api.sign).toHaveBeenCalledTimes(1)
    expect('batch_id' in api.sign.mock.calls[0][0]).toBe(false)
  })
})

describe('跨日處置', () => {
  // 每天的未審閱告警：系統告警兩類，各天筆數不同；本人觸發的每 3 筆一筆
  let alertsByDay = {}
  let nextId = 1
  const makeAlerts = (date, plan) => {
    const rows = []
    for (const [type, n] of plan) {
      for (let i = 0; i < n; i += 1) {
        const id = nextId++
        rows.push({
          id, kind: 'system_security', rule_name: type, reason_code: type, severity: 'high',
          user_id: id % 3 === 0 ? ME : 99, username: id % 3 === 0 ? 'auditor1' : 'chen.wei',
          target_kind: 'user', target_id: '4', params: { recipient: 'ops' },
          triggered_at: new Date(Date.parse(`${date}T09:00:00+08:00`) + i * 60000).toISOString(),
        })
      }
    }
    return rows
  }
  // 待簽清單：有過告警的日子處置完仍在清單上（只是告警數歸零），直到簽核
  let alertDates = []
  const refreshPending = (cleanDates = []) => {
    alertDates = [...new Set([...alertDates, ...Object.keys(alertsByDay)])]
    const withAlerts = alertDates.map((date) => day(date, { counts: okCounts({ unreviewed_alerts: (alertsByDay[date] || []).length }) }))
    pendingDays = [...withAlerts, ...cleanDates.map((d) => day(d))].sort((a, b) => (a.date < b.date ? -1 : 1))
  }
  const alertDialog = () => new DOMWrapper(document.body).find('[data-test="alerts-batch-dialog"]')

  beforeEach(() => {
    Object.values(api).forEach((m) => m.mockReset())
    Object.values(alertApi).forEach((m) => m.mockReset())
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'auditor1' }))
    api.status.mockResolvedValue({ data: { enabled: true, timezone_state: { active: TZ, today: { date: '2026-11-23' } }, overdue_count: 0 } })
    api.list.mockResolvedValue({ data: { items: [], total: 0 } })
    api.stats.mockResolvedValue({ data: null })
    api.sign.mockImplementation(async (body) => ({ data: { review_date: body.review_date, late: Boolean(body.delay_reason) } }))
    pendingDays = []
    servePending()
    alertsByDay = {}
    alertDates = []
    nextId = 1
    document.body.innerHTML = ''
    api.day.mockImplementation(async (date) => ({
      data: { date, status: 'pending', timezone: TZ, counts: okCounts({ unreviewed_alerts: (alertsByDay[date] || []).length }), unreviewed_alerts: alertsByDay[date] || [] },
    }))
    // 伺服端：處置過的告警離開未審閱
    alertApi.batch.mockImplementation(async (data) => {
      const done = new Set(data.alert_ids)
      for (const date of Object.keys(alertsByDay)) {
        alertsByDay[date] = alertsByDay[date].filter((row) => !done.has(row.id))
        if (!alertsByDay[date].length) delete alertsByDay[date]
      }
      refreshPending(cleanDays)
      return { batch_id: data.batch_id, limit: 500, items: data.alert_ids.map((id) => ({ id, result: 'reviewed', self_triggered: false })) }
    })
  })
  let cleanDays = []

  async function selectAllAndOpen(w) {
    await w.find('[data-test="dr-select-all"] input').setValue(true)
    await flushPromises()
  }
  async function fillAndSend() {
    const ack = alertDialog().find('[data-test="bulk-self-ack"] input')
    if (ack.exists()) await ack.setValue(true)
    await alertDialog().find('[data-test="batch-note"] textarea').setValue('11/13 至 11/21 依變更單處置')
    await alertDialog().find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
  }

  it('勾 7 天（6 天有告警）：批次列只有「處置這幾天的告警」；開啟時逐日讀 6 天、依類型合併並列各天筆數；一個請求送完後接著簽核 7 天', async () => {
    const plan = { '2026-11-13': 4, '2026-11-14': 6, '2026-11-15': 2, '2026-11-18': 5, '2026-11-20': 3, '2026-11-21': 1 }
    for (const [date, n] of Object.entries(plan)) alertsByDay[date] = makeAlerts(date, [['management_role_granted', n], ['notification_channel_changed', 1]])
    cleanDays = ['2026-11-22']
    refreshPending(cleanDays)
    const w = mountWorkspace()
    await flushPromises()
    await selectAllAndOpen(w)
    const bar = w.find('[data-test="dr-batch-bar"]')
    expect(bar.text()).toContain('已選 7 天')
    expect(bar.text()).toContain('其中 6 天有 27 筆告警，要先處置才能簽核')
    expect(w.find('[data-test="dr-multi-open"]').exists()).toBe(false)
    expect(w.find('[data-test="dr-cross-open"]').text()).toBe('處置這幾天的告警（27 筆）')

    await w.find('[data-test="dr-cross-open"]').trigger('click')
    await flushPromises()
    expect(api.day.mock.calls.map(([d]) => d)).toEqual(Object.keys(plan))
    expect(alertDialog().find('.el-dialog__title').text()).toBe('處置 27 筆告警（6 天）')
    const types = alertDialog().findAll('[data-test="bulk-type-row"]')
    expect(types).toHaveLength(2)
    expect(types[0].text()).toContain('發放管理類角色給他人')
    expect(types[0].find('[data-test="bulk-type-days"]').text()).toBe('11-13 4 · 11-14 6 · 11-15 2 · 11-18 5 · 11-20 3 · 11-21 1')
    expect(types[1].find('[data-test="bulk-type-days"]').text()).toBe('11-13 1 · 11-14 1 · 11-15 1 · 11-18 1 · 11-20 1 · 11-21 1')

    await fillAndSend()
    expect(alertApi.batch).toHaveBeenCalledTimes(1)
    expect(alertApi.batch.mock.calls[0][0].alert_ids).toHaveLength(27)
    expect(alertDialog().find('[data-test="bulk-result-note"]').text()).toContain('6 天的告警都處置完了。接著簽核這 7 天')
    await alertDialog().find('[data-test="bulk-next"]').trigger('click')
    await flushPromises()
    expect(dialog(w).findAll('[data-test="dr-multi-date"]').map((n) => n.text().slice(0, 10)))
      .toEqual(['2026-11-13', '2026-11-14', '2026-11-15', '2026-11-18', '2026-11-20', '2026-11-21', '2026-11-22'])
  })

  it('612 筆：第一次送所屬日由早到晚的前 500 筆；剩下 112 筆所在的日子不進入簽核確認，結果框說明', async () => {
    alertsByDay['2026-11-09'] = makeAlerts('2026-11-09', [['notification_channel_changed', 300]])
    alertsByDay['2026-11-10'] = makeAlerts('2026-11-10', [['custom_secret_used', 200]])
    alertsByDay['2026-11-11'] = makeAlerts('2026-11-11', [['management_role_granted', 112]])
    cleanDays = ['2026-11-12']
    refreshPending(cleanDays)
    const order = [...alertsByDay['2026-11-09'], ...alertsByDay['2026-11-10'], ...alertsByDay['2026-11-11']].map((r) => r.id)
    const w = mountWorkspace()
    await flushPromises()
    await selectAllAndOpen(w)
    await w.find('[data-test="dr-cross-open"]').trigger('click')
    await flushPromises()
    expect(alertDialog().find('[data-test="bulk-over-limit"]').text()).toContain('剩下的 112 筆')
    await fillAndSend()
    expect(alertApi.batch.mock.calls[0][0].alert_ids).toEqual(order.slice(0, 500))
    expect(alertDialog().find('[data-test="bulk-remaining-hint"]').text()).toContain('還有 112 筆')
    expect(alertDialog().find('[data-test="bulk-result-note"]').text()).toContain('另有 1 天仍有告警，不會進入簽核。')
    await alertDialog().find('[data-test="bulk-next"]').trigger('click')
    await flushPromises()
    expect(dialog(w).findAll('[data-test="dr-multi-date"]').map((n) => n.text().slice(0, 10)))
      .toEqual(['2026-11-09', '2026-11-10', '2026-11-12'])
    expect(dialog(w).text()).not.toContain('2026-11-11')
  })

  it('只勾沒有告警的日子：批次列照現況是「簽核所選」', async () => {
    alertsByDay['2026-11-13'] = makeAlerts('2026-11-13', [['management_role_granted', 2]])
    cleanDays = ['2026-11-22']
    refreshPending(cleanDays)
    const w = mountWorkspace()
    await flushPromises()
    await select(w, ['2026-11-22'])
    expect(w.find('[data-test="dr-multi-open"]').text()).toBe('簽核所選（1 天）')
    expect(w.find('[data-test="dr-cross-open"]').exists()).toBe(false)
  })
})
