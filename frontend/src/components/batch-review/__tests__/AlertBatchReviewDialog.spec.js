import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, DOMWrapper } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { defineComponent, h, ref } from 'vue'
import AlertBatchReviewDialog from '../AlertBatchReviewDialog.vue'

// 告警的處置對話框（告警頁、每日簽核單日與跨日共用）：一次請求送出；替身端點，不打任何真實服務
enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

const batchReviewMock = vi.fn()
const searchAlertsMock = vi.fn()
vi.mock('@/api/alerts', () => ({
  batchReviewAlerts: (...a) => batchReviewMock(...a),
  searchAlerts: (...a) => searchAlertsMock(...a),
}))

const ME = 7
const row = (id, extra = {}) => ({
  id,
  kind: 'system_security',
  rule_name: 'management_role_granted',
  reason_code: 'management_role_granted',
  severity: 'high',
  user_id: 99,
  username: 'chen.wei',
  triggered_at: `2026-11-13T12:${String(id % 60).padStart(2, '0')}:00Z`,
  ...extra,
})
const selfRow = (id, extra = {}) => row(id, { user_id: ME, username: 'admin', ...extra })

// 最小的呼叫端：兩顆按鈕各開一天（換一天時理由不沿用）
const Host = defineComponent({
  props: { dayA: { type: Array, default: () => [] }, dayB: { type: Array, default: () => [] } },
  setup(props) {
    const dialog = ref(null)
    return () => h('div', [
      h('button', { 'data-test': 'open-a', onClick: () => dialog.value.open(props.dayA, { days: ['2026-11-13'], dayOf: () => '2026-11-13' }) }),
      h('button', { 'data-test': 'open-b', onClick: () => dialog.value.open(props.dayB, { days: ['2026-11-14'] }) }),
      h(AlertBatchReviewDialog, { ref: dialog, currentUserId: ME, surface: 'dialog-spec', labelFor: (r) => `#${r.id} ${r.username}` }),
    ])
  },
})

const body = () => new DOMWrapper(document.body)
const dlg = () => body().find('[data-test="alerts-batch-dialog"]')

async function mountHost(dayA, dayB = []) {
  const w = mount(Host, { props: { dayA, dayB }, global: { plugins: [ElementPlus] }, attachTo: document.body })
  return w
}
async function open(w, which = 'a') {
  await w.find(`[data-test="open-${which}"]`).trigger('click')
  await flushPromises()
}
async function fill(note) {
  await dlg().find('[data-test="batch-note"] textarea').setValue(note)
}
async function ack() {
  await dlg().find('[data-test="bulk-self-ack"] input').setValue(true)
}
async function submit() {
  await dlg().find('[data-test="batch-submit"]').trigger('click')
  await flushPromises()
}
const reviewedAll = (data) => ({
  batch_id: data.batch_id,
  limit: 500,
  summary: { reviewed: data.alert_ids.length },
  items: data.alert_ids.map((id) => ({ id, result: 'reviewed', self_triggered: false })),
})

beforeEach(() => {
  batchReviewMock.mockReset()
  searchAlertsMock.mockReset()
  sessionStorage.clear()
  document.body.innerHTML = ''
})

const mixed = () => [selfRow(1), selfRow(2), row(3), selfRow(4), row(5), selfRow(6, { rule_name: 'notification_channel_changed', reason_code: 'notification_channel_changed', severity: 'medium' })]

describe('AlertBatchReviewDialog 填寫', () => {
  it('含 4 筆本人觸發、沒勾確認就送出：不發請求，確認處標紅', async () => {
    const w = await mountHost(mixed())
    await open(w)
    await fill('依 CHG-1182 調整')
    await submit()
    expect(batchReviewMock).not.toHaveBeenCalled()
    expect(dlg().find('[data-test="bulk-self"]').classes()).toContain('bulk-box--error')
    expect(dlg().find('[data-test="bulk-self-error"]').text()).toContain('4')
    expect(dlg().find('[data-test="bulk-note-error"]').exists()).toBe(false)
    // 單日處置不列各天筆數（只有跨日才列）
    expect(dlg().find('[data-test="bulk-type-days"]').exists()).toBe(false)
  })

  it('沒填理由：不發請求，理由處標紅', async () => {
    const w = await mountHost(mixed())
    await open(w)
    await ack()
    await submit()
    expect(batchReviewMock).not.toHaveBeenCalled()
    expect(dlg().find('[data-test="bulk-note-error"]').exists()).toBe(true)
    expect(dlg().find('[data-test="batch-note"]').classes()).toContain('batch-note--error')
    expect(dlg().find('[data-test="bulk-self-error"]').exists()).toBe(false)
  })

  it('確認與理由都缺：兩處同時標紅', async () => {
    const w = await mountHost(mixed())
    await open(w)
    await submit()
    expect(batchReviewMock).not.toHaveBeenCalled()
    expect(dlg().find('[data-test="bulk-self-error"]').exists()).toBe(true)
    expect(dlg().find('[data-test="bulk-note-error"]').exists()).toBe(true)
  })

  it('勾了確認且填了理由：一個請求，self_triggered_ack 為 4，類型表與本人段依類型列出', async () => {
    batchReviewMock.mockImplementation(async (data) => reviewedAll(data))
    const w = await mountHost(mixed())
    await open(w)
    const types = dlg().findAll('[data-test="bulk-type-row"]').map((r) => r.text())
    expect(types[0]).toContain('發放管理類角色給他人')
    expect(types[0]).toMatch(/5\s*3/)
    expect(dlg().find('[data-test="bulk-self"]').text()).toContain('其中 4 筆是你自己觸發的')
    expect(dlg().find('[data-test="bulk-audit-mark"]').exists()).toBe(true)
    await ack()
    await fill('依 CHG-1182 調整')
    await submit()
    expect(batchReviewMock).toHaveBeenCalledTimes(1)
    const [data] = batchReviewMock.mock.calls[0]
    expect(data).toMatchObject({ alert_ids: [1, 2, 3, 4, 5, 6], disposition: 'benign', note: '依 CHG-1182 調整', self_triggered_ack: 4 })
  })

  it('沒有本人觸發：不出現確認段，self_triggered_ack 為 0', async () => {
    batchReviewMock.mockImplementation(async (data) => reviewedAll(data))
    const w = await mountHost([row(3), row(5)])
    await open(w)
    expect(dlg().find('[data-test="bulk-self"]').exists()).toBe(false)
    expect(dlg().find('[data-test="bulk-audit-mark"]').exists()).toBe(false)
    await dlg().find('[data-test="batch-disposition-escalated"] input').setValue(true)
    await fill('已通報')
    await submit()
    expect(batchReviewMock.mock.calls[0][0]).toMatchObject({ self_triggered_ack: 0, disposition: 'escalated' })
  })

  it('處理中：按鈕停用、沒有關閉鈕、按 Esc 關不掉，說明以伺服器結果為準', async () => {
    let release
    batchReviewMock.mockImplementation((data) => new Promise((resolve) => { release = () => resolve(reviewedAll(data)) }))
    const w = await mountHost([row(3), row(5)])
    await open(w)
    await fill('已通報')
    await submit()
    expect(dlg().find('[data-test="bulk-running"]').text()).toContain('2')
    expect(dlg().find('[data-test="bulk-running-button"]').attributes('disabled')).toBeDefined()
    expect(dlg().find('[data-test="batch-submit"]').exists()).toBe(false)
    expect(dlg().find('.el-dialog__headerbtn').exists()).toBe(false)
    expect(dlg().text()).toContain('重新打開時，清單以伺服器實際處理的結果為準')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }))
    await flushPromises()
    expect(dlg().isVisible()).toBe(true)
    expect(dlg().find('[data-test="bulk-running"]').exists()).toBe(true)
    release()
    await flushPromises()
    expect(dlg().find('[data-test="batch-summary"]').text()).toBe('成功 2 筆 · 沒有生效 0 筆')
  })

  it('對話框沒有證據包與「連線觸發」的說法', async () => {
    const w = await mountHost(mixed())
    await open(w)
    await submit()
    const text = dlg().text()
    expect(text).not.toContain('證據包')
    expect(text).not.toContain('連線觸發')
  })
})

describe('AlertBatchReviewDialog 結果與錯誤', () => {
  it('先前由你處置為需升級處理、這次送無害：列在沒有生效並寫出先前的處置與這次沒有變更；他人處置的不寫名稱', async () => {
    batchReviewMock.mockImplementation(async (data) => ({
      batch_id: data.batch_id,
      limit: 500,
      summary: { reviewed: 1, already_reviewed: 2, not_found: 1 },
      items: [
        { id: 3, result: 'reviewed', self_triggered: false },
        { id: 5, result: 'already_reviewed', self_triggered: false, reviewed_by_you: true, existing_disposition: 'escalated' },
        { id: 8, result: 'already_reviewed', self_triggered: false, reviewed_by_you: false, existing_disposition: 'benign' },
        { id: 9, result: 'not_found', self_triggered: false },
      ],
    }))
    const w = await mountHost([row(3), row(5), row(8), row(9)])
    await open(w)
    await fill('已核對')
    await submit()
    expect(dlg().find('[data-test="batch-summary"]').text()).toBe('成功 1 筆 · 沒有生效 3 筆')
    const success = dlg().findAll('[data-test="bulk-success-row"]')
    expect(success).toHaveLength(1)
    expect(success[0].text()).toContain('發放管理類角色給他人 1 筆')
    const item = (id) => dlg().find(`[data-test="batch-item"][data-id="${id}"]`)
    expect(item(5).attributes('data-state')).toBe('notApplied')
    expect(item(5).text()).toContain('先前已由你處置為「需升級處理」，這次沒有變更')
    expect(item(8).text()).toContain('送出前已有人處置為「無害」')
    expect(item(9).text()).toContain('告警已不存在')
    const text = dlg().text()
    expect(text).not.toContain('被拒')
    expect(text).not.toContain('已由你處置為「無害」')
    // 他人處置的那筆只寫分類，不出現任何處置者名稱（回應本來就不帶）
    expect(item(8).text()).not.toMatch(/由 \S+ 處置/)
  })

  it('409 本人觸發筆數不符：以伺服器的筆數重列確認段、取消勾選，不自動重送', async () => {
    batchReviewMock.mockRejectedValue({ response: { status: 409, data: { code: 'CONFLICT_ALERT_BATCH_SELF_ACK', self_triggered: 5 } } })
    const w = await mountHost(mixed())
    await open(w)
    await ack()
    await fill('依 CHG-1182 調整')
    await submit()
    expect(batchReviewMock).toHaveBeenCalledTimes(1)
    const self = dlg().find('[data-test="bulk-self"]')
    expect(self.text()).toContain('其中 5 筆是你自己觸發的')
    expect(dlg().find('[data-test="bulk-self-mismatch"]').exists()).toBe(true)
    expect(self.find('input').element.checked).toBe(false)
    expect(dlg().find('[data-test="batch-note"] textarea').element.value).toBe('依 CHG-1182 調整')
    await ack()
    batchReviewMock.mockImplementation(async (data) => reviewedAll(data))
    await submit()
    expect(batchReviewMock).toHaveBeenCalledTimes(2)
    expect(batchReviewMock.mock.calls[1][0].self_triggered_ack).toBe(5)
  })

  it('500 帶 INTERNAL_ALERT_REVIEW：說明這一次沒有生效、可再送，送出鈕可用、內容保留', async () => {
    batchReviewMock.mockRejectedValue({ response: { status: 500, data: { code: 'INTERNAL_ALERT_REVIEW' } } })
    const w = await mountHost([row(3)])
    await open(w)
    await fill('已核對')
    await submit()
    expect(dlg().find('[data-test="bulk-failed"]').text()).toBe('這一次沒有生效，可以再送一次。')
    expect(dlg().find('[data-test="batch-submit"]').attributes('disabled')).toBeUndefined()
    expect(dlg().find('[data-test="batch-note"] textarea').element.value).toBe('已核對')
  })

  it('沒有回應：待確認並提供重新查詢，不說沒有生效', async () => {
    batchReviewMock.mockRejectedValue({ code: 'ECONNABORTED', request: {} })
    const w = await mountHost([row(3), row(5)])
    await open(w)
    await fill('已核對')
    await submit()
    expect(dlg().find('[data-test="batch-summary"]').text()).toBe('成功 0 筆 · 沒有生效 0 筆 · 待確認 2 筆')
    expect(dlg().find('[data-test="batch-recheck"]').exists()).toBe(true)
    expect(dlg().find('[data-test="bulk-unconfirmed-hint"]').exists()).toBe(true)
  })

  it('612 筆：第一次送清單順序的前 500 筆；結果後按「處置剩下的」第二次送 112 筆、理由帶入、確認未預勾；換一天理由為空', async () => {
    batchReviewMock.mockImplementation(async (data) => reviewedAll(data))
    const many = Array.from({ length: 612 }, (_, i) => (i % 3 === 0 ? selfRow(i + 1) : row(i + 1)))
    const w = await mountHost(many, [row(9001)])
    await open(w)
    expect(dlg().find('[data-test="bulk-over-limit"]').text()).toContain('剩下的 112 筆')
    expect(dlg().find('[data-test="batch-submit"]').text()).toBe('送出 500 筆')
    await ack()
    await fill('11/9 批次匯入')
    await submit()
    const first = batchReviewMock.mock.calls[0][0]
    expect(first.alert_ids).toEqual(many.slice(0, 500).map((r) => r.id))
    expect(first.self_triggered_ack).toBe(many.slice(0, 500).filter((r) => r.user_id === ME).length)
    expect(dlg().find('[data-test="bulk-remaining-hint"]').text()).toContain('還有 112 筆')
    await dlg().find('[data-test="bulk-continue"]').trigger('click')
    await flushPromises()
    expect(dlg().find('[data-test="batch-note"] textarea').element.value).toBe('11/9 批次匯入')
    expect(dlg().find('[data-test="bulk-self-ack"] input').element.checked).toBe(false)
    await ack()
    await submit()
    const second = batchReviewMock.mock.calls[1][0]
    expect(second.alert_ids).toEqual(many.slice(500).map((r) => r.id))
    expect(second.note).toBe('11/9 批次匯入')
    await dlg().find('[data-test="batch-done"]').trigger('click')
    await flushPromises()
    await open(w, 'b')
    expect(dlg().find('[data-test="batch-note"] textarea').element.value).toBe('')
  })
})
