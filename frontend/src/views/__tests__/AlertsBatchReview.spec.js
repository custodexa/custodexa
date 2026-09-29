import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Alerts from '../Alerts.vue'

// 告警「批次審閱」：勾選 → 共用理由 → 前端逐筆呼叫既有單筆端點（非原子）
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

const searchAlertsMock = vi.fn()
const reviewAlertMock = vi.fn()

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
  reviewAlert: (...args) => reviewAlertMock(...args),
  getAlertRules: vi.fn().mockResolvedValue({ data: [] }),
  createAlertRule: vi.fn(),
  updateAlertRule: vi.fn(),
  deleteAlertRule: vi.fn(),
  getChannels: vi.fn().mockResolvedValue({ data: [] }),
  createChannel: vi.fn(),
  updateChannel: vi.fn(),
  deleteChannel: vi.fn(),
  testChannel: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

const ME = 7
const STORAGE_KEY = 'ot-batch-review:alerts'
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const alertRow = (id, extra = {}) => ({
  id,
  rule_id: 1,
  rule_name: `規則${id}`,
  kind: 'rule',
  session_id: 100 + id,
  user_id: 8,
  command: `cmd-${id}`,
  severity: 'medium',
  triggered_at: '2026-09-24T10:14:00Z',
  reviewed_at: null,
  disposition: '',
  note: '',
  ...extra,
})

const sampleAlerts = [
  alertRow(1, { user_id: ME }), // 本人觸發
  alertRow(2),
  alertRow(3, { user_id: 9 }),
  alertRow(4, { reviewed_at: '2026-09-23T01:00:00Z', reviewed_by: 11, disposition: 'benign' }),
]

const listResponse = (rows) => ({ data: rows, total: rows.length })

const mountAlerts = () =>
  mount(Alerts, { global: { plugins: [ElementPlus] } })

const cell = (wrapper, id) => wrapper.find(`[data-test="batch-select-cell"][data-id="${id}"] input`)
const dialog = (wrapper) => wrapper.find('[data-test="alerts-batch-dialog"]')

const selectAndOpen = async (wrapper, ids) => {
  for (const id of ids) {
    await cell(wrapper, id).setValue(true)
  }
  await flushPromises()
  await wrapper.find('[data-test="batch-open"]').trigger('click')
  await flushPromises()
}

const fillAndSubmit = async (wrapper, { note = '更換筆電後首次連線', escalate = false } = {}) => {
  if (escalate) {
    await dialog(wrapper).find('[data-test="batch-disposition-escalated"] input').setValue(true)
  }
  await dialog(wrapper).find('[data-test="batch-note"] textarea').setValue(note)
  await dialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
  await flushPromises()
}

const httpError = (status, code) => ({ response: { status, data: { code, error: code } } })

describe('Alerts 批次審閱', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // mockImplementationOnce 佇列不隨 clearAllMocks 清掉：逐一 reset，避免前一測殘留
    searchAlertsMock.mockReset()
    reviewAlertMock.mockReset()
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'auditor1', roles: ['auditor'] }))
    searchAlertsMock.mockResolvedValue(listResponse(sampleAlerts))
    reviewAlertMock.mockResolvedValue({})
  })

  it('只能勾未審閱且非本人觸發的告警；全選只取可勾者', async () => {
    const wrapper = mountAlerts()
    await flushPromises()

    expect(cell(wrapper, 1).attributes('disabled')).toBeDefined() // 本人觸發
    expect(cell(wrapper, 4).attributes('disabled')).toBeDefined() // 已審閱
    expect(cell(wrapper, 2).attributes('disabled')).toBeUndefined()
    expect(cell(wrapper, 3).attributes('disabled')).toBeUndefined()
    // 不可勾的原因要讀得到（勾選框的可讀名稱，同時是滑鼠提示）
    expect(wrapper.find('[data-test="batch-select-cell"][data-id="1"]').text())
      .toContain('自己連線觸發的告警請逐筆審閱')

    await wrapper.find('[data-test="batch-select-all"] input').setValue(true)
    await flushPromises()
    const bar = wrapper.find('[data-test="batch-bar"]')
    expect(bar.exists()).toBe(true)
    expect(bar.text()).toContain('已選 2 筆未審閱告警')
  })

  it('不具審閱權限時不顯示勾選欄', async () => {
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'u', roles: ['user'] }))
    const wrapper = mountAlerts()
    await flushPromises()
    expect(wrapper.find('[data-test="batch-select-cell"]').exists()).toBe(false)
  })

  it('理由必填：未填不可送出', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    await selectAndOpen(wrapper, [2])
    const submit = dialog(wrapper).find('[data-test="batch-submit"]')
    expect(submit.attributes('disabled')).toBeDefined()
    expect(dialog(wrapper).text()).toContain('送出後逐筆處理，可能部分完成')
  })

  it('批次送出逐筆循序呼叫單筆端點，每筆帶同一個 batch_id', async () => {
    let releaseFirst
    reviewAlertMock
      .mockImplementationOnce(() => new Promise((resolve) => { releaseFirst = resolve }))
      .mockResolvedValue({})
    const wrapper = mountAlerts()
    await flushPromises()
    await selectAndOpen(wrapper, [2, 3])
    expect(dialog(wrapper).text()).toContain('逐筆送出 2 筆')

    await fillAndSubmit(wrapper, { escalate: true })
    // 第一筆未回應前不送第二筆（循序）
    expect(reviewAlertMock).toHaveBeenCalledTimes(1)
    expect(dialog(wrapper).text()).toContain('第 1／2 筆')
    releaseFirst({})
    await flushPromises()

    expect(reviewAlertMock).toHaveBeenCalledTimes(2)
    const [firstId, firstBody, firstOpts] = reviewAlertMock.mock.calls[0]
    const [secondId, secondBody] = reviewAlertMock.mock.calls[1]
    expect([firstId, secondId]).toEqual([2, 3])
    expect(firstBody).toEqual({ disposition: 'escalated', note: '更換筆電後首次連線', batch_id: firstBody.batch_id })
    expect(firstBody.batch_id).toMatch(UUID_V4)
    expect(secondBody.batch_id).toBe(firstBody.batch_id)
    // 批次呼叫自行呈現錯誤：不走全域 toast
    expect(firstOpts).toEqual({ skipErrorToast: true })

    const summary = dialog(wrapper).find('[data-test="batch-summary"]')
    expect(summary.attributes('aria-live')).toBe('polite')
    expect(summary.text()).toContain('成功 2 筆')
  })

  it('部分失敗（409／403）不影響其他筆，逐筆呈現原因', async () => {
    searchAlertsMock.mockResolvedValue(listResponse([...sampleAlerts, alertRow(5)]))
    reviewAlertMock
      .mockRejectedValueOnce(httpError(409, 'CONFLICT_ALERT_ALREADY_REVIEWED'))
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(httpError(403, 'RULE_ALERT_BATCH_SELF_TRIGGERED'))
    const wrapper = mountAlerts()
    await flushPromises()
    await selectAndOpen(wrapper, [2, 3, 5])
    await fillAndSubmit(wrapper)

    expect(reviewAlertMock).toHaveBeenCalledTimes(3)
    const text = dialog(wrapper).text()
    expect(dialog(wrapper).find('[data-test="batch-summary"]').text())
      .toContain('成功 1 筆 · 被拒 2 筆 · 未送出 0 筆 · 待確認 0 筆')
    const item = (id) => dialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    expect(item(2)).toContain('被拒：送出時已有審閱結果')
    expect(item(3)).toContain('已標記')
    expect(item(5)).toContain('自己連線觸發的告警不納入批次')
    // 409 不得寫成「他人」審閱，也不得用原子語氣
    expect(text).not.toContain('他人')
    expect(text).not.toContain('全部完成')
    expect(text).not.toContain('一次處置')
  })

  it('無回應記為待確認；重新掛載時查回實際狀態，不自動續送', async () => {
    reviewAlertMock
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce({ request: {}, message: 'Network Error' })
    const first = mountAlerts()
    await flushPromises()
    await selectAndOpen(first, [2, 3])
    await fillAndSubmit(first, { note: '同一理由' })
    expect(dialog(first).find('[data-test="batch-summary"]').text()).toContain('待確認 1 筆')

    const saved = JSON.parse(sessionStorage.getItem(STORAGE_KEY))
    expect(saved.items.map((i) => i.state)).toEqual(['success', 'unconfirmed'])
    const batchId = saved.batchId

    // 模擬重新整理：卸載、重新掛載
    first.unmount()
    reviewAlertMock.mockClear()
    searchAlertsMock.mockImplementation((params) => {
      if (params?.ids) {
        return Promise.resolve(listResponse([
          alertRow(3, { user_id: 9, reviewed_at: '2026-09-29T01:00:00Z', reviewed_by: ME, disposition: 'benign', note: '同一理由' }),
        ]))
      }
      return Promise.resolve(listResponse(sampleAlerts))
    })
    const second = mountAlerts()
    await flushPromises()

    expect(searchAlertsMock).toHaveBeenCalledWith(expect.objectContaining({ ids: '3' }), { skipErrorToast: true })
    expect(reviewAlertMock).not.toHaveBeenCalled()
    const summary = dialog(second).find('[data-test="batch-summary"]').text()
    expect(summary).toContain('成功 2 筆')
    expect(summary).toContain('待確認 0 筆')
    expect(JSON.parse(sessionStorage.getItem(STORAGE_KEY)).batchId).toBe(batchId)

    await dialog(second).find('[data-test="batch-done"]').trigger('click')
    await flushPromises()
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
  })

  it('執行中離開頁面：剩下的不再送出，回來時標為未送出且不自動續送', async () => {
    let releaseFirst
    reviewAlertMock.mockImplementationOnce(() => new Promise((resolve) => { releaseFirst = resolve }))
    const first = mountAlerts()
    await flushPromises()
    await selectAndOpen(first, [2, 3])
    await fillAndSubmit(first)
    expect(reviewAlertMock).toHaveBeenCalledTimes(1)

    first.unmount()
    releaseFirst({})
    await flushPromises()
    // 卸載後回來的回應仍寫回該筆；第二筆沒送
    expect(reviewAlertMock).toHaveBeenCalledTimes(1)
    const saved = JSON.parse(sessionStorage.getItem(STORAGE_KEY))
    expect(saved.items.map((i) => i.state)).toEqual(['success', 'queued'])

    const second = mountAlerts()
    await flushPromises()
    expect(reviewAlertMock).toHaveBeenCalledTimes(1)
    const item = (id) => dialog(second).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    expect(item(2)).toContain('已標記')
    expect(item(3)).toContain('未送出')
  })

  it('掛載時收尾：送出中→查無審閱結果記未送出、排隊中→未送出、他人結果→被拒', async () => {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
      v: 1,
      batchId: '0b8e4c0e-2f1a-4b7a-9c3d-5e6f7a8b9c0d',
      kind: 'alert',
      userId: ME,
      params: { disposition: 'benign', note: '共用理由' },
      items: [
        { id: 2, label: '規則2 · 09/24 18:14', state: 'inflight', message: '' },
        { id: 3, label: '規則3 · 09/24 18:14', state: 'inflight', message: '' },
        { id: 5, label: '規則5 · 09/24 18:14', state: 'queued', message: '' },
      ],
    }))
    searchAlertsMock.mockImplementation((params) => {
      if (params?.ids) {
        return Promise.resolve(listResponse([
          alertRow(2),
          alertRow(3, { reviewed_at: '2026-09-29T01:00:00Z', reviewed_by: 12, disposition: 'escalated', note: '別的理由' }),
        ]))
      }
      return Promise.resolve(listResponse(sampleAlerts))
    })
    const wrapper = mountAlerts()
    await flushPromises()

    expect(reviewAlertMock).not.toHaveBeenCalled()
    expect(searchAlertsMock).toHaveBeenCalledWith(expect.objectContaining({ ids: '2,3' }), { skipErrorToast: true })
    const item = (id) => dialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    expect(item(2)).toContain('未送出')
    expect(item(3)).toContain('已有審閱結果')
    expect(item(5)).toContain('未送出')
    expect(dialog(wrapper).find('[data-test="batch-summary"]').text())
      .toContain('成功 0 筆 · 被拒 1 筆 · 未送出 2 筆 · 待確認 0 筆')
  })

  it('勾選達上限 50 筆後不可再勾並提示', async () => {
    const many = Array.from({ length: 51 }, (_, i) => alertRow(i + 10))
    searchAlertsMock.mockResolvedValue({ data: many, total: 51 })
    const wrapper = mountAlerts()
    await flushPromises()

    await wrapper.find('[data-test="batch-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="batch-bar"]').text()).toContain('已選 50 筆未審閱告警')
    expect(cell(wrapper, 60).attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="batch-limit-hint"]').text()).toContain('50')
  })

  it('單筆審閱既有流程不帶 batch_id', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    wrapper.vm.openReviewDialog(sampleAlerts[1])
    wrapper.vm.reviewForm.note = '單筆'
    await wrapper.vm.submitReview()
    await flushPromises()
    expect(reviewAlertMock).toHaveBeenCalledWith(2, { disposition: 'benign', note: '單筆' })
  })
})
