import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, DOMWrapper } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Alerts from '../Alerts.vue'
import { resetCapabilities } from '@/composables/useCapabilities'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'

// 告警頁的批次處置：勾選 → 共用處置與理由 → 一次請求送出；
// 本人觸發的也可以勾，對話框要求確認。替身端點，不打任何真實服務
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
const batchReviewMock = vi.fn()

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
  reviewAlert: (...args) => reviewAlertMock(...args),
  batchReviewAlerts: (...args) => batchReviewMock(...args),
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
// 對話框掛在 body（append-to-body）
const dialog = () => new DOMWrapper(document.body).find('[data-test="alerts-batch-dialog"]')

const selectAndOpen = async (wrapper, ids) => {
  for (const id of ids) {
    await cell(wrapper, id).setValue(true)
  }
  await flushPromises()
  await wrapper.find('[data-test="batch-open"]').trigger('click')
  await flushPromises()
}

const fillAndSubmit = async ({ note = '更換筆電後首次連線', escalate = false, ack = true } = {}) => {
  if (escalate) await dialog().find('[data-test="batch-disposition-escalated"] input').setValue(true)
  const box = dialog().find('[data-test="bulk-self-ack"] input')
  if (ack && box.exists()) await box.setValue(true)
  await dialog().find('[data-test="batch-note"] textarea').setValue(note)
  await dialog().find('[data-test="batch-submit"]').trigger('click')
  await flushPromises()
}

const reviewedAll = (data) => ({
  batch_id: data.batch_id,
  limit: 500,
  items: data.alert_ids.map((id) => ({ id, result: 'reviewed', self_triggered: id === 1 })),
})

describe('Alerts 批次處置', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    searchAlertsMock.mockReset()
    reviewAlertMock.mockReset()
    batchReviewMock.mockReset()
    localStorage.clear()
    sessionStorage.clear()
    document.body.innerHTML = ''
    resetCapabilities()
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'auditor1' }))
    grantFor(['auditor'])
    searchAlertsMock.mockResolvedValue(listResponse(sampleAlerts))
    reviewAlertMock.mockResolvedValue({})
    batchReviewMock.mockImplementation(async (data) => reviewedAll(data))
  })

  it('未審閱的都可以勾（含本人觸發）；已審閱的不能勾；全選取全部未審閱', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    expect(cell(wrapper, 1).attributes('disabled')).toBeUndefined() // 本人觸發
    expect(cell(wrapper, 4).attributes('disabled')).toBeDefined() // 已審閱
    expect(wrapper.find('[data-test="batch-select-cell"][data-id="4"]').text()).toContain('已審閱的告警請逐筆重新審閱')
    await wrapper.find('[data-test="batch-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="batch-bar"]').text()).toContain('已選 3 筆（3 類，其中你觸發的 1 筆）')
  })

  it('不具審閱權限時不顯示勾選欄', async () => {
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'u' }))
    grantFor(['user'])
    const wrapper = mountAlerts()
    await flushPromises()
    expect(wrapper.find('[data-test="batch-select-cell"]').exists()).toBe(false)
  })

  it('含本人觸發的一批：出現確認段，送出一個批次請求（依表格順序、帶本人觸發筆數）', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    await selectAndOpen(wrapper, [3, 1, 2])
    expect(dialog().find('[data-test="bulk-self"]').text()).toContain('其中 1 筆是你自己觸發的')
    await fillAndSubmit({ escalate: true })
    expect(reviewAlertMock).not.toHaveBeenCalled()
    expect(batchReviewMock).toHaveBeenCalledTimes(1)
    const [data, options] = batchReviewMock.mock.calls[0]
    expect(data).toMatchObject({ alert_ids: [1, 2, 3], disposition: 'escalated', note: '更換筆電後首次連線', self_triggered_ack: 1 })
    expect(data.batch_id).toMatch(UUID_V4)
    expect(options).toEqual({ skipErrorToast: true })
    expect(dialog().find('[data-test="batch-summary"]').text()).toBe('成功 3 筆 · 沒有生效 0 筆')
  })

  it('只看未審閱時，結果說明處置過的已離開清單、表格是下一批', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    await wrapper.findComponent({ name: 'ElSwitch' }).vm.$emit('update:modelValue', true)
    await flushPromises()
    await selectAndOpen(wrapper, [2, 3])
    searchAlertsMock.mockResolvedValue(listResponse([alertRow(1, { user_id: ME })]))
    await fillAndSubmit()
    expect(dialog().find('[data-test="bulk-result-note"]').text()).toBe('處置過的已離開「僅未審閱」的清單；表格現在是下一批 1 筆，可以再全選本頁。')
  })

  it('沒有回應：待確認；重新掛載時以 id 清單查回，不自動重送', async () => {
    batchReviewMock.mockRejectedValue({ request: {}, message: 'Network Error' })
    const first = mountAlerts()
    await flushPromises()
    await selectAndOpen(first, [2, 3])
    await fillAndSubmit({ note: '同一理由' })
    expect(dialog().find('[data-test="batch-summary"]').text()).toBe('成功 0 筆 · 沒有生效 0 筆 · 待確認 2 筆')
    first.unmount()
    document.body.innerHTML = ''
    searchAlertsMock.mockImplementation(async (params) => {
      if (params.ids) {
        return listResponse(params.ids.split(',').map((id) => alertRow(Number(id), { reviewed_at: 'x', reviewed_by: ME, disposition: 'benign', note: '同一理由' })))
      }
      return listResponse(sampleAlerts)
    })
    mountAlerts()
    await flushPromises()
    expect(batchReviewMock).toHaveBeenCalledTimes(1)
    const lookup = searchAlertsMock.mock.calls.find(([params]) => params.ids)
    expect(lookup[0].ids).toBe('2,3')
    expect(dialog().find('[data-test="batch-summary"]').text()).toBe('成功 2 筆 · 沒有生效 0 筆')
  })

  it('勾選上限是批次端點的單次上限（不是逐筆批次的 50 筆）：一頁 60 筆可全選', async () => {
    const many = Array.from({ length: 60 }, (_, i) => alertRow(i + 10))
    searchAlertsMock.mockResolvedValue({ data: many, total: 60 })
    const wrapper = mountAlerts()
    await flushPromises()
    await wrapper.find('[data-test="batch-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="batch-bar"]').text()).toContain('已選 60 筆')
    expect(wrapper.find('[data-test="batch-limit-hint"]').exists()).toBe(false)
  })

  it('單筆審閱既有流程不帶 batch_id，處置分類用「無害」「需升級處理」', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    wrapper.vm.openReviewDialog(sampleAlerts[1])
    await flushPromises()
    const text = wrapper.text()
    expect(text).toContain('需升級處理')
    expect(text).not.toContain('誤報 / 無害')
    wrapper.vm.reviewForm.note = '單筆'
    await wrapper.vm.submitReview()
    await flushPromises()
    expect(reviewAlertMock).toHaveBeenCalledWith(2, { disposition: 'benign', note: '單筆' })
  })
})
