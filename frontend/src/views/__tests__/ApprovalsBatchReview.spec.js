import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Approvals from '../Approvals.vue'

// 審核中心批次處理：待審（核准／拒絕）與待補審（確認無誤），前端逐張呼叫既有單張端點
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

const getPendingMock = vi.fn()
const getHistoryMock = vi.fn()
const approveMock = vi.fn()
const rejectMock = vi.fn()
const reviewMock = vi.fn()
const getReviewsMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequests: (...a) => getPendingMock(...a),
  getAccessRequestHistory: (...a) => getHistoryMock(...a),
  getActiveTickets: vi.fn().mockResolvedValue({ data: [] }),
  approveAccessRequest: (...a) => approveMock(...a),
  rejectAccessRequest: (...a) => rejectMock(...a),
  revokeAccessRequest: vi.fn(),
  reviewBreakGlass: (...a) => reviewMock(...a),
  getPendingReviews: (...a) => getReviewsMock(...a),
  rejectAccessRequestItem: vi.fn(),
}))

vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))

const ME = 67
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const item = (id, extra = {}) => ({
  id,
  asset_id: 20 + id,
  asset_name: `asset-${id}`,
  accounts: ['ops'],
  status: 'pending',
  approvals: [],
  ...extra,
})

const request107 = {
  id: 107,
  requester_id: 64,
  requester: { username: 'alice' },
  asset_id: 21,
  asset: { name: 'asset-1' },
  reason: '每日例行巡檢',
  requested_duration_minutes: 60,
  created_at: '2026-09-29T01:13:00Z',
  items: [item(1)],
}
const request108 = {
  id: 108,
  requester_id: 65,
  requester: { username: 'bob' },
  asset_id: 22,
  asset: { name: 'asset-2' },
  reason: '部署修補',
  requested_duration_minutes: 120,
  created_at: '2026-09-29T01:13:00Z',
  items: [item(2, { accounts: ['deploy'] }), item(3, { status: 'approved', accounts: ['deploy'] })],
}
const request111 = {
  id: 111,
  requester_id: 66,
  requester: { username: 'carol' },
  asset_id: 30,
  asset: { name: 'legacy-01' },
  reason: '舊式單',
  requested_duration_minutes: 30,
  created_at: '2026-09-29T01:13:00Z',
}

const httpError = (status, code) => ({ response: { status, data: { code, error: code } } })

const mountView = () => mount(Approvals, { global: { plugins: [ElementPlus] } })
const pendingCell = (w, id) => w.find(`[data-test="pending-select-cell"][data-id="${id}"] input`)
const pendingDialog = (w) => w.find('[data-test="pending-batch-dialog"]')
const reviewsDialog = (w) => w.find('[data-test="reviews-batch-dialog"]')

describe('Approvals 批次處理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // mockImplementationOnce 佇列不隨 clearAllMocks 清掉：逐一 reset，避免前一測殘留
    for (const m of [getPendingMock, getHistoryMock, approveMock, rejectMock, reviewMock, getReviewsMock]) m.mockReset()
    localStorage.clear()
    sessionStorage.clear()
    localStorage.setItem('user', JSON.stringify({ id: ME, username: 'a4-batch-approver', roles: ['user', 'approver'] }))
    getPendingMock.mockResolvedValue({ data: [request107, request108, request111] })
    getHistoryMock.mockResolvedValue({ data: [], total: 0 })
    getReviewsMock.mockResolvedValue({ data: [] })
  })

  it('批次核准：逐張列出申請內容，body 只帶所有 pending 項目與 batch_id，不帶時長或帳號修改', async () => {
    approveMock
      .mockResolvedValueOnce({ ...request107, status: 'approved', items: [item(1, { status: 'approved' })] })
      .mockResolvedValueOnce({
        ...request108,
        status: 'pending',
        items: [
          item(2, { accounts: ['deploy'], approvals_received: 1, approvals_required: 2 }),
          item(3, { status: 'approved' }),
        ],
      })
      .mockRejectedValueOnce(httpError(403, 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER'))
    const wrapper = mountView()
    await flushPromises()

    await wrapper.find('[data-test="pending-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="pending-batch-bar"]').text()).toContain('已選 3 張申請')
    await wrapper.find('[data-test="batch-approve-open"]').trigger('click')
    await flushPromises()

    const confirmText = pendingDialog(wrapper).text()
    expect(confirmText).toContain('任務 107')
    expect(confirmText).toContain('alice')
    expect(confirmText).toContain('asset-1')
    expect(confirmText).toContain('ops')
    expect(confirmText).toContain('1 小時')
    expect(confirmText).toContain('批次核准一律照申請內容；要調整請逐張處理')
    // 已決定的項目不在這次核准範圍內
    expect(confirmText).not.toContain('asset-3')

    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()

    expect(approveMock).toHaveBeenCalledTimes(3)
    const [c1, c2, c3] = approveMock.mock.calls
    const batchId = c1[1].batch_id
    expect(batchId).toMatch(UUID_V4)
    expect(c1).toEqual([107, { items: [{ item_id: 1 }], batch_id: batchId }, { skipErrorToast: true }])
    expect(c2).toEqual([108, { items: [{ item_id: 2 }], batch_id: batchId }, { skipErrorToast: true }])
    expect(c3).toEqual([111, { batch_id: batchId }, { skipErrorToast: true }])

    const row = (id) => pendingDialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    expect(row(107)).toContain('已核准')
    expect(row(108)).toContain('已投票（1／2），等其他審核人')
    expect(row(111)).toContain('被拒')
    expect(row(111)).toContain('整張未生效')
    expect(pendingDialog(wrapper).find('[data-test="batch-summary"]').text())
      .toContain('成功 2 張（其中 1 張仍需其他審核人）· 被拒 1 張 · 未送出 0 張 · 待確認 0 張')
  })

  it('批次拒絕：理由必填，逐張送出 {note, batch_id}，不帶 item_id', async () => {
    rejectMock.mockResolvedValue({ status: 'rejected' })
    const wrapper = mountView()
    await flushPromises()

    await pendingCell(wrapper, 107).setValue(true)
    await pendingCell(wrapper, 108).setValue(true)
    await flushPromises()
    await wrapper.find('[data-test="batch-reject-open"]').trigger('click')
    await flushPromises()

    const submit = () => pendingDialog(wrapper).find('[data-test="batch-submit"]')
    expect(submit().attributes('disabled')).toBeDefined()
    expect(pendingDialog(wrapper).text()).toContain('拒絕 2 張')
    // 只列這次會被拒絕的待決項目；已核准的項目不受影響、不列
    expect(pendingDialog(wrapper).text()).toContain('asset-2')
    expect(pendingDialog(wrapper).text()).not.toContain('asset-3')
    await pendingDialog(wrapper).find('[data-test="batch-note"] textarea').setValue('本週凍結變更')
    await submit().trigger('click')
    await flushPromises()

    expect(rejectMock).toHaveBeenCalledTimes(2)
    const batchId = rejectMock.mock.calls[0][2].batchId
    expect(batchId).toMatch(UUID_V4)
    expect(rejectMock.mock.calls[0]).toEqual([107, '本週凍結變更', { batchId, skipErrorToast: true }])
    expect(rejectMock.mock.calls[1]).toEqual([108, '本週凍結變更', { batchId, skipErrorToast: true }])
  })

  it('待審待確認：掛載時比對待審與歷史，查回實際狀態', async () => {
    sessionStorage.setItem('ot-batch-review:approvals-pending', JSON.stringify({
      v: 1,
      batchId: '0b8e4c0e-2f1a-4b7a-9c3d-5e6f7a8b9c0d',
      kind: 'approve',
      userId: ME,
      params: {},
      items: [
        { id: 107, label: '任務 107 · alice', state: 'inflight', message: '', meta: { itemIds: [1] } },
        { id: 108, label: '任務 108 · bob', state: 'inflight', message: '', meta: { itemIds: [2] } },
        { id: 109, label: '任務 109 · carol', state: 'inflight', message: '', meta: { itemIds: [9] } },
        { id: 110, label: '任務 110 · dave', state: 'inflight', message: '', meta: { itemIds: [10] } },
      ],
    }))
    getPendingMock.mockResolvedValue({
      data: [
        { ...request107, items: [item(1, { approvals: [{ approver_id: ME }] })] },
        request108,
      ],
    })
    getHistoryMock.mockResolvedValue({
      data: [{ id: 109, status: 'approved', approver_id: 99, approvals: [{ approver_id: 99 }], items: [item(9, { status: 'approved', decided_by: 99 })] }],
      total: 1,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(approveMock).not.toHaveBeenCalled()
    expect(getHistoryMock).toHaveBeenCalledWith({ page: 1, page_size: 100 }, { skipErrorToast: true })
    const row = (id) => pendingDialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    // 仍在待審但所選項目已有我的票：我的核准已記錄，單子還在等其他審核人
    expect(row(107)).toContain('已投票')
    expect(row(108)).toContain('未送出')
    expect(row(109)).toContain('已由其他審核人處理')
    expect(row(110)).toContain('待確認')
    expect(row(110)).toContain('歷史')
  })

  it('待補審：批次只提供確認無誤，理由必填，逐筆帶同一 batch_id', async () => {
    getReviewsMock.mockResolvedValue({
      data: [
        { id: 40, requester_id: 64, requester: { username: 'alice' }, asset: { name: 'k8s' }, reason: '事故', created_at: '2026-09-29T01:00:00Z', kind: 'break_glass' },
        { id: 41, requester_id: 65, requester: { username: 'bob' }, asset: { name: 'db' }, reason: '事故', created_at: '2026-09-29T01:00:00Z', kind: 'break_glass' },
      ],
    })
    reviewMock.mockRejectedValueOnce(httpError(409, 'CONFLICT_ACCESS_REQUEST_STATE')).mockResolvedValueOnce({})
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()

    await wrapper.find('[data-test="reviews-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="reviews-batch-bar"]').text()).toContain('已選 2 筆')
    await wrapper.find('[data-test="batch-review-open"]').trigger('click')
    await flushPromises()

    // 批次只提供「確認無誤」：沒有處置選項可選
    expect(reviewsDialog(wrapper).find('input[type="radio"]').exists()).toBe(false)
    expect(reviewsDialog(wrapper).text()).toContain('確認無誤')
    expect(reviewsDialog(wrapper).find('[data-test="batch-submit"]').attributes('disabled')).toBeDefined()
    await reviewsDialog(wrapper).find('[data-test="batch-note"] textarea').setValue('皆為事故處理')
    await reviewsDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()

    expect(reviewMock).toHaveBeenCalledTimes(2)
    const opts = reviewMock.mock.calls[0][3]
    expect(opts.batchId).toMatch(UUID_V4)
    expect(reviewMock.mock.calls[0]).toEqual([40, 'confirmed', '皆為事故處理', { batchId: opts.batchId, skipErrorToast: true }])
    expect(reviewMock.mock.calls[1]).toEqual([41, 'confirmed', '皆為事故處理', { batchId: opts.batchId, skipErrorToast: true }])
    expect(reviewsDialog(wrapper).find('[data-test="batch-summary"]').text())
      .toContain('成功 1 筆 · 被拒 1 筆 · 未送出 0 筆 · 待確認 0 筆')
  })

  it('既有單張核准與拒絕不帶 batch_id', async () => {
    approveMock.mockResolvedValue({ id: 111, status: 'approved' })
    rejectMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.openApprove(request111)
    await wrapper.vm.submitApprove()
    expect(approveMock).toHaveBeenCalledWith(111, { duration_minutes: 30, note: undefined })
    wrapper.vm.openReject(request111)
    wrapper.vm.rejectNote = '不行'
    await wrapper.vm.submitReject()
    expect(rejectMock).toHaveBeenCalledWith(111, '不行')
  })
})
