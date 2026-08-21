import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Approvals from '../Approvals.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容（同 MyConnections）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getPendingMock = vi.fn()
const getHistoryMock = vi.fn()
const getTicketsMock = vi.fn()
const approveMock = vi.fn()
const rejectMock = vi.fn()
const revokeMock = vi.fn()
const reviewMock = vi.fn()
const getReviewsMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequests: (...a) => getPendingMock(...a),
  getAccessRequestHistory: (...a) => getHistoryMock(...a),
  getActiveTickets: (...a) => getTicketsMock(...a),
  approveAccessRequest: (...a) => approveMock(...a),
  rejectAccessRequest: (...a) => rejectMock(...a),
  revokeAccessRequest: (...a) => revokeMock(...a),
  reviewBreakGlass: (...a) => reviewMock(...a),
  getPendingReviews: (...a) => getReviewsMock(...a),
}))

const samplePending = {
  data: [
    {
      id: 21,
      requester_id: 5,
      requester: { username: 'alice' },
      asset_id: 1,
      asset: { name: '正式資料庫' },
      reason: '例行維護',
      requested_duration_minutes: 480,
      created_at: '2026-07-17T10:00:00+08:00',
    },
  ],
  total: 1,
}

const sampleHistory = {
  data: [
    {
      id: 20,
      requester: { username: 'bob' },
      asset: { name: '跳板機' },
      reason: '查 log',
      status: 'approved',
      auto_approved: true,
      decision_note: 'system',
      decided_at: '2026-07-16T10:00:00+08:00',
    },
  ],
  total: 1,
}

const mountView = () =>
  mount(Approvals, {
    global: { plugins: [ElementPlus] },
  })

describe('Approvals 審核中心', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPendingMock.mockResolvedValue(samplePending)
    getHistoryMock.mockResolvedValue(sampleHistory)
    getTicketsMock.mockResolvedValue({ data: [], total: 0 })
    getReviewsMock.mockResolvedValue({ data: [], total: 0 })
  })

  it('待審空狀態渲染自訂文案（ui-quick-fixes：title 實際顯示）', async () => {
    getPendingMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('目前沒有等候審核的申請')
  })

  it('待審列表渲染申請人/資產/理由與待審計數', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('alice')
    expect(text).toContain('正式資料庫')
    expect(text).toContain('例行維護')
    expect(text).toContain('待審（1）')
  })

  it('核准對話框預填申請時長且上限鎖在申請值（只能縮短）', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openApprove(samplePending.data[0])
    await flushPromises()

    expect(wrapper.vm.approveForm.duration_minutes).toBe(480)
    expect(wrapper.vm.approveTarget.requested_duration_minutes).toBe(480)
  })

  it('核准送出帶下修時長與備註，成功後刷新待審', async () => {
    approveMock.mockResolvedValue({ id: 21, status: 'approved' })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openApprove(samplePending.data[0])
    wrapper.vm.approveForm.duration_minutes = 120
    wrapper.vm.approveForm.note = '縮短為兩小時'
    getPendingMock.mockClear()

    await wrapper.vm.submitApprove()
    await flushPromises()

    expect(approveMock).toHaveBeenCalledWith(21, {
      duration_minutes: 120,
      note: '縮短為兩小時',
    })
    expect(wrapper.vm.approveVisible).toBe(false)
    expect(getPendingMock).toHaveBeenCalled()
  })

  it('拒絕未填理由不可送出；填理由後送出', async () => {
    rejectMock.mockResolvedValue({ id: 21, status: 'rejected' })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.openReject(samplePending.data[0])
    await wrapper.vm.submitReject()
    expect(rejectMock).not.toHaveBeenCalled()

    wrapper.vm.rejectNote = '不在維護時段'
    await wrapper.vm.submitReject()
    await flushPromises()

    expect(rejectMock).toHaveBeenCalledWith(21, '不在維護時段')
    expect(wrapper.vm.rejectVisible).toBe(false)
  })

  it('歷史頁籤：自動核准單帶可辨識標記', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.activeTab = 'history'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()

    expect(getHistoryMock).toHaveBeenCalled()
    expect(wrapper.text()).toContain('系統自動核准')
  })

  it('提前撤銷帶申請單 id 與事由；成功後刷新限時連線（break-glass-revocation）', async () => {
    revokeMock.mockResolvedValue({ id: 30, status: 'approved' })
    const wrapper = mountView()
    await flushPromises()

    // 票證列附 request_id 回鏈（撤銷走申請單）
    wrapper.vm.openRevokeDialog({ request_id: 30, user: { username: 'alice' }, asset: { name: 'db' } })
    await wrapper.vm.submitRevoke()
    expect(revokeMock).not.toHaveBeenCalled() // 事由必填

    wrapper.vm.revokeNote = '任務已完成'
    await wrapper.vm.submitRevoke()
    await flushPromises()

    expect(revokeMock).toHaveBeenCalledWith(30, '任務已完成')
    expect(wrapper.vm.revokeVisible).toBe(false)
    expect(getTicketsMock).toHaveBeenCalled()
  })

  it('待補審頁籤：載入待補審清單並可補審', async () => {
    getReviewsMock.mockResolvedValue({
      data: [{ id: 40, requester: { username: 'carol' }, asset: { name: 'k8s' },
        reason: '線上事故', created_at: '2026-07-17T02:00:00+08:00' }],
      total: 1,
    })
    reviewMock.mockResolvedValue({ id: 40, review_status: 'reviewed' })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()
    expect(getReviewsMock).toHaveBeenCalled()
    expect(wrapper.text()).toContain('carol')

    wrapper.vm.openReviewDialog({ id: 40, requester: { username: 'carol' }, asset: { name: 'k8s' }, reason: '線上事故' })
    wrapper.vm.reviewForm.disposition = 'violation'
    wrapper.vm.reviewForm.note = '未依規範'
    await wrapper.vm.submitReview()
    await flushPromises()

    expect(reviewMock).toHaveBeenCalledWith(40, 'violation', '未依規範')
    expect(wrapper.vm.reviewVisible).toBe(false)
  })
})
