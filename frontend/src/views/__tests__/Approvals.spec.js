import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { t } from '@/i18n'
import ElementPlus from 'element-plus'
import Approvals from '../Approvals.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積會使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅，故以 enableAutoUnmount(afterEach) 確保
// 每測結束卸載元件。
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
const getCountMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequests: (...a) => getPendingMock(...a),
  getAccessRequestHistory: (...a) => getHistoryMock(...a),
  getActiveTickets: (...a) => getTicketsMock(...a),
  approveAccessRequest: (...a) => approveMock(...a),
  rejectAccessRequest: (...a) => rejectMock(...a),
  revokeAccessRequest: (...a) => revokeMock(...a),
  reviewBreakGlass: (...a) => reviewMock(...a),
  getPendingReviews: (...a) => getReviewsMock(...a),
  getPendingAccessRequestCount: (...a) => getCountMock(...a),
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
    attachTo: document.body,
  })

describe('Approvals 審核中心', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPendingMock.mockResolvedValue(samplePending)
    getHistoryMock.mockResolvedValue(sampleHistory)
    getTicketsMock.mockResolvedValue({ data: [], total: 0 })
    getReviewsMock.mockResolvedValue({ data: [], total: 0 })
    getCountMock.mockResolvedValue({ count: 1, review_count: 0 })
  })

  it('待審空狀態渲染自訂文案（title 實際顯示）', async () => {
    getPendingMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('目前沒有等候審核的申請')
    // 空態要交代原因與下一步，不能只留一句「沒有」
    expect(wrapper.text()).toContain('新申請進來會顯示在這裡')
    expect(wrapper.text()).toContain('AI agent 任務')
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

  it('列表被截斷時待審頁籤顯示總數，不是已載入列數（與「已載入 N 筆，共 M 筆」的 M 同源）', async () => {
    getPendingMock.mockResolvedValue(samplePending)
    getCountMock.mockResolvedValue({ count: 236, review_count: 7 })
    const wrapper = mountView()
    await flushPromises()

    const tabs = wrapper.find('.el-tabs__header').text()
    expect(tabs).toContain(t('approvals.pendingTabCount', { n: 236 }))
    expect(tabs).toContain(t('approvals.reviewTabCount', { n: 7 }))
    expect(tabs).not.toContain(t('approvals.pendingTabCount', { n: samplePending.data.length }))
    expect(wrapper.find('[data-test="pending-loaded-of-total"]').text()).toContain('236')
  })

  it('全量讀不到時頁籤只顯示名稱，不用已載入列數冒充總數', async () => {
    getPendingMock.mockResolvedValue(samplePending)
    getCountMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountView()
    await flushPromises()

    const tabs = wrapper.find('.el-tabs__header').text()
    expect(tabs).toContain(t('approvals.pendingTab'))
    expect(tabs).not.toContain(t('approvals.pendingTabCount', { n: samplePending.data.length }))
  })

  it('已載入／全量說明在表格下方', async () => {
    const wrapper = mountView()
    await flushPromises()

    const table = wrapper.find('[data-test="pending-table"]').element
    const note = wrapper.find('[data-test="pending-loaded-of-total"]').element
    expect(table.compareDocumentPosition(note) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
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

  it('版面：操作欄不固定在右側、展開區黏在可見寬度內；1024 寬時申請人併入申請欄', async () => {
    window.innerWidth = 1024
    const wrapper = mountView()
    await flushPromises()
    const columns = wrapper.getComponent('[data-test="pending-table"]').findAllComponents({ name: 'ElTableColumn' })
    expect(columns.every((col) => !col.props('fixed'))).toBe(true)
    expect(wrapper.findAll('[data-test="pending-table"] th').map((th) => th.text())).not.toContain('申請人')
    await wrapper.get('[data-test="toggle-items"]').trigger('click')
    await flushPromises()
    const sticky = wrapper.get('[data-test="expand-sticky"]')
    expect(sticky.attributes('style')).toContain('position: sticky')
    expect(sticky.attributes('style')).toContain('left: 0')
  })

  it('窄螢幕：需要多位審核人時進度欄表頭用短字，單號欄可在空白處換行而不被裁掉', async () => {
    window.innerWidth = 1024
    getPendingMock.mockResolvedValue({
      data: [{ id: 9002, requester_id: 5, requester: { username: 'chen.wei' }, asset_id: 1, asset: { name: 'web' }, reason: 'x', requested_duration_minutes: 60, created_at: '2026-11-23T02:00:00Z', items: [{ id: 1, asset_id: 1, asset_name: 'web', status: 'pending', approvals_required: 2, approvals: [] }] }],
    })
    const wrapper = mountView()
    await flushPromises()
    const heads = wrapper.findAll('[data-test="pending-table"] th').map((th) => th.text())
    expect(heads).toContain('進度')
    expect(heads).not.toContain('核准進度')
    expect(wrapper.get('[data-test="pending-table"] td.request-column').exists()).toBe(true)
  })

  it('歷史：一人核准兩項只算一人；兩人核准寫兩人並列名', async () => {
    getHistoryMock.mockResolvedValue({
      data: [
        { id: 36, requester_id: 5, requester: { username: 'liu.an' }, status: 'approved', decided_at: '2026-11-22T08:12:00Z',
          approver: { username: 'lin.mei' },
          approvals: [{ approver_id: 9, approver: { username: 'lin.mei' } }, { approver_id: 9, approver: { username: 'lin.mei' } }],
          items: [{ id: 1, asset_id: 1, asset_name: 'db-stg-02', status: 'approved' }, { id: 2, asset_id: 2, asset_name: 'db-stg-03', status: 'approved' }] },
        { id: 38, requester_id: 6, requester: { username: 'zhao.min' }, status: 'approved', decided_at: '2026-11-23T02:25:00Z',
          approver: { username: 'lin.mei' },
          approvals: [{ approver_id: 8, approver: { username: 'wang.jie' } }, { approver_id: 9, approver: { username: 'lin.mei' } }],
          items: [{ id: 3, asset_id: 3, asset_name: 'core-sw-02', status: 'approved' }] },
      ],
      total: 2,
    })
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.activeTab = 'history'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()
    const handlers = wrapper.findAll('.history-table tbody [data-test="history-handler"]')
    expect(handlers[0].text()).toBe('lin.mei')
    expect(handlers[0].find('[data-test="approved-by-count"]').exists()).toBe(false)
    expect(handlers[1].text()).toContain('wang.jie、lin.mei')
    expect(handlers[1].get('[data-test="approved-by-count"]').text()).toBe('共 2 人核准')
  })

  it('歷史：申請人就是執行者時只列一次名稱', async () => {
    getHistoryMock.mockResolvedValue({
      data: [{ id: 40, requester_id: 5, requester: { id: 5, username: 'chen.wei' }, executor_user_id: 5,
        executor: { id: 5, username: 'chen.wei', kind: 'human' }, status: 'approved', decided_at: '2026-11-23T02:36:00Z', items: [] }],
      total: 1,
    })
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.activeTab = 'history'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()
    const table = wrapper.get('.history-table')
    expect(table.text().split('chen.wei')).toHaveLength(2)
    expect(table.find('[data-test="executor-principal"]').exists()).toBe(false)
  })

  it('有效限時連線：同一張申請的列相鄰並標示、不寫整張台數；撤銷框列出清單中的兩台、送出一次整張撤銷', async () => {
    getTicketsMock.mockResolvedValue({
      data: [
        { id: 501, request_id: 34, user_id: 5, user: { username: 'liu.an' }, asset_id: 1, asset: { name: 'app-prod-01' }, date_start: '2026-11-23T02:05:00Z', date_expired: '2026-11-23T04:05:00Z' },
        { id: 502, request_id: 40, user_id: 6, user: { username: 'chen.wei' }, asset_id: 3, asset: { name: 'web-prod-03' }, date_start: '2026-11-23T02:36:00Z', date_expired: '2026-11-23T03:36:00Z' },
        { id: 503, request_id: 34, user_id: 5, user: { username: 'liu.an' }, asset_id: 2, asset: { name: 'app-prod-02' }, date_start: '2026-11-23T02:05:00Z', date_expired: '2026-11-23T04:05:00Z' },
      ],
      total: 3,
    })
    revokeMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.activeTab = 'tickets'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()
    const rows = wrapper.findAll('[data-test="tickets-table"] tbody tr.el-table__row').map((tr) => tr.text())
    expect(rows[0]).toContain('申請 #34')
    // 清單依審核範圍過濾且有上限，不主張整張的台數
    expect(rows[0]).not.toMatch(/共 \d+ 台/)
    expect(rows[1]).toContain('同一張申請')
    expect(rows[1]).toContain('app-prod-02')
    expect(rows[2]).toContain('申請 #40')

    wrapper.vm.openRevokeDialog(wrapper.vm.ticketRows[1])
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="revoke-dialog"]')?.closest('.el-dialog') || document.body
    const items = [...document.body.querySelectorAll('[data-test="revoke-items"] li')].map((li) => li.textContent)
    expect(items).toHaveLength(2)
    expect(items[0]).toContain('app-prod-01')
    expect(items[1]).toContain('app-prod-02')
    expect(dialog.textContent).toContain('提前撤銷申請 #34')
    expect(dialog.textContent).toContain('會一起收回這張申請的所有資產')
    expect(document.body.querySelector('[data-test="revoke-submit"]').textContent.trim()).toBe('撤銷這張申請')
    expect(dialog.textContent).not.toMatch(/無法只撤銷|individually|1 台だけ/)

    wrapper.vm.revokeNote = '任務已完成'
    await wrapper.vm.submitRevoke()
    await flushPromises()
    expect(revokeMock).toHaveBeenCalledTimes(1)
    expect(revokeMock).toHaveBeenCalledWith(34, '任務已完成')
  })

  it('提前撤銷帶申請單 id 與事由；成功後刷新限時連線', async () => {
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

describe('Approvals 審核歷史唯讀（只持審核歷史呈現點）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPendingMock.mockResolvedValue(samplePending)
    getHistoryMock.mockResolvedValue(sampleHistory)
    getTicketsMock.mockResolvedValue({ data: [], total: 0 })
    getReviewsMock.mockResolvedValue({ data: [], total: 0 })
    getCountMock.mockResolvedValue({ count: 1, review_count: 0 })
  })
  afterEach(() => {
    resetCapabilities()
    window.history.replaceState({}, '', '/')
  })

  const tabNames = (wrapper) => wrapper.findAll('.el-tabs__item').map((n) => n.text())

  it('只有歷史分頁、唯讀說明，不讀待審、清冊、待補審與待審數；重新整理只重讀歷史', async () => {
    setCapabilitiesForTests(['ui:approval-history'])
    const wrapper = mountView()
    await flushPromises()

    expect(tabNames(wrapper)).toEqual([t('approvals.tabHistory')])
    expect(wrapper.text()).toContain(t('approvals.historyOnlyNote'))
    expect(wrapper.find('[data-test="page-header-tag"]').text()).toBe(t('approvals.readOnlyTag'))
    expect(wrapper.text()).not.toContain(t('approvals.forbiddenTitle'))
    expect(wrapper.text()).toContain('bob')

    await wrapper.find('.page-actions button').trigger('click')
    await flushPromises()
    expect(getHistoryMock).toHaveBeenCalledTimes(2)
    expect(getPendingMock).toHaveBeenCalledTimes(0)
    expect(getTicketsMock).toHaveBeenCalledTimes(0)
    expect(getReviewsMock).toHaveBeenCalledTimes(0)
    expect(getCountMock).toHaveBeenCalledTimes(0)
  })

  it('深連結 ?request= 照常定位該筆並展開', async () => {
    setCapabilitiesForTests(['ui:approval-history'])
    window.history.replaceState({}, '', '/approvals?request=20')
    const wrapper = mountView()
    await flushPromises()
    expect(wrapper.vm.highlightId).toBe(20)
    expect(wrapper.find('[data-test="history-highlight-missing"]').exists()).toBe(false)
    expect(wrapper.find('.el-table__expanded-cell').exists()).toBe(true)
    expect(getPendingMock).toHaveBeenCalledTimes(0)
  })

  it('同時持審核資格與審核歷史：分頁與只持審核資格時相同', async () => {
    setCapabilitiesForTests(['ui:approvals'])
    const approver = mountView()
    await flushPromises()
    const approverTabs = tabNames(approver)
    approver.unmount()

    setCapabilitiesForTests(['ui:approvals', 'ui:approval-history'])
    const both = mountView()
    await flushPromises()
    expect(tabNames(both)).toEqual(approverTabs)
    expect(approverTabs.length).toBeGreaterThan(1)
    expect(both.text()).not.toContain(t('approvals.historyOnlyNote'))
    expect(getPendingMock).toHaveBeenCalled()
  })
})
