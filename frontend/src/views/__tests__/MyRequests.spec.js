import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import MyRequests from '../MyRequests.vue'

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

const getMyAccessRequestsMock = vi.fn()
const getMyActiveTicketsMock = vi.fn()
const cancelAccessRequestMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getMyAccessRequests: (...a) => getMyAccessRequestsMock(...a),
  getMyActiveTickets: (...a) => getMyActiveTicketsMock(...a),
  cancelAccessRequest: (...a) => cancelAccessRequestMock(...a),
}))

const sampleRequests = {
  data: [
    {
      id: 11,
      asset_id: 1,
      asset: { name: '正式資料庫' },
      reason: '例行維護',
      requested_duration_minutes: 120,
      status: 'pending',
      created_at: '2026-07-17T10:00:00+08:00',
    },
    {
      id: 10,
      asset_id: 2,
      asset: { name: '跳板機' },
      reason: '查 log',
      requested_duration_minutes: 60,
      status: 'approved',
      approved_duration_minutes: 30,
      approver: { username: 'boss' },
      created_at: '2026-07-16T10:00:00+08:00',
    },
    {
      id: 9,
      asset_id: 2,
      asset: { name: '跳板機' },
      reason: '臨時查修',
      requested_duration_minutes: 60,
      status: 'rejected',
      decision_note: '不在維護時段',
      created_at: '2026-07-15T10:00:00+08:00',
    },
  ],
  total: 3,
}

const sampleTickets = {
  data: [
    {
      id: 5,
      asset_id: 2,
      asset: { name: '跳板機' },
      date_start: '2026-07-17T09:00:00+08:00',
      date_expired: '2026-07-17T09:30:00+08:00',
    },
  ],
  total: 1,
}

const mountView = () =>
  mount(MyRequests, {
    global: { plugins: [ElementPlus] },
  })

describe('MyRequests 我的申請', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getMyAccessRequestsMock.mockResolvedValue(sampleRequests)
    getMyActiveTicketsMock.mockResolvedValue(sampleTickets)
  })

  it('渲染申請列表：白話狀態文案與處理結果', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('等候審核')
    expect(text).toContain('已核准')
    expect(text).toContain('未核准')
    // 核准摘要含核准人與實際可用時長（下修後 30 分）
    expect(text).toContain('boss 核准')
    expect(text).toContain('30 分鐘')
    // 拒絕理由申請人可見
    expect(text).toContain('不在維護時段')
  })

  it('有效限時連線區塊呈現時窗', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.ticket-panel').exists()).toBe(true)
    expect(wrapper.text()).toContain('可連線')
  })

  it('無有效臨時授權時不顯示限時連線區塊', async () => {
    getMyActiveTicketsMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.find('.ticket-panel').exists()).toBe(false)
  })

  it('僅 pending 列有撤回；確認後呼叫撤回 API 並刷新', async () => {
    cancelAccessRequestMock.mockResolvedValue({ id: 11, status: 'cancelled' })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountView()
    await flushPromises()

    const cancelButtons = wrapper
      .findAll('button')
      .filter((b) => b.text().includes('撤回'))
    expect(cancelButtons.length).toBe(1)

    getMyAccessRequestsMock.mockClear()
    await wrapper.vm.handleCancel(sampleRequests.data[0])
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(cancelAccessRequestMock).toHaveBeenCalledWith(11)
    expect(getMyAccessRequestsMock).toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('使用者取消確認時不呼叫撤回 API', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = mountView()
    await flushPromises()

    await wrapper.vm.handleCancel(sampleRequests.data[0])
    await flushPromises()

    expect(cancelAccessRequestMock).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('空狀態渲染引導文案（title＋hint 實際顯示）', async () => {
    getMyAccessRequestsMock.mockResolvedValue({ data: [], total: 0 })
    getMyActiveTicketsMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('還沒有任何申請')
    expect(text).toContain('到「資產管理」找到需要申請的主機')
  })

  it('破窗單標記「緊急」、已撤銷單顯示「已提前撤銷」', async () => {
    getMyAccessRequestsMock.mockResolvedValue({
      data: [
        {
          id: 20, asset_id: 3, asset: { name: '核心主機' }, reason: '線上事故',
          requested_duration_minutes: 60, status: 'approved', kind: 'break_glass',
          auto_approved: true, created_at: '2026-07-17T02:00:00+08:00',
        },
        {
          id: 19, asset_id: 2, asset: { name: '跳板機' }, reason: '維護',
          requested_duration_minutes: 60, status: 'approved', approver: { username: 'boss' },
          revoked_at: '2026-07-17T03:00:00+08:00', revoke_note: '任務已完成',
          created_at: '2026-07-17T01:00:00+08:00',
        },
      ],
      total: 2,
    })
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('緊急') // 破窗單標記
    expect(text).toContain('已提前撤銷') // 撤銷覆蓋狀態文案
    expect(text).toContain('任務已完成') // 撤銷事由
  })
})
