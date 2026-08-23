import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AccessReviews from '../AccessReviews.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getAccessReviewsMock = vi.fn()
const getAccessReviewDetailMock = vi.fn()
const createAccessReviewMock = vi.fn()

vi.mock('@/api/access-reviews', () => ({
  getAccessReviews: (...a) => getAccessReviewsMock(...a),
  getAccessMatrix: vi.fn().mockResolvedValue({ total: 15 }),
  getAccessReviewDetail: (...a) => getAccessReviewDetailMock(...a),
  createAccessReview: (...a) => createAccessReviewMock(...a),
}))

const setUser = (roles) => {
  localStorage.setItem('user', JSON.stringify({ id: 1, username: 'x', roles }))
}

// happy-dom×el-drawer 炸點：抽屜 stub 掉，本檔只驗清單/按鈕/狀態卡
const mountView = () =>
  mount(AccessReviews, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-drawer': true },
    },
  })

const historyFixture = {
  data: [
    {
      id: 5,
      reviewer_name: 'admin',
      reviewed_at: '2026-07-17T18:56:14Z',
      note: '',
      authorization_count: 15,
      days_ago: 2,
    },
    {
      id: 1,
      reviewer_name: 'admin',
      reviewed_at: '2026-07-02T18:59:27Z',
      note: '季度存取複審，全部授權已確認',
      authorization_count: 4,
      days_ago: 17,
    },
  ],
  last_review_days_ago: 2,
  review_period_days: 180,
  overdue: false,
}

describe('AccessReviews 存取複審獨立頁（職能自授權頁遷出）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAccessReviewsMock.mockResolvedValue(historyFixture)
  })

  it('複審歷史清單可見（補簽核後無處可看的斷鏈）', async () => {
    setUser(['admin'])
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('季度存取複審，全部授權已確認')
    expect(text).toContain('檢視快照')
    expect(text).toContain('上次存取複審：2 天前')
  })

  it('週期與逾期用伺服端欄位（前端不硬編碼 180）', async () => {
    getAccessReviewsMock.mockResolvedValue({
      ...historyFixture,
      last_review_days_ago: 200,
      review_period_days: 90,
      overdue: true,
    })
    setUser(['admin'])
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('已逾 90 天建議週期')
  })

  it('auditor 可見歷史但無發起簽核入口（簽核限 admin）', async () => {
    setUser(['auditor'])
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('檢視快照')
    expect(text).not.toContain('發起存取複審')
  })

  it('admin 有發起簽核入口', async () => {
    setUser(['admin'])
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('發起存取複審')
  })

  it('載入失敗顯錯不偽裝空狀態', async () => {
    getAccessReviewsMock.mockRejectedValue({
      response: { status: 500, data: { error: 'boom' } },
    })
    setUser(['auditor'])
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('複審歷史載入失敗')
    expect(text).not.toContain('尚無複審簽核紀錄')
  })
})
