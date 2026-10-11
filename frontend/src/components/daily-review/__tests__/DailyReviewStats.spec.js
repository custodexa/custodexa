import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewStats from '../DailyReviewStats.vue'

enableAutoUnmount(afterEach)

const getDailyReviewStatsMock = vi.fn()
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStats: (...args) => getDailyReviewStatsMock(...args),
}))

// 近 30 天＝截至昨日的 30 個所屬日；昨日未到期，應簽至多 29 天（後端的共用定義）
const statsResponse = (overrides = {}) => ({
  data: {
    from: '2026-09-11',
    to: '2026-10-10',
    as_of: '2026-10-11T04:00:00Z',
    timezone: 'Asia/Taipei',
    required: 29,
    on_time: 23,
    late: 2,
    unsigned: 4,
    sign_rate: 25 / 29,
    sign_rate_percent: 86,
    inferred_days: 0,
    days: [],
    ...overrides,
  },
})

const mountStats = () => mount(DailyReviewStats, { global: { plugins: [ElementPlus] } })

describe('DailyReviewStats', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // 防：前端自己用日期推分母，與後端、證據包、合規報告對不上
  it('顯示回應的期間與數字、不自行計算', async () => {
    getDailyReviewStatsMock.mockResolvedValue(statsResponse())
    const wrapper = mountStats()
    await flushPromises()

    expect(getDailyReviewStatsMock).toHaveBeenCalledWith({ period: '30d' })
    expect(wrapper.find('[data-test="dr-stats-range"]').text()).toContain('2026-09-11 至 2026-10-10')
    expect(wrapper.find('[data-test="dr-stats-range"]').text()).toContain('2026/10/11 12:00 (UTC+8)')
    expect(wrapper.find('[data-test="dr-stats-rate"]').text()).toBe('86%')
    expect(wrapper.find('[data-test="dr-stats-on-time"]').text()).toBe('23')
    expect(wrapper.find('[data-test="dr-stats-late"]').text()).toBe('2')
    expect(wrapper.find('[data-test="dr-stats-unsigned"]').text()).toBe('4')
    const text = wrapper.text()
    expect(text).toContain('應簽 29 天，已簽 25 天')
    expect(text).not.toContain('應簽 30')
    expect(text).toContain('尚未到期的日子、功能關閉期間不計入應簽')
    expect(wrapper.find('[data-test="dr-stats-inferred"]').exists()).toBe(false)
  })

  // 防：推定天數被當成另一個不計入的類別，讓人誤讀分母
  it('有推定天數時說明已計入應簽，四格數字不變', async () => {
    getDailyReviewStatsMock.mockResolvedValue(statsResponse({ inferred_days: 3 }))
    const wrapper = mountStats()
    await flushPromises()

    expect(wrapper.find('[data-test="dr-stats-inferred"]').text()).toContain('其中 3 天的啟用狀態由推定而來')
    expect(wrapper.find('[data-test="dr-stats-inferred"]').text()).toContain('已計入應簽')
    expect(wrapper.find('[data-test="dr-stats-rate"]').text()).toBe('86%')
    expect(wrapper.find('[data-test="dr-stats-on-time"]').text()).toBe('23')
    expect(wrapper.find('[data-test="dr-stats-late"]').text()).toBe('2')
    expect(wrapper.find('[data-test="dr-stats-unsigned"]').text()).toBe('4')
  })

  it('分母為 0 時簽核率顯示「—」而不是 0% 或 100%', async () => {
    getDailyReviewStatsMock.mockResolvedValue(statsResponse({ required: 0, on_time: 0, late: 0, unsigned: 0, sign_rate: null, sign_rate_percent: null }))
    const wrapper = mountStats()
    await flushPromises()
    expect(wrapper.find('[data-test="dr-stats-rate"]').text()).toBe('—')
  })

  it('切換近 90 天與自訂期間時照樣以後端參數查詢', async () => {
    getDailyReviewStatsMock.mockResolvedValue(statsResponse())
    const wrapper = mountStats()
    await flushPromises()

    wrapper.vm.$.setupState.period = '90d'
    await wrapper.vm.$.setupState.onPeriodChange()
    expect(getDailyReviewStatsMock).toHaveBeenLastCalledWith({ period: '90d' })

    wrapper.vm.$.setupState.period = 'custom'
    wrapper.vm.$.setupState.customRange = ['2026-04-01', '2026-04-30']
    await wrapper.vm.load()
    expect(getDailyReviewStatsMock).toHaveBeenLastCalledWith({ from: '2026-04-01', to: '2026-04-30' })
  })
})
