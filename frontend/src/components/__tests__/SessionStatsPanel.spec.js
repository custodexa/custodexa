import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const ElDrawerStub = {
  name: 'ElDrawer',
  props: ['modelValue', 'title'],
  emits: ['update:modelValue', 'open', 'close'],
  template: '<div class="stub-drawer"><slot /></div>',
}

const { mockGetSessionStats } = vi.hoisted(() => ({
  mockGetSessionStats: vi.fn(),
}))

vi.mock('@/api/sessions', () => ({
  getSessionStats: mockGetSessionStats,
}))

import SessionStatsPanel from '../SessionStatsPanel.vue'

const sample = (over = {}) => ({
  hostname: 'host-a',
  uptime_sec: 90000,
  load1: 0.1,
  load5: 0.2,
  load15: 0.3,
  mem_total_kb: 8000000,
  mem_avail_kb: 6000000,
  cpu_busy: 100,
  cpu_total: 1000,
  net_rx_bytes: 10000,
  net_tx_bytes: 5000,
  ...over,
})

function mountPanel() {
  return mount(SessionStatsPanel, {
    props: { modelValue: true, sessionId: 42 },
    global: { stubs: { 'el-drawer': ElDrawerStub } },
  })
}

describe('SessionStatsPanel', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('開啟輪詢並渲染指標', async () => {
    mockGetSessionStats.mockResolvedValue(sample())
    const wrapper = mountPanel()
    await wrapper.vm.poll()
    await wrapper.vm.$nextTick()

    expect(mockGetSessionStats).toHaveBeenCalledWith(42)
    expect(wrapper.text()).toContain('host-a')
    expect(wrapper.text()).toContain('1 天 1 時')
  })

  it('CPU% 與網速由兩次輪詢差分', async () => {
    mockGetSessionStats.mockResolvedValueOnce(sample())
    const wrapper = mountPanel()
    await wrapper.vm.poll()

    // 第二次：busy +50 / total +100 → 50%；rx +4096 bytes / 2s → 2048 B/s
    mockGetSessionStats.mockResolvedValueOnce(
      sample({ cpu_busy: 150, cpu_total: 1100, net_rx_bytes: 14096 })
    )
    await wrapper.vm.poll()

    expect(wrapper.vm.cpuPercent).toBeCloseTo(50)
    expect(wrapper.vm.rxRate).toBeCloseTo(2048)
  })

  it('start 啟動 2s 輪詢、stop 停止', async () => {
    mockGetSessionStats.mockResolvedValue(sample())
    const wrapper = mountPanel()

    wrapper.vm.start()
    await vi.advanceTimersByTimeAsync(4100)
    const calls = mockGetSessionStats.mock.calls.length
    expect(calls).toBeGreaterThanOrEqual(3) // 立即 1 次 + 2 次 interval

    wrapper.vm.stop()
    await vi.advanceTimersByTimeAsync(4000)
    expect(mockGetSessionStats.mock.calls.length).toBe(calls)
  })

  it('API 錯誤顯示後端訊息', async () => {
    mockGetSessionStats.mockRejectedValue({
      response: { data: { error: '目標主機不支援指標採集' } },
    })
    const wrapper = mountPanel()
    await wrapper.vm.poll()
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('目標主機不支援指標採集')
  })
})
