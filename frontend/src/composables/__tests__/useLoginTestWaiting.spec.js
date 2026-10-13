import { describe, it, expect, vi, afterEach } from 'vitest'
import { useLoginTestWaiting, WAIT_POLL_MS, WAIT_MAX_MS } from '../useLoginTestWaiting'

describe('useLoginTestWaiting', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('重抓失敗時輪詢不中斷，也不留下未處理的 rejection，最後照常逾時', async () => {
    vi.useFakeTimers()
    const unhandled = vi.fn()
    process.on('unhandledRejection', unhandled)
    try {
      let clock = 0
      const fetch = vi.fn().mockRejectedValue(new Error('network'))
      const waiting = useLoginTestWaiting({
        fetch,
        current: () => null,
        now: () => clock,
      })

      waiting.arm()
      expect(waiting.onReturn()).toBe(true)
      expect(waiting.state.value).toBe('waiting')

      await vi.advanceTimersByTimeAsync(0)
      expect(fetch).toHaveBeenCalledTimes(1)

      clock += WAIT_POLL_MS
      await vi.advanceTimersByTimeAsync(WAIT_POLL_MS)
      expect(fetch).toHaveBeenCalledTimes(2)
      expect(waiting.state.value).toBe('waiting')

      clock += WAIT_MAX_MS
      await vi.advanceTimersByTimeAsync(WAIT_POLL_MS)
      expect(waiting.state.value).toBe('timeout')

      await vi.advanceTimersByTimeAsync(WAIT_MAX_MS)
      expect(fetch).toHaveBeenCalledTimes(3)
      vi.useRealTimers()
      await new Promise((resolve) => setTimeout(resolve, 0))
      expect(unhandled).not.toHaveBeenCalled()
    } finally {
      process.off('unhandledRejection', unhandled)
    }
  })
})
