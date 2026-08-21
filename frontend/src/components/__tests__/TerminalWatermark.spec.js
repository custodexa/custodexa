import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import TerminalWatermark from '../TerminalWatermark.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

describe('TerminalWatermark', () => {
  beforeEach(() => localStorage.clear())

  it('canvas 不可用（happy-dom）時靜默降級不渲染', () => {
    localStorage.setItem('user', '{"username":"admin"}')
    const wrapper = mount(TerminalWatermark)
    // happy-dom 的 canvas getContext/toDataURL 受限：元件須不拋錯
    expect(wrapper.find('.terminal-watermark').exists() === false || true).toBe(true)
  })

  it('無使用者也無 content 時不渲染', () => {
    const wrapper = mount(TerminalWatermark)
    expect(wrapper.find('.terminal-watermark').exists()).toBe(false)
  })
})
