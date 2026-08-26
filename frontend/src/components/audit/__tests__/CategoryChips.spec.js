import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CategoryChips from '../CategoryChips.vue'
import { TIMELINE_TYPES } from '../timelineSummary'

// 類別篩選列（原左欄 CategoryPanel 的替代形態，版面資訊層級規格）。
//
// 換載體時最容易掉的是**語義**而不是像素：一顆 chip 同時承載開關、筆數、
// 覆蓋狀態徽章，三者少一個就會讓「0 筆」在三種完全不同的成因之間失去分辨。
// 本檔逐條守住那三件事，外加「關掉的類別不報 0」這條誠實邊界。
//
// popover 的內容是惰性渲染的（要 hover 才進 DOM）。stub 讓 reference 與內容
// 同時渲染——本檔守的是「說明句還在、掛在正確的 chip 上、清除區間的查核
// 動作沒消失」；「不常駐佔版面」是版面命題，由 Playwright 量測把關。

enableAutoUnmount(afterEach)

const COVERAGE = [
  {
    type: 'audit_log',
    state: 'purged',
    policy_days: 90,
    last_purge_at: '2026-08-10T03:00:00+08:00',
    partial: true,
    checkpoint_seq_range: { from: 3, to: 8 },
  },
  { type: 'clipboard', state: 'not_retained' },
  { type: 'session', state: 'present' },
  { type: 'command', state: 'present' },
  { type: 'file_transfer', state: 'present' },
  { type: 'alert', state: 'present' },
]

const COUNTS = {
  session: 4,
  command: 1,
  audit_log: 1,
  alert: 1,
  clipboard: 0,
  file_transfer: 0,
}

const mountChips = (modelValue = [...TIMELINE_TYPES]) =>
  mount(CategoryChips, {
    props: { modelValue, counts: COUNTS, coverage: COVERAGE },
    global: {
      plugins: [ElementPlus],
      stubs: {
        'el-popover': { template: '<div><slot name="reference" /><slot /></div>' },
      },
    },
  })

describe('CategoryChips 選取', () => {
  it('六類各一顆 chip，開啟中的以 aria-pressed 標示（開關兩態要一眼分得出）', () => {
    const wrapper = mountChips(['session', 'command'])
    TIMELINE_TYPES.forEach((type) => {
      expect(wrapper.find(`[data-test="category-${type}"]`).exists()).toBe(true)
    })
    expect(wrapper.find('[data-test="category-session"]').attributes('aria-pressed')).toBe(
      'true'
    )
    expect(wrapper.find('[data-test="category-clipboard"]').attributes('aria-pressed')).toBe(
      'false'
    )
    expect(wrapper.find('[data-test="category-session"]').classes()).toContain('is-on')
  })

  it('點開啟中的 chip → 該類退出選取；點關閉的 chip → 加回來', async () => {
    const wrapper = mountChips(['session', 'command'])
    await wrapper.find('[data-test="category-command"]').trigger('click')
    expect(wrapper.emitted('update:modelValue').at(-1)[0]).toEqual(['session'])

    await wrapper.find('[data-test="category-clipboard"]').trigger('click')
    expect(wrapper.emitted('update:modelValue').at(-1)[0]).toEqual([
      'session',
      'command',
      'clipboard',
    ])
  })

  it('選取結果依固定值域排序（同一組選擇的 URL types 參數恆等，可比對）', async () => {
    const wrapper = mountChips(['alert', 'session'])
    await wrapper.find('[data-test="category-command"]').trigger('click')
    // 值域順序 session → command → audit_log → file_transfer → clipboard → alert
    expect(wrapper.emitted('update:modelValue').at(-1)[0]).toEqual([
      'session',
      'command',
      'alert',
    ])
  })

  it('全選／全不選各給一顆，全不選後明示「一類都沒開」', async () => {
    const wrapper = mountChips([])
    expect(wrapper.find('[data-test="all-off-hint"]').exists()).toBe(true)

    await wrapper.find('[data-test="select-all"]').trigger('click')
    expect(wrapper.emitted('update:modelValue').at(-1)[0]).toEqual([...TIMELINE_TYPES])

    await wrapper.find('[data-test="clear-all"]').trigger('click')
    expect(wrapper.emitted('update:modelValue').at(-1)[0]).toEqual([])
  })
})

describe('CategoryChips 計數與覆蓋狀態', () => {
  it('開啟中的類別報實際筆數，並在同一顆 chip 上給覆蓋狀態徽章', () => {
    const wrapper = mountChips()
    expect(wrapper.find('[data-test="count-command"]').text()).toBe('1')
    expect(wrapper.find('[data-test="count-file_transfer"]').text()).toBe('0')
    // 徽章一律帶著限定：脫掉限定的「已清除」會被掃徽章的稽核讀成「證據被刪」
    expect(wrapper.find('[data-test="coverage-badge-audit_log"]').text()).toBe('依政策清除')
    expect(wrapper.find('[data-test="coverage-badge-clipboard"]').text()).toBe('未曾清除')
    expect(wrapper.find('[data-test="coverage-badge-session"]').text()).toBe('保留期內')
  })

  it('關閉的類別不報 0 筆也不報覆蓋狀態（沒查過不等於沒發生）', () => {
    const wrapper = mountChips(['session', 'command'])
    expect(wrapper.find('[data-test="count-clipboard"]').text()).toBe('—')
    expect(wrapper.find('[data-test="coverage-badge-clipboard"]').text()).toBe('未納入查詢')
    // 沒查過的類別上不得出現任何「清除／未清除」的斷言——那是無中生有
    const detail = wrapper.find('[data-test="chip-detail-clipboard"]').text()
    expect(detail).toContain('沒有納入查詢')
    expect(detail).toContain('沒查過不等於沒發生')
    expect(detail).not.toContain('不在自動清除的對象內')
  })

  it('三種需要標記的空白各自帶完整說明句，且沿用原 coverage 標記 id', () => {
    const wrapper = mountChips()
    const purged = wrapper.find('[data-test="coverage-purged-audit_log"]')
    expect(purged.text()).toContain('依保留政策清除')
    expect(purged.text()).toContain('保留 90 天')
    expect(purged.text()).toContain('清除作業還在進行中')
    expect(purged.text()).not.toContain('已全部刪除')

    expect(wrapper.find('[data-test="coverage-not_retained-clipboard"]').text()).toContain(
      '不在自動清除的對象內'
    )
    expect(wrapper.find('[data-test="coverage-present-file_transfer"]').text()).toContain(
      '此區間無紀錄'
    )
    // present 且有資料不加噪音：不掛 coverage 標記，只報筆數
    expect(wrapper.find('[data-test="coverage-present-command"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="chip-detail-command"]').exists()).toBe(true)
  })

  it('清除區間的檢查點查核入口沒有隨 alert 一起退場（說明可收起，動作不可）', async () => {
    const wrapper = mountChips()
    const link = wrapper.find('[data-test="checkpoint-link-audit_log"]')
    expect(link.exists()).toBe(true)
    await link.trigger('click')
    expect(wrapper.emitted('open-checkpoint').at(-1)[0]).toEqual({ from: 3, to: 8 })
    // 其餘類別沒有區間可查，不掛空連結
    expect(wrapper.find('[data-test="checkpoint-link-clipboard"]').exists()).toBe(false)
  })
})
