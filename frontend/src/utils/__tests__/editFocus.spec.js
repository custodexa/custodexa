import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { applyEditFocus } from '@/utils/editFocus'
import { EDIT_FOCUS_TARGETS } from '@/constants/assetExecutor'

// 深連結落點流程。落點表擴充一列（含 focus 欄）不需改流程。

let root
beforeEach(() => {
  vi.useFakeTimers()
  root = document.createElement('div')
  document.body.appendChild(root)
  Element.prototype.scrollIntoView = vi.fn()
})
afterEach(() => {
  vi.useRealTimers()
  root.remove()
})

const add = (html) => {
  const wrap = document.createElement('div')
  wrap.innerHTML = html
  root.appendChild(wrap.firstElementChild)
}

describe('EditFocusTargets', () => {
  it('未帶 focus 捲到主機金鑰（既有行為）', async () => {
    add('<div class="host-key-item"></div>')
    await applyEditFocus({ targets: EDIT_FOCUS_TARGETS, key: '', isOpen: () => true, root })
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1)
  })

  it('focus=executor 捲到專用帳號區塊；未知值退回主機金鑰', async () => {
    add('<div class="host-key-item"></div>')
    add('<div data-focus="executor"></div>')
    // 此列只驗捲動落點；聚焦目標（區塊標題）不在這個 DOM 內，不等它出現
    await applyEditFocus({ targets: EDIT_FOCUS_TARGETS, key: 'executor', isOpen: () => true, root, focusTimeout: 0 })
    expect(Element.prototype.scrollIntoView.mock.instances.at(-1).getAttribute('data-focus')).toBe('executor')
    await applyEditFocus({ targets: EDIT_FOCUS_TARGETS, key: 'nope', isOpen: () => true, root })
    expect(Element.prototype.scrollIntoView.mock.instances.at(-1).className).toBe('host-key-item')
  })

  it('深連結聚焦時要求畫出焦點框（focusVisible）', async () => {
    add('<div data-focus="executor"><h3 tabindex="-1" data-test="executor-title">t</h3></div>')
    const title = root.querySelector('[data-test="executor-title"]')
    const spy = vi.spyOn(title, 'focus')
    await applyEditFocus({ targets: EDIT_FOCUS_TARGETS, key: 'executor', isOpen: () => true, root })
    expect(spy).toHaveBeenCalledWith({ focusVisible: true })
    expect(document.activeElement).toBe(title)
  })

  it('聚焦目標晚 500ms 才進 DOM 時仍被聚焦', async () => {
    add('<div data-focus="executor"></div>')
    const targets = { 'host-key': { scroll: '.host-key-item' }, probe: { scroll: '[data-focus="executor"]', focus: '#late' } }
    const p = applyEditFocus({ targets, key: 'probe', isOpen: () => true, root })
    await vi.advanceTimersByTimeAsync(500)
    add('<button id="late"></button>')
    await vi.advanceTimersByTimeAsync(10)
    await p
    expect(document.activeElement.id).toBe('late')
  })

  it('目標始終不出現時逾時只捲動、不聚焦', async () => {
    add('<div data-focus="executor"></div>')
    const targets = { 'host-key': { scroll: '.host-key-item' }, probe: { scroll: '[data-focus="executor"]', focus: '#never' } }
    const p = applyEditFocus({ targets, key: 'probe', isOpen: () => true, root })
    await vi.advanceTimersByTimeAsync(3500)
    await p
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1)
  })

  it('等待期間抽屜被關閉則不聚焦', async () => {
    add('<div data-focus="executor"></div>')
    let open = true
    const targets = { 'host-key': { scroll: '.host-key-item' }, probe: { scroll: '[data-focus="executor"]', focus: '#late2' } }
    const p = applyEditFocus({ targets, key: 'probe', isOpen: () => open, root })
    await vi.advanceTimersByTimeAsync(200)
    open = false
    add('<button id="late2"></button>')
    await vi.advanceTimersByTimeAsync(10)
    await p
    expect(document.activeElement.id).not.toBe('late2')
  })
})
