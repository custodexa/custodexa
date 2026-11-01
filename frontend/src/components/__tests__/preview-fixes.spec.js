import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import { nextTick } from 'vue'
import ElementPlus from 'element-plus'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import PreviewDropdownItem from '../PreviewDropdownItem.vue'
import { clampToViewport } from '@/directives/clampViewport'
import { showHintCard, hideHintCard } from '@/utils/previewHintCard'
import i18n from '@/i18n'
import { applyPreviewResponse, beginPreviewRequest, cancelPreview } from '@/composables/useRolePreview'
import { resetCapabilities } from '@/composables/useCapabilities'

enableAutoUnmount(afterEach)
const t = (k) => i18n.global.t(k)

const enter = () => {
  applyPreviewResponse(beginPreviewRequest(), {
    role: { id: 7, name: 'R7' },
    previewable: true,
    permissions: ['asset:view'],
    entry_states: [],
  })
}

beforeEach(() => resetCapabilities())
afterEach(() => {
  cancelPreview()
  hideHintCard()
  document.body.innerHTML = ''
})

describe('下拉選單項目的預覽停用', () => {
  const mountMenu = async () => {
    const onCommand = vi.fn()
    const w = mount(
      {
        components: { PreviewDropdownItem },
        methods: { onCommand },
        template: `
          <el-dropdown ref="dd" :teleported="false" @command="onCommand">
            <span>open</span>
            <template #dropdown>
              <el-dropdown-menu>
                <PreviewDropdownItem command="rename" data-test="item-rename">改名</PreviewDropdownItem>
                <PreviewDropdownItem command="delete" kind="create" data-test="item-delete">刪除</PreviewDropdownItem>
              </el-dropdown-menu>
            </template>
          </el-dropdown>`,
      },
      { global: { plugins: [ElementPlus] }, attachTo: document.body }
    )
    w.vm.$refs.dd.handleOpen()
    await nextTick()
    await nextTick()
    return { w, onCommand }
  }

  it('預覽中項目本身 disabled 並帶說明；離開預覽後恢復', async () => {
    enter()
    const { w } = await mountMenu()
    const items = [...document.querySelectorAll('li.el-dropdown-menu__item')]
    expect(items).toHaveLength(2)
    for (const li of items) {
      expect(li.classList.contains('is-disabled')).toBe(true)
      expect(li.getAttribute('aria-disabled')).toBe('true')
    }
    const fills = [...document.querySelectorAll('.preview-menu-fill')]
    expect(fills[0].getAttribute('aria-description')).toBe(t('rolePreview.disabledAction'))
    expect(fills[1].getAttribute('aria-description')).toBe(t('rolePreview.disabledCreate'))
    cancelPreview()
    await nextTick()
    expect(document.querySelectorAll('li.el-dropdown-menu__item.is-disabled')).toHaveLength(0)
    expect(document.querySelector('.preview-menu-fill').hasAttribute('aria-description')).toBe(false)
    w.unmount()
  })

  it('預覽中點項目不觸發 command；未預覽時照常觸發', async () => {
    enter()
    const first = await mountMenu()
    document.querySelector('li.el-dropdown-menu__item').click()
    document.querySelector('.preview-menu-fill').click()
    await nextTick()
    expect(first.onCommand).not.toHaveBeenCalled()
    first.w.unmount()
    cancelPreview()
    const second = await mountMenu()
    document.querySelector('li.el-dropdown-menu__item').click()
    await nextTick()
    expect(second.onCommand.mock.calls[0][0]).toBe('rename')
  })
})

describe('指令不得掛在非單一根節點的元件上', () => {
  const files = (dir) =>
    readdirSync(dir).flatMap((n) => {
      const p = join(dir, n)
      if (n === 'node_modules' || n === '__tests__') return []
      return statSync(p).isDirectory() ? files(p) : p.endsWith('.vue') ? [p] : []
    })

  it('全部 .vue 裡 v-preview-write 不出現在 el-dropdown-item 上', () => {
    const offenders = []
    for (const f of files('src')) {
      const src = readFileSync(f, 'utf8')
      const re = /<el-dropdown-item\b(?:[^<>"']|"[^"]*"|'[^']*')*?v-preview-write/g
      if (re.test(src)) offenders.push(f)
    }
    expect(offenders).toEqual([])
  })
})

describe('錨定浮層夾在視窗內', () => {
  const rectOf = (left, right) => () => ({ left, right, top: 0, bottom: 20, width: right - left, height: 20 })

  it('左緣跑出視窗：改左對齊並留 8px', () => {
    vi.stubGlobal('innerWidth', 390)
    const parent = document.createElement('div')
    const el = document.createElement('div')
    parent.appendChild(el)
    document.body.appendChild(parent)
    // 右對齊時左緣在 -17；改左對齊後左緣在 4（仍小於 8）
    let mode = 'right'
    el.getBoundingClientRect = () => (mode === 'right' ? rectOf(-17, 303)() : rectOf(4, 324)())
    Object.defineProperty(el, 'offsetParent', { value: parent })
    parent.getBoundingClientRect = rectOf(4, 100)
    const observe = new MutationObserver(() => {})
    observe.disconnect()
    const origSet = el.style.setProperty.bind(el.style)
    el.style.setProperty = (k, v) => {
      if (k === 'left' && v === '0px') mode = 'left'
      origSet(k, v)
    }
    clampToViewport(el)
    expect(el.style.left).toBe(`${8 - 4 + 0}px`)
    vi.unstubAllGlobals()
  })

  it('右緣跑出視窗：往左推到留 8px', () => {
    vi.stubGlobal('innerWidth', 390)
    const el = document.createElement('div')
    document.body.appendChild(el)
    el.getBoundingClientRect = rectOf(100, 400)
    clampToViewport(el)
    // 原本右對齊（right 未指定，視為 0）：位移 -18
    expect(el.style.right).toBe('18px')
    vi.unstubAllGlobals()
  })
})

describe('說明卡定位與讓位', () => {
  const anchorAt = (left, right) => {
    const a = document.createElement('button')
    document.body.appendChild(a)
    a.getBoundingClientRect = () => ({ left, right, top: 100, bottom: 130, width: right - left, height: 30 })
    return a
  }
  beforeEach(() => {
    vi.stubGlobal('innerWidth', 1000)
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(200)
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(40)
  })
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('優先與錨點右緣對齊', () => {
    showHintCard(anchorAt(600, 700), { body: 'x' })
    const card = document.querySelector('[data-test="preview-hint-card"]')
    expect(card.style.left).toBe('500px')
  })

  it('右緣對齊會超出左側時，改與錨點左緣對齊；仍放不下則貼邊', () => {
    showHintCard(anchorAt(20, 120), { body: 'x' })
    const card = document.querySelector('[data-test="preview-hint-card"]')
    expect(card.style.left).toBe('20px')
    showHintCard(anchorAt(2, 60), { body: 'x' })
    expect(card.style.left).toBe('8px')
  })

  it('錨點靠右緣：往左推，右邊留 8px', () => {
    showHintCard(anchorAt(900, 1000), { body: 'x' })
    const card = document.querySelector('[data-test="preview-hint-card"]')
    expect(card.style.left).toBe('792px')
  })

  it('有其他浮層展開時不顯示；錨點在該浮層內則照常顯示', () => {
    const popper = document.createElement('div')
    popper.className = 'el-popper'
    document.body.appendChild(popper)
    const outside = anchorAt(100, 200)
    showHintCard(outside, { body: 'x' })
    expect(document.querySelector('[data-test="preview-hint-card"]')?.hidden ?? true).toBe(true)
    const inside = document.createElement('div')
    popper.appendChild(inside)
    inside.getBoundingClientRect = () => ({ left: 100, right: 200, top: 10, bottom: 30, width: 100, height: 20 })
    showHintCard(inside, { body: 'y' })
    expect(document.querySelector('[data-test="preview-hint-card"]').hidden).toBe(false)
    popper.style.display = 'none'
    showHintCard(outside, { body: 'x' })
    expect(document.querySelector('[data-test="preview-hint-card"]').hidden).toBe(false)
  })
})
