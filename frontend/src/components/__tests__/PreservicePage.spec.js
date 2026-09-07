import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import PreservicePage from '../PreservicePage.vue'

// 服務前頁面（解封頁、守衛攔下頁）的共同兩欄版面。
//
// 這組守衛盯的是版面的三個契約，缺一就回到改版前的痛點：
// 1. 左欄承載狀態、右欄承載唯一動作，兩者互不推擠；
// 2. 左欄在**文件順序**上先於右欄（i18n spec 的遺失警語版位以 DOM 序判定，
//    不以「畫面上看得到」為通過依據）；
// 3. 窄視窗摺為單欄時左欄仍在前——摺欄以 CSS 實作，happy-dom 不套用樣式，
//    故此條打在樣式表本體（規則存在且未以 order 改寫順序）。

enableAutoUnmount(afterEach)

const SOURCE = readFileSync(
  join(process.cwd(), 'src/components/PreservicePage.vue'),
  'utf8'
)

const mountPage = (props = {}) =>
  mount(PreservicePage, {
    props,
    slots: {
      lang: '<div class="probe-lang">語言</div>',
      left: '<p class="probe-left">狀態內容</p>',
      right: '<p class="probe-right">動作內容</p>',
    },
    global: { plugins: [ElementPlus] },
  })

describe('PreservicePage 版位', () => {
  it('左右兩個 slot 各自渲染於自己的欄', () => {
    const wrapper = mountPage()

    expect(wrapper.find('.preservice-left .probe-left').exists()).toBe(true)
    expect(wrapper.find('.preservice-right .probe-right').exists()).toBe(true)
    // 交叉否證：內容沒有落到另一欄（單看「存在」無法分辨兩欄是否其實是同一個容器）
    expect(wrapper.find('.preservice-left .probe-right').exists()).toBe(false)
    expect(wrapper.find('.preservice-right .probe-left').exists()).toBe(false)
  })

  it('語言切換 slot 有獨立版位（封印期本頁是唯一可達頁，缺切換即卡人）', () => {
    const wrapper = mountPage()
    expect(wrapper.find('.preservice-lang .probe-lang').exists()).toBe(true)
  })

  it('左欄在文件順序上先於右欄', () => {
    const html = mountPage().html()
    expect(html.indexOf('probe-left')).toBeGreaterThan(-1)
    expect(html.indexOf('probe-left')).toBeLessThan(html.indexOf('probe-right'))
  })

  it('右欄可掛外部 class（頁面自己的測試錨點與狀態旗標）', () => {
    const wrapper = mountPage({ rightClass: ['unseal-card', 'is-initialization'] })
    const right = wrapper.find('.preservice-right')
    expect(right.classes()).toContain('unseal-card')
    expect(right.classes()).toContain('is-initialization')
  })

  it('tone=danger 時右欄套危險外框，預設不套', () => {
    expect(mountPage().find('.preservice-right').classes()).not.toContain('is-danger')
    expect(mountPage({ tone: 'danger' }).find('.preservice-right').classes()).toContain(
      'is-danger'
    )
  })
})

describe('PreservicePage 狀態訊息的固定版位', () => {
  const MESSAGES = [
    { key: 'a', tone: 'danger', title: '故障', text: '細節' },
    {
      key: 'b',
      tone: 'warning',
      title: '稽核不可寫',
      text: '依序處理：',
      steps: ['查空間', '查權限', '重啟'],
      note: '留不下紀錄就不受理。',
    },
  ]

  it('訊息渲染於左欄，且右欄不受影響', () => {
    const quiet = mountPage()
    const quietRight = quiet.find('.preservice-right').html()

    const noisy = mountPage({ messages: MESSAGES })
    expect(noisy.findAll('.preservice-left .status-message')).toHaveLength(2)
    expect(noisy.find('.preservice-right').html()).toBe(quietRight)
  })

  it('逐則帶語意色，步驟與尾註完整渲染', () => {
    const wrapper = mountPage({ messages: MESSAGES })
    const [first, second] = wrapper.findAll('.status-message')

    expect(first.classes()).toContain('is-danger')
    expect(first.text()).toContain('故障')
    expect(second.classes()).toContain('is-warning')
    expect(second.findAll('.status-message-steps li').map((li) => li.text())).toEqual([
      '查空間',
      '查權限',
      '重啟',
    ])
    expect(second.find('.status-message-note').text()).toBe('留不下紀錄就不受理。')
  })

  it('沒有訊息時版位仍在但不佔空間', () => {
    const wrapper = mountPage()
    const slot = wrapper.find('.status-messages')
    expect(slot.exists()).toBe(true)
    expect(slot.element.children).toHaveLength(0)
    // :empty 規則負責讓空版位不佔空間——規則消失即無守衛，故一併釘住
    expect(SOURCE).toMatch(/\.status-messages:empty\s*\{[^}]*display:\s*none/)
  })
})

describe('PreservicePage 摺欄（樣式契約）', () => {
  it('寬度不足時摺為單欄', () => {
    // 媒體查詢區塊：自 @media 起至行首的收尾大括號（內層規則縮排，故不會提早收束）
    const media = SOURCE.match(/@media[^{]*\(max-width:\s*900px\)[^{]*\{[\s\S]*?\n\}/)
    expect(media, '缺少 900px 摺欄的媒體查詢').toBeTruthy()
    expect(media[0]).toMatch(/grid-template-columns:\s*(1fr|minmax\(0,\s*1fr\))\s*;/)
  })

  it('並排時左欄 5 欄、右欄 7 欄', () => {
    expect(SOURCE).toMatch(/\.preservice-left\s*\{[^}]*grid-column:\s*span 5/)
    expect(SOURCE).toMatch(/\.preservice-right\s*\{[^}]*grid-column:\s*span 7/)
  })

  it('樣式未以 order 改寫欄序（摺單欄後左欄仍在前）', () => {
    expect(SOURCE).not.toMatch(/^\s*order:/m)
  })

  it('不寫死色值，只用 token 或 Element Plus 變數', () => {
    const style = SOURCE.slice(SOURCE.indexOf('<style'))
    const literals = style.match(/#[0-9a-fA-F]{3,8}\b|\brgba?\(\s*\d/g) || []
    expect(literals, `樣式出現寫死色值：${literals.join(', ')}`).toEqual([])
  })
})
