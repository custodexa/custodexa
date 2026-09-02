import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import PolicyKeySections from '../PolicyKeySections.vue'

// 逐測卸載：殘留元件會讓後續測試耗時隨序累積
enableAutoUnmount(afterEach)

const TITLE_POLICY = {
  key: 'login_banner_title',
  type: 'text',
  label: '登入告示標題',
  max_length: 120,
  compliant: null,
  epayment_compliant: null,
}

// multiline 在後端帶 omitempty：單行鍵的回應根本不會有這個欄位
const BODY_POLICY = {
  key: 'login_banner_body',
  type: 'text',
  label: '登入告示內文',
  max_length: 2000,
  multiline: true,
  compliant: null,
  epayment_compliant: null,
}

const INT_POLICY = {
  key: 'lockout_max_attempts',
  type: 'int',
  label: '登入失敗鎖定次數上限',
  min: 1,
  max: 100,
  pci_value: '6',
  compliant: true,
}

const mountSections = (policies, values) =>
  mount(PolicyKeySections, {
    global: { plugins: [ElementPlus] },
    props: {
      sections: [{ title: '登入告示', hint: '提示', policies }],
      formValues: values,
      savedValues: values,
    },
  })

describe('PolicyKeySections — 文字型政策鍵', () => {
  it('多行鍵給 textarea，單行鍵給一般輸入框', () => {
    const wrapper = mountSections([TITLE_POLICY, BODY_POLICY], {
      login_banner_title: '授權使用者專用',
      login_banner_body: '第一行\n第二行',
    })

    const rows = wrapper.findAll('.policy-row-text')
    expect(rows).toHaveLength(2)
    expect(rows[0].find('textarea').exists()).toBe(false)
    expect(rows[0].find('input').element.value).toBe('授權使用者專用')
    expect(rows[1].find('textarea').element.value).toBe('第一行\n第二行')
  })

  it('不綁原生 maxlength（那是 UTF-16 計數，會在後端仍接受的長度截斷輸入）', () => {
    const wrapper = mountSections([TITLE_POLICY, BODY_POLICY], {
      login_banner_title: '標題',
      login_banner_body: '內文',
    })

    expect(wrapper.find('.policy-row-text input').attributes('maxlength')).toBeUndefined()
    expect(wrapper.find('.policy-row-text textarea').attributes('maxlength')).toBeUndefined()
  })

  it('字數以 code point 計：2000 個補充平面字元顯示 2000 / 2000', () => {
    const body = '\u{1F600}'.repeat(2000)
    expect(body.length).toBe(4000)

    const wrapper = mountSections([BODY_POLICY], { login_banner_body: body })
    const counter = wrapper.find('.policy-counter')
    expect(counter.text()).toBe('2000 / 2000')
    expect(counter.classes()).not.toContain('policy-counter-over')
  })

  it('超過上限時計數變色，輸入不被截斷', () => {
    const body = '字'.repeat(2001)
    const wrapper = mountSections([BODY_POLICY], { login_banner_body: body })

    const counter = wrapper.find('.policy-counter')
    expect(counter.text()).toBe('2001 / 2000')
    expect(counter.classes()).toContain('policy-counter-over')
    expect(wrapper.find('textarea').element.value).toHaveLength(2001)
  })

  it('文字型鍵不顯示基準建議值 meta 欄', () => {
    const wrapper = mountSections([BODY_POLICY], { login_banner_body: '內文' })

    expect(wrapper.find('.policy-meta').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('無 PCI 建議值')
  })

  it('非文字型鍵的 meta 欄與控制項不受影響', () => {
    const wrapper = mountSections([INT_POLICY], { lockout_max_attempts: 5 })

    expect(wrapper.find('.policy-row-text').exists()).toBe(false)
    expect(wrapper.find('.policy-meta').exists()).toBe(true)
    expect(wrapper.text()).toContain('PCI 建議')
    expect(wrapper.find('.policy-counter').exists()).toBe(false)
  })

  it('編輯輸入框時以 update:value 上拋鍵與新值', async () => {
    const wrapper = mountSections([BODY_POLICY], { login_banner_body: '舊內文' })

    await wrapper.find('textarea').setValue('新內文')

    expect(wrapper.emitted('update:value')).toContainEqual([
      'login_banner_body',
      '新內文',
    ])
  })
})
