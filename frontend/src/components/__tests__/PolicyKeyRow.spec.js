import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import PolicyKeyRow from '../PolicyKeyRow.vue'

// 逐測卸載：殘留元件會讓後續測試耗時隨序累積
enableAutoUnmount(afterEach)

const INT_POLICY = {
  key: 'lockout_max_attempts',
  type: 'int',
  label: '登入失敗鎖定次數上限',
  unit: '次',
  min: 1,
  max: 100,
  // 過渡期後端仍回的規範欄位：第一層不得因為拿得到就把它們畫出來
}

const TITLE_POLICY = {
  key: 'login_banner_title',
  type: 'text',
  label: '登入告示標題',
  max_length: 120,
}

// multiline 在後端帶 omitempty：單行鍵的回應根本不會有這個欄位
const BODY_POLICY = {
  key: 'login_banner_body',
  type: 'text',
  label: '登入告示內文',
  max_length: 2000,
  multiline: true,
}

const mountRow = (policy, value, extra = {}) =>
  mount(PolicyKeyRow, {
    global: { plugins: [ElementPlus] },
    props: { policy, value, ...extra },
  })

describe('PolicyKeyRow — 第一層只有設定本身', () => {
  it('只渲染標籤、控制項、單位與資訊鈕，DOM 內無條號、建議值與不符文字', () => {
    const wrapper = mountRow(INT_POLICY, 10, {
      deviating: true,
      verdicts: [
        {
          key: 'lockout_max_attempts',
          group_code: 'pci_dss_4_0_1',
          clause_no: '8.3.4',
          result: 'deviating',
          reason: 'above_maximum',
          current: '10',
          expected: '6',
          comparator: 'max',
        },
      ],
    })

    const text = wrapper.text()
    expect(text).toContain('登入失敗鎖定次數上限')
    expect(text).toContain('次')
    // 條號、建議值、不符字樣一律不在第一層
    expect(text).not.toContain('8.3.4')
    expect(text).not.toContain('PCI')
    expect(text).not.toContain('建議')
    expect(text).not.toContain('不符')
    expect(text).not.toContain('電支')
    // 抽屜入口是唯一的第二層去處
    expect(wrapper.find('[data-test="policy-info-lockout_max_attempts"]').exists()).toBe(true)
  })

  it('偏離鍵有琥珀點且帶文字提示（不只靠顏色）', () => {
    const wrapper = mountRow(INT_POLICY, 10, { deviating: true })

    const dot = wrapper.find('[data-test="policy-deviation-lockout_max_attempts"]')
    expect(dot.exists()).toBe(true)
    expect(dot.classes()).toContain('policy-deviation-dot')
    // title 與 aria-label 都要有字：色盲、灰階列印與螢幕報讀各走一條路
    expect(dot.attributes('title')).toBeTruthy()
    expect(dot.attributes('title')).toContain('政策組')
    expect(dot.attributes('aria-label')).toBe(dot.attributes('title'))
  })

  it('未偏離的鍵不長點', () => {
    const wrapper = mountRow(INT_POLICY, 5, { deviating: false })
    expect(wrapper.find('[data-test="policy-deviation-lockout_max_attempts"]').exists()).toBe(false)
  })

  it('點資訊鈕上拋 info（開抽屜的權在父層）', async () => {
    const wrapper = mountRow(INT_POLICY, 10)
    await wrapper.find('[data-test="policy-info-lockout_max_attempts"]').trigger('click')
    expect(wrapper.emitted('info')).toHaveLength(1)
  })
})

describe('PolicyKeyRow — 控制項', () => {
  it('int 型以數字輸入框呈現並上拋鍵與新值', () => {
    const wrapper = mountRow(INT_POLICY, 10)
    wrapper.findComponent({ name: 'ElInputNumber' }).vm.$emit('update:modelValue', 7)
    expect(wrapper.emitted('update:value')).toContainEqual(['lockout_max_attempts', 7])
  })

  it('bool 型以開關呈現並帶 aria-label', () => {
    const wrapper = mountRow(
      { key: 'break_glass_enabled', type: 'bool', label: '破窗緊急連線' },
      false
    )
    const sw = wrapper.findComponent({ name: 'ElSwitch' })
    expect(sw.props('ariaLabel')).toBe('破窗緊急連線')
    sw.vm.$emit('update:modelValue', true)
    expect(wrapper.emitted('update:value')).toContainEqual(['break_glass_enabled', true])
  })

  it('enum 型逐段列出且用白話段位文案', () => {
    const wrapper = mountRow(
      {
        key: 'access_policy_default',
        type: 'enum',
        label: '全域預設存取政策段位',
        enum_order: ['open', 'reason', 'approval'],
      },
      'open'
    )
    expect(wrapper.findAllComponents({ name: 'ElRadioButton' })).toHaveLength(3)
    expect(wrapper.text()).toContain('不需申請')
  })
})

describe('PolicyKeyRow — 文字型鍵', () => {
  it('多行鍵給 textarea，單行鍵給一般輸入框', () => {
    const title = mountRow(TITLE_POLICY, '授權使用者專用')
    const body = mountRow(BODY_POLICY, '第一行\n第二行')

    expect(title.find('textarea').exists()).toBe(false)
    expect(title.find('input').element.value).toBe('授權使用者專用')
    expect(body.find('textarea').element.value).toBe('第一行\n第二行')
    expect(body.find('.policy-row-text').exists()).toBe(true)
  })

  it('不綁原生 maxlength（那是 UTF-16 計數，會在後端仍接受的長度截斷輸入）', () => {
    expect(mountRow(TITLE_POLICY, '標題').find('input').attributes('maxlength')).toBeUndefined()
    expect(
      mountRow(BODY_POLICY, '內文').find('textarea').attributes('maxlength')
    ).toBeUndefined()
  })

  it('字數以 code point 計：2000 個補充平面字元顯示 2000 / 2000', () => {
    const body = '\u{1F600}'.repeat(2000)
    expect(body.length).toBe(4000)

    const counter = mountRow(BODY_POLICY, body).find('.policy-counter')
    expect(counter.text()).toBe('2000 / 2000')
    expect(counter.classes()).not.toContain('policy-counter-over')
  })

  it('超過上限時計數變色，輸入不被截斷', () => {
    const wrapper = mountRow(BODY_POLICY, '字'.repeat(2001))

    const counter = wrapper.find('.policy-counter')
    expect(counter.text()).toBe('2001 / 2000')
    expect(counter.classes()).toContain('policy-counter-over')
    expect(wrapper.find('textarea').element.value).toHaveLength(2001)
  })

  it('編輯輸入框時以 update:value 上拋鍵與新值', async () => {
    const wrapper = mountRow(BODY_POLICY, '舊內文')
    await wrapper.find('textarea').setValue('新內文')
    expect(wrapper.emitted('update:value')).toContainEqual(['login_banner_body', '新內文'])
  })
})
