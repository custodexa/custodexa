import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import PolicyKeySections from '../PolicyKeySections.vue'

// 逐測卸載：殘留元件會讓後續測試耗時隨序累積
enableAutoUnmount(afterEach)

const drawerStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="drawer-stub"><slot /></div>',
}

const RouterLinkStub = {
  props: ['to'],
  template: '<a class="router-link-stub"><slot /></a>',
}

const PASSWORD = {
  key: 'password_min_length',
  type: 'int',
  label: '密碼最小長度',
  unit: '字元',
  min: 1,
  max: 128,
}
const HISTORY = {
  key: 'password_history_count',
  type: 'int',
  label: '禁止重用最近密碼筆數',
  unit: '筆',
  min: 0,
  max: 24,
}

const deviating = (key, group) => ({
  key,
  group_code: group,
  clause_no: '8.3.6',
  result: 'deviating',
  reason: 'below_minimum',
  current: '8',
  expected: '12',
  comparator: 'min',
})

const mountSections = (props = {}) =>
  mount(PolicyKeySections, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-drawer': drawerStub, RouterLink: RouterLinkStub, 'router-link': RouterLinkStub },
    },
    props: {
      sections: [
        { id: 'password', title: '密碼政策', hint: '提示', policies: [PASSWORD, HISTORY] },
      ],
      formValues: { password_min_length: 8, password_history_count: 4 },
      verdictsByKey: {},
      groupNames: { pci_dss_4_0_1: 'PCI DSS 4.0.1', epayment_baseline: '電支基準' },
      ...props,
    },
  })

describe('PolicyKeySections — 分區偏離數', () => {
  it('沒有偏離時說的是「無偏離項目」，不是「全部符合」', () => {
    // 沒有偏離不等於全部符合：待稽核判讀、待人工確認與未對照的鍵都在這一區裡，
    // 它們都還沒有人說符合
    const wrapper = mountSections()
    expect(wrapper.find('[data-test="section-deviation-password"]').text()).toBe('無偏離項目')
  })

  it('同一鍵偏離兩組只算一次，且點數字到合規對照頁', () => {
    const wrapper = mountSections({
      verdictsByKey: {
        password_min_length: [
          deviating('password_min_length', 'pci_dss_4_0_1'),
          deviating('password_min_length', 'epayment_baseline'),
        ],
      },
    })

    const link = wrapper.find('[data-test="section-deviation-password"]')
    expect(link.text()).toBe('偏離 1 項')
    expect(wrapper.findComponent(RouterLinkStub).props('to')).toBe('/compliance-map')
  })

  it('偏離的鍵在列上有標示，未偏離的沒有', () => {
    const wrapper = mountSections({
      verdictsByKey: {
        password_min_length: [deviating('password_min_length', 'pci_dss_4_0_1')],
        password_history_count: [
          { key: 'password_history_count', group_code: 'pci_dss_4_0_1', result: 'compliant' },
        ],
      },
    })

    expect(wrapper.find('[data-test="policy-deviation-password_min_length"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="policy-deviation-password_history_count"]').exists()).toBe(
      false
    )
  })

  it('草稿判定要標示為草稿', () => {
    expect(mountSections().text()).not.toContain('草稿')
    expect(mountSections({ draft: true }).text()).toContain('草稿')
  })
})

describe('PolicyKeySections — 第一層與抽屜', () => {
  it('未展開任何抽屜時，畫面上沒有條號、建議值與不符文字', () => {
    const wrapper = mountSections({
      verdictsByKey: {
        password_min_length: [deviating('password_min_length', 'pci_dss_4_0_1')],
      },
    })

    const text = wrapper.text()
    expect(text).toContain('密碼最小長度')
    expect(text).not.toContain('8.3.6')
    expect(text).not.toContain('PCI')
    expect(text).not.toContain('建議')
    expect(text).not.toContain('不符')
  })

  it('點資訊鈕開抽屜，帶的是該鍵的判定', async () => {
    const wrapper = mountSections({
      verdictsByKey: {
        password_min_length: [deviating('password_min_length', 'pci_dss_4_0_1')],
      },
    })

    expect(wrapper.find('.drawer-stub').exists()).toBe(false)
    await wrapper.find('[data-test="policy-info-password_min_length"]').trigger('click')

    const drawer = wrapper.findComponent({ name: 'PolicyKeyDrawer' })
    expect(drawer.props('policy').key).toBe('password_min_length')
    expect(drawer.props('verdicts')).toHaveLength(1)
    expect(wrapper.find('.drawer-stub').text()).toContain('PCI DSS 4.0.1')
  })

  it('編輯控制項時把鍵與新值上拋父層', () => {
    const wrapper = mountSections()
    wrapper
      .findAllComponents({ name: 'ElInputNumber' })[0]
      .vm.$emit('update:modelValue', 14)
    expect(wrapper.emitted('update:value')).toContainEqual(['password_min_length', 14])
  })

  it('兩個具名插槽仍供頁面掛專屬內容', () => {
    const wrapper = mount(PolicyKeySections, {
      global: {
        plugins: [ElementPlus],
        stubs: { 'el-drawer': drawerStub, RouterLink: RouterLinkStub, 'router-link': RouterLinkStub },
      },
      props: {
        sections: [{ id: 'password', title: '密碼政策', hint: '', policies: [PASSWORD] }],
        formValues: { password_min_length: 8 },
      },
      slots: {
        'section-extra': '<p class="extra-slot">區塊補充</p>',
        'section-footer': '<p class="footer-slot">區塊尾端</p>',
      },
    })

    expect(wrapper.find('.extra-slot').exists()).toBe(true)
    expect(wrapper.find('.footer-slot').exists()).toBe(true)
  })
})
