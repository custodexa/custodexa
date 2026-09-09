import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import PolicyKeyDrawer from '../PolicyKeyDrawer.vue'

// 逐測卸載：殘留元件會讓後續測試耗時隨序累積
enableAutoUnmount(afterEach)

// el-drawer teleport 到 body，happy-dom 下 wrapper 撈不到——就地渲染的替身保留預設插槽
const drawerStub = {
  props: ['modelValue', 'title'],
  template: '<div v-if="modelValue" class="drawer-stub"><h3>{{ title }}</h3><slot /></div>',
}

const RouterLinkStub = {
  props: ['to'],
  template: '<a class="router-link-stub"><slot /></a>',
}

const POLICY = {
  key: 'password_min_length',
  type: 'int',
  label: '密碼最小長度',
  unit: '字元',
  unit_key: 'chars',
  min: 1,
  max: 128,
  value: '8',
  updated_by: 'admin',
  updated_at: '2026-09-08T02:30:12Z',
}

const verdict = (over = {}) => ({
  key: 'password_min_length',
  group_code: 'pci_dss_4_0_1',
  clause_no: '8.3.6',
  result: 'compliant',
  reason: 'meets_expectation',
  current: '12',
  expected: '12',
  comparator: 'min',
  ...over,
})

const mountDrawer = (props = {}) =>
  mount(PolicyKeyDrawer, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-drawer': drawerStub, RouterLink: RouterLinkStub, 'router-link': RouterLinkStub },
    },
    props: {
      modelValue: true,
      policy: POLICY,
      verdicts: [verdict()],
      groupNames: { pci_dss_4_0_1: 'PCI DSS 4.0.1', epayment_baseline: '支付基準組' },
      ...props,
    },
  })

describe('PolicyKeyDrawer — 對各生效組的一行人話', () => {
  it('符合：說出要求與結果，條號退為列尾小字', () => {
    const wrapper = mountDrawer()

    const line = wrapper.find('[data-test="requirement-pci_dss_4_0_1"]')
    expect(line.text()).toContain('PCI DSS 4.0.1')
    expect(line.text()).toContain('至少 12 字元')
    expect(line.text()).toContain('符合')
    // 條號在，但只是列尾小字
    expect(line.find('.clause-no').text()).toContain('8.3.6')
  })

  it('偏離：說出目前值與未達要求', () => {
    const wrapper = mountDrawer({
      verdicts: [verdict({ result: 'deviating', reason: 'below_minimum', current: '8' })],
    })

    const line = wrapper.find('[data-test="requirement-pci_dss_4_0_1"]')
    expect(line.text()).toContain('至少 12 字元')
    expect(line.text()).toContain('8 字元')
    expect(line.text()).toContain('未達要求')
  })

  it('待人工確認：標出參考值與是否已由機構確認', () => {
    const unconfirmed = mountDrawer({
      verdicts: [
        verdict({
          result: 'needs_review',
          reason: 'reference_value_unconfirmed',
          expected: '90',
        }),
      ],
    })
    expect(unconfirmed.text()).toContain('參考值')
    expect(unconfirmed.text()).toContain('尚未由機構確認')

    const confirmed = mountDrawer({
      verdicts: [
        verdict({
          result: 'needs_review',
          reason: 'reference_value_confirmed',
          expected: '90',
          confirmed_by: 'admin',
          confirmed_at: '2026-09-01T01:00:00Z',
        }),
      ],
    })
    expect(confirmed.text()).toContain('機構已於')
    expect(confirmed.text()).toContain('admin')
  })

  it('待稽核判讀：不判符合或偏離，附目前值', () => {
    const wrapper = mountDrawer({
      verdicts: [
        verdict({
          group_code: 'epayment_baseline',
          clause_no: '21-6',
          result: 'review',
          reason: 'expectation_unspecified',
          expected: '',
          comparator: 'review',
          current: 'warn',
        }),
      ],
    })

    const line = wrapper.find('[data-test="requirement-epayment_baseline"]')
    expect(line.text()).toContain('支付基準組')
    expect(line.text()).toContain('沒有定值')
    expect(line.text()).toContain('由稽核人員判讀')
    expect(line.text()).not.toContain('符合')
  })

  it('未對照的組不列；一組都沒有時說明沒有政策組對照到', () => {
    const wrapper = mountDrawer({
      verdicts: [verdict({ group_code: '', clause_no: '', result: 'unmapped', reason: 'no_control' })],
    })

    expect(wrapper.findAll('.requirement-line')).toHaveLength(0)
    expect(wrapper.text()).toContain('沒有生效的政策組對照到這個設定')
  })

  it('草稿判定要標示，與已儲存值可區分', () => {
    expect(mountDrawer({ draft: true }).text()).toContain('尚未儲存')
    expect(mountDrawer({ draft: false }).text()).not.toContain('尚未儲存')
  })
})

describe('PolicyKeyDrawer — 抽屜其餘四段', () => {
  it('白話一句只在 policyPlain.<key> 有譯文時出現，沒有譯文的鍵不留空白行', () => {
    // 白話句只給標籤本身不自明的鍵；標籤已白話者不補，首行直接從對各組的要求開始
    const withPlain = mountDrawer({
      policy: { ...POLICY, key: 'retention_checkpoint_days', label: '檢查點保留天數', unit: '天', unit_key: 'days' },
      verdicts: [],
    })
    expect(withPlain.find('.drawer-plain').exists()).toBe(true)
    expect(withPlain.find('.drawer-plain').text()).toBe('用來查核紀錄的證明留幾天。')

    expect(mountDrawer().find('.drawer-plain').exists()).toBe(false)
  })

  it('最後變更帶時間與操作者，記錄連結帶資源與鍵的篩選參數', () => {
    const wrapper = mountDrawer()

    const lastChange = wrapper.find('.drawer-last-change')
    expect(lastChange.text()).toContain('admin')
    expect(lastChange.text()).toContain('2026')

    const link = wrapper.findComponent(RouterLinkStub)
    expect(link.props('to')).toMatchObject({
      path: '/audit-logs',
      query: { resource: 'security_policy', key: 'password_min_length' },
    })
  })

  it('從未變更過的鍵說明維持出廠預設，不假裝有一筆變更', () => {
    const wrapper = mountDrawer({
      policy: { ...POLICY, updated_by: '', updated_at: null },
    })
    expect(wrapper.find('.drawer-last-change').text()).toContain('出廠預設')
  })

  it('什麼時候生效取 policyEffect.<key>', () => {
    expect(mountDrawer().find('.drawer-effect').text()).toContain('改密碼時擋下')
  })

  it('更多說明沿用既有的 policyNote.<key> 原文，且是摺疊的', () => {
    const wrapper = mountDrawer({
      policy: { ...POLICY, key: 'audit_checkpoint_interval_seconds', type: 'int', label: '檢查點封存週期' },
      verdicts: [],
    })

    const collapse = wrapper.findComponent({ name: 'ElCollapse' })
    expect(collapse.exists()).toBe(true)
    expect(collapse.text()).toContain('更多說明')
  })

  it('沒有 policyNote 譯文的鍵不長出摺疊區', () => {
    expect(mountDrawer().findComponent({ name: 'ElCollapse' }).exists()).toBe(false)
  })
})
