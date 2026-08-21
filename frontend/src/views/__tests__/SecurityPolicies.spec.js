import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SecurityPolicies from '../SecurityPolicies.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const getPoliciesMock = vi.fn()
const updatePoliciesMock = vi.fn()

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
}))

// 頁面掛載即載入 syslog 設定；本檔只驗政策流，syslog 細節見
// SecurityPoliciesLogRetention.spec.js
const getSyslogMock = vi.fn()
vi.mock('@/api/syslogSettings', () => ({
  getSyslogSettings: (...args) => getSyslogMock(...args),
  updateSyslogSettings: vi.fn(),
  testSyslogSettings: vi.fn(),
}))

const policyFixture = (overrides = {}) => ({
  data: [
    {
      key: 'lockout_max_attempts',
      type: 'int',
      default: '10',
      pci_value: '10',
      direction: 'max',
      zero_disables: true,
      requirement: '8.3.4',
      label: '登入失敗鎖定次數上限',
      unit: '次',
      value: '10',
      compliant: true,
    },
    {
      key: 'password_min_length',
      type: 'int',
      default: '12',
      pci_value: '12',
      direction: 'min',
      requirement: '8.3.6',
      label: '密碼最小長度',
      unit: '字元',
      value: '8',
      compliant: false,
    },
    {
      key: 'force_change_on_reset',
      type: 'bool',
      default: 'true',
      pci_value: 'true',
      requirement: '8.3.5',
      label: '管理員重設後強制改密',
      value: 'true',
      compliant: true,
    },
  ],
  deviation_count: 1,
  ...overrides,
})

const mountPage = async () => {
  const wrapper = mount(SecurityPolicies, {
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

describe('SecurityPolicies', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
    getSyslogMock.mockResolvedValue({
      data: {
        dropped: 0,
        setting: {
          enabled: false,
          host: '',
          port: 514,
          protocol: 'udp',
          tls_ca: '',
        },
      },
    })
  })

  it('renders sections with policy metadata and deviation summary', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('與 PCI 建議偏離 1 項')
    expect(wrapper.text()).toContain('登入與鎖定')
    expect(wrapper.text()).toContain('密碼政策')
    expect(wrapper.text()).toContain('登入失敗鎖定次數上限')
    expect(wrapper.text()).toContain('PCI 8.3.4')
    // 0=停用 sentinel 提示
    expect(wrapper.text()).toContain('0 = 停用')
  })

  it('marks non-compliant values with a visible warning tag', async () => {
    const wrapper = await mountPage()

    // password_min_length=8 劣於建議 12：標示不只靠顏色，含文字
    expect(wrapper.text()).toContain('不符 PCI 建議')
  })

  it('applies all PCI values into the form pending save', async () => {
    const wrapper = await mountPage()

    const applyBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('套用本頁建議值'))
    await applyBtn.trigger('click')
    await flushPromises()

    // 一鍵套用只填表單，出現未儲存標示，須按儲存生效
    expect(wrapper.text()).toContain('有未儲存變更')
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })

  it('saves only changed keys as strings', async () => {
    updatePoliciesMock.mockResolvedValue(
      policyFixture({ deviation_count: 0 })
    )
    const wrapper = await mountPage()

    const applyBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('套用本頁建議值'))
    await applyBtn.trigger('click')

    const saveBtn = wrapper
      .findAll('button')
      .find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    // 只送有變更的鍵（僅 password_min_length 8→12）
    expect(updatePoliciesMock).toHaveBeenCalledWith({
      password_min_length: '12',
    })
  })

  it('母頁總覽：分域偏離合計＝全系統總數，未歸域鍵計入本頁', async () => {
    // D5 一致性：後端 deviation_count（compliant=false 全鍵計數）＝分域列表合計；
    // 未歸任何域的新鍵 fallback 到本頁計數（domainDeviations 的 assigned 排除邏輯）
    getPoliciesMock.mockResolvedValue({
      data: [
        { key: 'password_min_length', type: 'int', pci_value: '12', direction: 'min', label: '密碼最小長度', unit: '字元', value: '8', compliant: false },
        { key: 'access_policy_default', type: 'enum', enum_order: ['open', 'reason', 'approval'], pci_value: 'approval', label: '全域預設', value: 'open', compliant: false },
        { key: 'transport_rdp_level', type: 'enum', enum_order: ['off', 'warn', 'strict'], pci_value: 'warn', label: 'RDP 等級', value: 'off', compliant: false },
        { key: 'key_cryptoperiod_reminder_days', type: 'int', pci_value: '365', direction: 'min', zero_disables: true, label: '提醒天數', unit: '天', value: '0', compliant: false },
        { key: 'future_unassigned_key', type: 'bool', pci_value: 'true', label: '未歸域新鍵', value: 'false', compliant: false },
      ],
      deviation_count: 5,
    })
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('全系統與 PCI 建議偏離 5 項')
    // 分域合計 2+1+1+1 = 5 = 全系統總數
    expect(wrapper.text()).toContain('本頁 2 項')
    expect(wrapper.text()).toContain('存取管控 1 項')
    expect(wrapper.text()).toContain('傳輸安全 1 項')
    expect(wrapper.text()).toContain('金鑰管理 1 項')
    // 未歸域鍵落本頁「其他」區塊（不靜默消失）
    expect(wrapper.text()).toContain('未歸域新鍵')
  })

  it('reset restores saved values and clears dirty state', async () => {
    const wrapper = await mountPage()

    const applyBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('套用本頁建議值'))
    await applyBtn.trigger('click')
    expect(wrapper.text()).toContain('有未儲存變更')

    const resetBtn = wrapper
      .findAll('button')
      .find((b) => b.text() === '還原')
    await resetBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).not.toContain('有未儲存變更')
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })
})
