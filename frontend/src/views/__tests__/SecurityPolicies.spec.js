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
    // 分域一致性：後端 deviation_count（compliant=false 全鍵計數）＝分域列表合計；
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

// 明文連線的建議提示。
// 兩個事實缺一則提示要嘛漏報（不知生效值，關閉後的健康部署也彈）、
// 要嘛誤報（不知協定，https 部署也彈）——四格逐一釘死
describe('SecurityPolicies — 明文連線建議提示', () => {
  const withRefreshCookieSecure = (value) => {
    const fixture = policyFixture()
    fixture.data.push({
      key: 'refresh_cookie_secure',
      type: 'bool',
      default: 'true',
      label: '登入狀態僅在 https 連線保存',
      value,
      compliant: null,
      epayment_compliant: null,
    })
    return fixture
  }

  beforeEach(() => {
    vi.clearAllMocks()
    window.location.href = 'http://localhost:3000/security-policies'
    getSyslogMock.mockResolvedValue({
      data: {
        dropped: 0,
        setting: { enabled: false, host: '', port: 514, protocol: 'udp', tls_ca: '' },
      },
    })
  })

  it('http + 政策開啟 → 顯示建議，並列出兩條處置路徑', async () => {
    getPoliciesMock.mockResolvedValue(withRefreshCookieSecure('true'))
    const wrapper = await mountPage()

    const alert = wrapper.find('.insecure-transport-alert')
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('使用者每 15 分鐘要重新登入')
    expect(alert.text()).toContain('系統不會自動改這個設定')
    expect(alert.text()).toContain('檢查反向代理的憑證與轉發設定')
    expect(alert.text()).toContain('關閉再儲存')
  })

  // 語氣是建議不是警告。type 錯一格，管理員讀到的就是「系統壞了」
  // 而不是「你有兩個選擇」
  it('語氣是建議：el-alert type=info，不是 warning／error', async () => {
    getPoliciesMock.mockResolvedValue(withRefreshCookieSecure('true'))
    const wrapper = await mountPage()

    const alert = wrapper
      .findAllComponents({ name: 'ElAlert' })
      .find((c) => c.classes().includes('insecure-transport-alert'))
    expect(alert.props('type')).toBe('info')
  })

  // 系統不得自動改設定。提示只指向同頁的開關，決定權在管理員——
  // 載入頁面本身不得產生任何寫入
  it('顯示提示不觸發任何寫入（系統不自動改設定）', async () => {
    getPoliciesMock.mockResolvedValue(withRefreshCookieSecure('true'))
    const wrapper = await mountPage()

    expect(wrapper.find('.insecure-transport-alert').exists()).toBe(true)
    expect(updatePoliciesMock).not.toHaveBeenCalled()
    // 開關維持後端回來的值，未被前端翻動
    expect(wrapper.text()).not.toContain('有未儲存變更')
  })

  it('提示指向本頁的開關，該政策項確實渲染在 Web 會話區塊', async () => {
    getPoliciesMock.mockResolvedValue(withRefreshCookieSecure('true'))
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('登入狀態僅在 https 連線保存')
    const labelled = wrapper
      .findAllComponents({ name: 'ElSwitch' })
      .filter((c) => c.props('ariaLabel') === '登入狀態僅在 https 連線保存')
    expect(labelled.length, '該政策項應以 bool 開關呈現').toBe(1)
    // 本鍵不掛 PCI／電支建議值：掛了會讓「套用本頁建議值」把明文部署翻成
    // 整站續期失敗。斷言限於本鍵那一列——同頁其他鍵是有建議值的
    const row = wrapper
      .findAll('.policy-row')
      .find((r) => r.text().includes('登入狀態僅在 https 連線保存'))
    expect(row.text()).toContain('無 PCI 建議值')
    expect(row.text()).not.toContain('PCI 建議：')
    expect(row.text()).not.toContain('電支基準：')
  })

  it('http + 政策已關閉 → 不顯示（健康的明文部署不該被打擾）', async () => {
    getPoliciesMock.mockResolvedValue(withRefreshCookieSecure('false'))
    const wrapper = await mountPage()

    expect(wrapper.find('.insecure-transport-alert').exists()).toBe(false)
  })

  it('https 頁面 → 不顯示（協定沒問題）', async () => {
    window.location.href = 'https://console.example.test/security-policies'
    getPoliciesMock.mockResolvedValue(withRefreshCookieSecure('true'))
    const wrapper = await mountPage()

    expect(wrapper.find('.insecure-transport-alert').exists()).toBe(false)
  })

  it('回應查無該鍵（舊後端）→ 不顯示且不報錯', async () => {
    getPoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()

    expect(wrapper.find('.insecure-transport-alert').exists()).toBe(false)
    expect(wrapper.text()).toContain('登入失敗鎖定次數上限')
  })
})
