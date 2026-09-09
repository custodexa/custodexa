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

const previewComplianceMock = vi.fn()
const previewApplyMock = vi.fn()

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
  // 判定與套用預覽端點：判定一律由後端供給，前端不自己算一份
  previewCompliance: (...args) => previewComplianceMock(...args),
  previewApplyPolicies: (...args) => previewApplyMock(...args),
}))

// 頁面掛載即載入 syslog 設定；本檔只驗政策流，syslog 細節見
// SecurityPoliciesLogRetention.spec.js
const getSyslogMock = vi.fn()
vi.mock('@/api/syslogSettings', () => ({
  getSyslogSettings: (...args) => getSyslogMock(...args),
  updateSyslogSettings: vi.fn(),
  testSyslogSettings: vi.fn(),
}))

// 判定由後端建構：前端只投影，不自己算一份
const verdict = (key, result, expected, comparator = 'min') => ({
  key,
  group_code: 'pci_dss_4_0_1',
  clause_no: '8.3.6',
  result,
  reason: result === 'deviating' ? 'below_minimum' : 'meets_expectation',
  current: '8',
  expected,
  comparator,
})

const policyFixture = (overrides = {}) => ({
  data: [
    {
      key: 'lockout_max_attempts',
      type: 'int',
      default: '10',
      direction: 'max',
      zero_disables: true,
      label: '登入失敗鎖定次數上限',
      unit: '次',
      value: '10',
      verdicts: [verdict('lockout_max_attempts', 'compliant', '10', 'max')],
    },
    {
      key: 'password_min_length',
      type: 'int',
      default: '12',
      direction: 'min',
      label: '密碼最小長度',
      unit: '字元',
      value: '8',
      verdicts: [verdict('password_min_length', 'deviating', '12')],
    },
    {
      key: 'force_change_on_reset',
      type: 'bool',
      default: 'true',
      label: '管理員重設後強制改密',
      value: 'true',
      verdicts: [verdict('force_change_on_reset', 'compliant', 'true', 'equals')],
    },
  ],
  groups: [{ code: 'pci_dss_4_0_1', name: 'PCI DSS 4.0.1', enabled: true }],
  ...overrides,
})

// 套用政策建議值：後端算出的變動清單（此處只有密碼最小長度要改）
const applyPreviewFixture = () => ({
  mode: 'strictest',
  changes: [
    { key: 'password_min_length', current: '8', proposed: '12', source_group: 'pci_dss_4_0_1' },
  ],
  conflicts: [],
  unchanged_count: 2,
  unmapped_count: 0,
})

const mountPage = async () => {
  const wrapper = mount(SecurityPolicies, {
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

// 頁首列送出套用模式 → 預覽對話框確認 → 值只進表單（儲存仍要另按）
const applyRecommended = async (wrapper) => {
  wrapper.findComponent({ name: 'PolicyGroupStrip' }).vm.$emit('apply', { mode: 'strictest' })
  await flushPromises()
  const dialog = wrapper.findComponent({ name: 'ApplyPreviewDialog' })
  dialog.vm.$emit('confirm', dialog.props('preview').changes)
  await flushPromises()
}

describe('SecurityPolicies', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
    previewComplianceMock.mockResolvedValue({ data: { draft: true, verdicts: [] } })
    previewApplyMock.mockResolvedValue({ data: applyPreviewFixture() })
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

  it('分區列出政策鍵並以判定推導偏離數，生效組列在頁首', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('登入與鎖定')
    expect(wrapper.text()).toContain('密碼政策')
    expect(wrapper.text()).toContain('登入失敗鎖定次數上限')
    // 密碼政策區一個偏離鍵、登入與鎖定區零個
    expect(wrapper.find('[data-test="section-deviation-password"]').text()).toBe('偏離 1 項')
    expect(wrapper.find('[data-test="section-deviation-login_lock"]').text()).toBe('無偏離項目')
    // 頁首列說出現在對照的是哪幾組
    expect(wrapper.text()).toContain('目前對照的政策組')
    expect(wrapper.find('[data-test="strip-group-pci_dss_4_0_1"]').text()).toBe('PCI DSS 4.0.1')
  })

  it('偏離的鍵有琥珀點與文字提示，第一層不寫條號與建議值', async () => {
    const wrapper = await mountPage()

    const dot = wrapper.find('[data-test="policy-deviation-password_min_length"]')
    expect(dot.exists()).toBe(true)
    expect(dot.attributes('title')).toContain('政策組')
    // 符合的鍵不長點
    expect(wrapper.find('[data-test="policy-deviation-force_change_on_reset"]').exists()).toBe(
      false
    )
    wrapper.findAll('.policy-row').forEach((row) => {
      expect(row.text()).not.toContain('8.3.4')
      expect(row.text()).not.toContain('PCI')
    })
  })

  it('套用政策建議值只填表單，須按儲存才生效', async () => {
    const wrapper = await mountPage()

    await applyRecommended(wrapper)

    expect(previewApplyMock).toHaveBeenCalledWith({
      scope: expect.arrayContaining(['password_min_length']),
      mode: 'strictest',
      group_code: '',
      draft: {},
    })
    expect(wrapper.text()).toContain('有未儲存變更')
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })

  it('saves only changed keys as strings', async () => {
    updatePoliciesMock.mockResolvedValue(
      policyFixture()
    )
    const wrapper = await mountPage()

    await applyRecommended(wrapper)

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

  it('本頁只承載安全域鍵，未歸域的新鍵落「其他」區塊不靜默消失', async () => {
    getPoliciesMock.mockResolvedValue({
      data: [
        { key: 'password_min_length', type: 'int', label: '密碼最小長度', unit: '字元', value: '8', verdicts: [verdict('password_min_length', 'deviating', '12')] },
        { key: 'access_policy_default', type: 'enum', enum_order: ['open', 'reason', 'approval'], label: '全域預設', value: 'open', verdicts: [] },
        { key: 'transport_rdp_level', type: 'enum', enum_order: ['off', 'warn', 'strict'], label: 'RDP 等級', value: 'off', verdicts: [] },
        { key: 'future_unassigned_key', type: 'bool', label: '未歸域新鍵', value: 'false', verdicts: [] },
      ],
      groups: [{ code: 'pci_dss_4_0_1', name: 'PCI DSS 4.0.1', enabled: true }],
    })
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('未歸域新鍵')
    // 其他域的鍵在各自頁面呈現，不在本頁
    expect(wrapper.text()).not.toContain('RDP 等級')
    expect(wrapper.text()).not.toContain('全域預設')
  })

  it('reset restores saved values and clears dirty state', async () => {
    const wrapper = await mountPage()

    await applyRecommended(wrapper)
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
    // 第一層只有標籤、控制項與資訊鈕：沒有建議值可讓一鍵套用把明文部署翻掉
    expect(row.text()).not.toContain('PCI')
    expect(row.text()).not.toContain('建議')
    expect(row.text()).not.toContain('電支')
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
