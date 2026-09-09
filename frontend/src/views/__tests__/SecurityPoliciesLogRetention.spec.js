import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElSelect, ElMessageBox } from 'element-plus'
import SecurityPolicies from '../SecurityPolicies.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// 日誌保留與審閱區塊 + syslog 轉發設定卡

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

const getSyslogMock = vi.fn()
const updateSyslogMock = vi.fn()
const testSyslogMock = vi.fn()

vi.mock('@/api/syslogSettings', () => ({
  getSyslogSettings: (...args) => getSyslogMock(...args),
  updateSyslogSettings: (...args) => updateSyslogMock(...args),
  testSyslogSettings: (...args) => testSyslogMock(...args),
}))

// 判定由後端建構，前端只投影：deviating 的鍵才會有琥珀點與分區偏離數
const verdict = (key, result, expected, comparator = 'min') => ({
  key,
  group_code: 'pci_dss_4_0_1',
  clause_no: '10.5.1',
  result,
  reason: result === 'deviating' ? 'below_minimum' : 'meets_expectation',
  current: '0',
  expected,
  comparator,
})

const retentionInt = (key, label, value) => ({
  key,
  type: 'int',
  default: '0',
  direction: 'min',
  zero_disables: true,
  max: 3650,
  label,
  unit: '天',
  value,
  verdicts: [verdict(key, 'deviating', '365')],
})

// fixture 依 live GET /api/v1/security-policies 實際回傳（2026-07-13 驗證）
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
    retentionInt('retention_audit_log_days', '操作日誌保留天數', '0'),
    retentionInt('retention_session_command_days', '指令流保留天數', '0'),
    retentionInt('retention_alert_days', '告警記錄保留天數', '0'),
    retentionInt('retention_recording_days', '連線錄影保留天數', '90'),
    {
      key: 'daily_review_enabled',
      type: 'bool',
      default: 'false',
      label: '每日審閱簽核',
      value: 'false',
      verdicts: [verdict('daily_review_enabled', 'deviating', 'true', 'equals')],
    },
    {
      key: 'failure_alert_enabled',
      type: 'bool',
      default: 'false',
      label: '稽核失效告警通知',
      value: 'false',
      verdicts: [verdict('failure_alert_enabled', 'deviating', 'true', 'equals')],
    },
  ],
  groups: [{ code: 'pci_dss_4_0_1', name: 'PCI DSS 4.0.1', enabled: true }],
  ...overrides,
})

const syslogFixture = (overrides = {}) => ({
  data: {
    dropped: 0,
    setting: {
      enabled: false,
      host: '',
      port: 514,
      protocol: 'udp',
      tls_ca: '',
      updated_by: '',
      updated_at: '0001-01-01T00:00:00Z',
    },
    ...overrides,
  },
})

// 一次滿足所有政策的預覽：後端算好的變動清單，前端只負責填進表單
const APPLY_CHANGES = [
  { key: 'retention_audit_log_days', current: '0', proposed: '365', source_group: 'pci_dss_4_0_1' },
  { key: 'retention_session_command_days', current: '0', proposed: '365', source_group: 'pci_dss_4_0_1' },
  { key: 'retention_alert_days', current: '0', proposed: '365', source_group: 'pci_dss_4_0_1' },
  { key: 'retention_recording_days', current: '90', proposed: '365', source_group: 'pci_dss_4_0_1' },
  { key: 'daily_review_enabled', current: 'false', proposed: 'true', source_group: 'pci_dss_4_0_1' },
  { key: 'failure_alert_enabled', current: 'false', proposed: 'true', source_group: 'pci_dss_4_0_1' },
]

const applyPreviewFixture = () => ({
  mode: 'strictest',
  changes: APPLY_CHANGES.map((c) => ({ ...c })),
  conflicts: [],
  unchanged_count: 1,
  unmapped_count: 0,
})

// 套用政策建議值：頁首列送出模式 → 預覽對話框確認 → 值只進表單
const applyRecommended = async (wrapper) => {
  wrapper.findComponent({ name: 'PolicyGroupStrip' }).vm.$emit('apply', { mode: 'strictest' })
  await flushPromises()
  wrapper
    .findComponent({ name: 'ApplyPreviewDialog' })
    .vm.$emit('confirm', wrapper.findComponent({ name: 'ApplyPreviewDialog' }).props('preview').changes)
  await flushPromises()
}

const mountPage = async () => {
  const wrapper = mount(SecurityPolicies, {
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

const findSyslogButton = (wrapper, text) =>
  wrapper
    .find('.syslog-card')
    .findAll('button')
    .find((b) => b.text().includes(text))

describe('SecurityPolicies 日誌保留與審閱區塊', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
    getSyslogMock.mockResolvedValue(syslogFixture())
    previewComplianceMock.mockResolvedValue({ data: { draft: true, verdicts: [] } })
    previewApplyMock.mockResolvedValue({ data: applyPreviewFixture() })
    // 保留收縮確認預設放行；收縮測試個別覆寫為取消
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
  })

  it('六個保留與審閱鍵都在，分區偏離數由判定推導', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('日誌保留與審閱')
    expect(wrapper.text()).toContain('操作日誌保留天數')
    expect(wrapper.text()).toContain('指令流保留天數')
    expect(wrapper.text()).toContain('告警記錄保留天數')
    expect(wrapper.text()).toContain('連線錄影保留天數')
    expect(wrapper.text()).toContain('每日審閱簽核')
    expect(wrapper.text()).toContain('稽核失效告警通知')
    // 六個鍵各有一筆 deviating 判定
    expect(wrapper.text()).toContain('偏離 6 項')
    // 條號與建議值只在抽屜裡：設定列上一個字都沒有
    //（區塊標題與提示的措辭是文案波的射程，不在本斷言內）
    wrapper.findAll('.policy-row').forEach((row) => {
      expect(row.text()).not.toContain('10.5.1')
      expect(row.text()).not.toContain('PCI')
      expect(row.text()).not.toContain('建議')
    })
  })

  it('套用政策建議值填入 365／true，儲存以字串送出', async () => {
    updatePoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()

    await applyRecommended(wrapper)

    const saveBtn = wrapper
      .findAll('button')
      .find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    // lockout 已合規不送；四保留鍵 365、兩開關 true
    expect(updatePoliciesMock).toHaveBeenCalledWith({
      retention_audit_log_days: '365',
      retention_session_command_days: '365',
      retention_alert_days: '365',
      retention_recording_days: '365',
      daily_review_enabled: 'true',
      failure_alert_enabled: 'true',
    })
    // 0（永久）→365 屬收縮，須先過保留清除確認
    expect(ElMessageBox.confirm).toHaveBeenCalledWith(
      expect.stringContaining('永久清除'),
      expect.stringContaining('保留期限縮短'),
      expect.any(Object)
    )
  })

  it('保留收縮取消確認時中止儲存，不送出任何政策', async () => {
    ElMessageBox.confirm.mockRejectedValue('cancel')
    const wrapper = await mountPage()

    await applyRecommended(wrapper)

    const saveBtn = wrapper.findAll('button').find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(ElMessageBox.confirm).toHaveBeenCalled()
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })

  it('放寬保留（365→永久0）不觸發收縮確認', async () => {
    // 既有 365 天，改為 0（永久保留）＝放寬，不應攔截
    getPoliciesMock.mockResolvedValue(
      policyFixture({
        data: [retentionInt('retention_audit_log_days', '操作日誌保留天數', '365')],
      })
    )
    updatePoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()

    const input = wrapper.find('input')
    await input.setValue('0')
    const saveBtn = wrapper.findAll('button').find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(ElMessageBox.confirm).not.toHaveBeenCalled()
    expect(updatePoliciesMock).toHaveBeenCalledWith({ retention_audit_log_days: '0' })
  })
})

describe('SecurityPolicies syslog 轉發設定卡', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
    getSyslogMock.mockResolvedValue(syslogFixture())
  })

  it('renders card from GET and hides TLS CA unless protocol is tcp+tls', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('syslog 日誌轉發')
    // 卡片說明留協定出處（RFC），規範條號退到鍵的抽屜
    expect(wrapper.text()).toContain('RFC 5424')
    expect(wrapper.text()).not.toContain('PCI 10.3.3')
    // udp 時不顯示 TLS CA textarea
    expect(wrapper.find('.syslog-card textarea').exists()).toBe(false)

    // 切到 tcp+tls 才顯示 TLS CA（含 PEM/系統信任庫說明）
    const select = wrapper.findComponent(ElSelect)
    select.vm.$emit('update:modelValue', 'tcp+tls')
    await flushPromises()

    const textarea = wrapper.find('.syslog-card textarea')
    expect(textarea.exists()).toBe(true)
    expect(textarea.attributes('placeholder')).toContain('PEM')

    // 切回 udp 再隱藏
    select.vm.$emit('update:modelValue', 'udp')
    await flushPromises()
    expect(wrapper.find('.syslog-card textarea').exists()).toBe(false)
  })

  it('shows dropped warning tag when buffer overflowed', async () => {
    getSyslogMock.mockResolvedValue(syslogFixture({ dropped: 7 }))
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('已丟棄 7 筆（緩衝溢出）')
  })

  it('test button reports success and failure with reason', async () => {
    testSyslogMock.mockResolvedValue({ data: { success: true } })
    const wrapper = await mountPage()

    const testBtn = findSyslogButton(wrapper, '發送測試訊息')
    await testBtn.trigger('click')
    await flushPromises()

    // 測試與存檔同受傳輸政策閘：帶 risk_acknowledged、關全域 toast 自行呈現
    expect(testSyslogMock).toHaveBeenCalledWith(
      {
        enabled: false,
        host: '',
        port: 514,
        protocol: 'udp',
        tls_ca: '',
        risk_acknowledged: false,
      },
      { skipErrorToast: true }
    )
    expect(wrapper.text()).toContain('測試訊息已發送')

    // 失敗改由 502＋registered code 表達：
    // 不再是 200＋{success:false}＋後端原始錯誤字串；UI 顯示前端查譯的泛化訊息
    const err = new Error('HTTP 502')
    err.response = {
      status: 502,
      data: { error: '後端 zh fallback', code: 'INTERNAL_SYSLOG_TEST_FAILED' },
    }
    testSyslogMock.mockRejectedValue(err)
    await testBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('syslog 測試訊息傳送失敗')
    expect(wrapper.text()).not.toContain('測試訊息已發送')
    // 泛化：不得回頭顯示 dial/timeout 之類的原始錯誤
    expect(wrapper.text()).not.toContain('dial tcp')
  })

  it('saves syslog form via dedicated API with current values', async () => {
    updateSyslogMock.mockResolvedValue({
      data: {
        enabled: false,
        host: 'siem.example.com',
        port: 514,
        protocol: 'udp',
        tls_ca: '',
      },
    })
    const wrapper = await mountPage()

    const hostInput = wrapper.find('.syslog-card input[placeholder*="siem"]')
    await hostInput.setValue('siem.example.com')

    const saveBtn = findSyslogButton(wrapper, '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    // 存檔走傳輸政策確認流程：帶 risk_acknowledged、關全域 toast 自行呈現
    expect(updateSyslogMock).toHaveBeenCalledWith(
      {
        enabled: false,
        host: 'siem.example.com',
        port: 514,
        protocol: 'udp',
        tls_ca: '',
        risk_acknowledged: false,
      },
      { skipErrorToast: true }
    )
    // 政策儲存流不受 syslog 卡影響
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })

  it('keeps form and surfaces rejection when backend blocks invalid save', async () => {
    // 啟用但 host 空：後端 400（訊息由全域攔截器 toast），表單不清空、不誤報成功
    updateSyslogMock.mockRejectedValue({
      response: { status: 400, data: { error: '啟用轉發時 host 不可為空' } },
    })
    const wrapper = await mountPage()

    const enableSwitch = wrapper.find('.syslog-card .el-switch')
    await enableSwitch.trigger('click')

    const saveBtn = findSyslogButton(wrapper, '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(updateSyslogMock).toHaveBeenCalledWith(
      expect.objectContaining({ enabled: true, host: '' }),
      { skipErrorToast: true }
    )
    // 失敗後儲存按鈕退出 loading，可再次修正送出
    expect(saveBtn.attributes('disabled')).toBeUndefined()
  })
})
