import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import SecurityPolicies from '../SecurityPolicies.vue'
import AccessControl from '../AccessControl.vue'
import OffsiteStorage from '../OffsiteStorage.vue'
import KeyManagement from '../KeyManagement.vue'
import SyslogForwardCard from '@/components/SyslogForwardCard.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 資料保留四鍵的下限（合法值域 {0} ∪ [7, 3650]）與「記錄並建立系統告警」的通知字樣。
// 守的是兩件事：輸入 1–6 時欄位當下報錯、儲存鈕停用且不夾值；
// 各處通知句只說「記錄並建立系統告警，送達取決於通知通道」，不暗示已有人被通知。

enableAutoUnmount(afterEach)
afterEach(() => resetCapabilities())

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getPoliciesMock = vi.fn()
const updatePoliciesMock = vi.fn()
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getPoliciesMock(...a),
  updateSecurityPolicies: (...a) => updatePoliciesMock(...a),
  previewCompliance: vi.fn().mockResolvedValue({ data: { draft: true, verdicts: [] } }),
  previewApplyPolicies: vi.fn().mockResolvedValue({
    data: { mode: 'strictest', changes: [], conflicts: [], unchanged_count: 0, unmapped_count: 0 },
  }),
}))

const getSyslogMock = vi.fn()
vi.mock('@/api/syslogSettings', () => ({
  getSyslogSettings: (...a) => getSyslogMock(...a),
  updateSyslogSettings: vi.fn(),
  testSyslogSettings: vi.fn(),
}))

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  updateAsset: vi.fn(),
}))
vi.mock('@/utils/accessPolicyDowngradeConfirm', () => ({
  confirmAccessPolicyDowngrade: vi.fn().mockResolvedValue('confirm'),
}))

const getInventoryMock = vi.fn()
const getTopologyMock = vi.fn()
vi.mock('@/api/keys', () => ({
  getKeyInventory: (...a) => getInventoryMock(...a),
  getKEKTopology: (...a) => getTopologyMock(...a),
  updateKEKTopology: vi.fn(),
  rotateKey: vi.fn(),
  rewrapKEK: vi.fn(),
  abandonRewrap: vi.fn(),
  cleanupRetiredMaterial: vi.fn(),
}))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))

const statusMock = vi.fn()
vi.mock('@/api/offsiteStorage', () => ({
  getOffsiteStatus: (...a) => statusMock(...a),
  getOffsiteFailures: vi.fn().mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 }),
  testOffsiteConnection: vi.fn(),
  retryOffsiteFailed: vi.fn(),
  retryOffsiteObject: vi.fn(),
  getOffsiteSettings: vi.fn(),
  saveOffsiteSettings: vi.fn(),
  confirmOffsiteGenerationSwitch: vi.fn(),
  disableOffsiteStorage: vi.fn(),
  listOffsiteProfiles: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  revokeOffsiteProfileCredentials: vi.fn(),
}))

const DATA_KEYS = [
  ['retention_audit_log_days', '操作日誌保留天數'],
  ['retention_session_command_days', '指令流保留天數'],
  ['retention_alert_days', '告警記錄保留天數'],
  ['retention_recording_days', '連線錄影保留天數'],
]

const retentionInt = (key, label, value) => ({
  key,
  type: 'int',
  default: '0',
  direction: 'min',
  zero_disables: true,
  min: 7,
  max: 3650,
  label,
  unit: '天',
  value,
})

const policyFixture = (values = {}) => ({
  data: [
    ...DATA_KEYS.map(([key, label]) => retentionInt(key, label, values[key] ?? '365')),
    {
      key: 'retention_checkpoint_days',
      type: 'int',
      default: '0',
      zero_disables: true,
      max: 3650,
      label: '檢查點保留天數',
      unit: '天',
      value: values.retention_checkpoint_days ?? '0',
    },
    {
      key: 'recording_failclose_enabled',
      type: 'bool',
      default: 'false',
      label: '錄影故障時阻擋連線',
      value: 'false',
    },
  ],
  groups: [],
})

const mountPolicies = async (values) => {
  getPoliciesMock.mockResolvedValue(policyFixture(values))
  const wrapper = mount(SecurityPolicies, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

const saveButton = (wrapper) => wrapper.findAll('button').find((b) => b.text() === '儲存')

// 找到某政策列的數字輸入框
const rowInput = (wrapper, label) => {
  const row = wrapper.findAll('.policy-row').find((r) => r.text().includes(label))
  return row.find('input')
}

const NOTICE_PARTS = ['建立系統告警', '取決於通知通道']
const FORBIDDEN = ['通知安全人員', '已通知']
const expectNotice = (text) => {
  NOTICE_PARTS.forEach((s) => expect(text).toContain(s))
  FORBIDDEN.forEach((s) => expect(text).not.toContain(s))
}

describe('資料保留四鍵的下限', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getSyslogMock.mockResolvedValue({
      data: { dropped: 0, setting: { enabled: false, host: '', port: 514, protocol: 'udp', tls_ca: '' } },
    })
    updatePoliciesMock.mockResolvedValue(policyFixture())
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
  })

  it('四欄常駐顯示下限提示', async () => {
    const wrapper = await mountPolicies()
    DATA_KEYS.forEach(([key]) => {
      const hint = wrapper.find(`[data-test="retention-floor-hint-${key}"]`)
      expect(hint.exists()).toBe(true)
      expect(hint.text()).toBe('最少 7 天，填 0 表示永久保留')
    })
    // 檢查點保留沒有資料保留的下限
    expect(wrapper.find('[data-test="retention-floor-hint-retention_checkpoint_days"]').exists()).toBe(false)
  })

  it.each(DATA_KEYS)('%s 輸入 3：欄位報錯、儲存停用、欄位值仍是 3', async (key, label) => {
    const wrapper = await mountPolicies()
    const input = rowInput(wrapper, label)
    await input.setValue('3')
    await flushPromises()

    const err = wrapper.find(`[data-test="retention-floor-error-${key}"]`)
    expect(err.exists()).toBe(true)
    expect(err.text()).toBe('不能少於 7 天（填 0 表示永久保留）')
    expect(wrapper.find(`[data-test="retention-floor-hint-${key}"]`).exists()).toBe(false)
    expect(saveButton(wrapper).attributes('disabled')).toBeDefined()
    expect(rowInput(wrapper, label).element.value).toBe('3')

    await saveButton(wrapper).trigger('click')
    await flushPromises()
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })

  it.each(DATA_KEYS)('%s 輸入 0 與 7：無錯誤、儲存可用', async (key, label) => {
    const wrapper = await mountPolicies()
    for (const v of ['0', '7']) {
      await rowInput(wrapper, label).setValue(v)
      await flushPromises()
      expect(wrapper.find(`[data-test="retention-floor-error-${key}"]`).exists()).toBe(false)
      expect(wrapper.find(`[data-test="retention-floor-hint-${key}"]`).exists()).toBe(true)
      expect(saveButton(wrapper).attributes('disabled')).toBeUndefined()
    }
  })

  it('改回合法值後錯誤消失、儲存恢復', async () => {
    const wrapper = await mountPolicies()
    await rowInput(wrapper, '操作日誌保留天數').setValue('3')
    await flushPromises()
    expect(saveButton(wrapper).attributes('disabled')).toBeDefined()
    await rowInput(wrapper, '操作日誌保留天數').setValue('30')
    await flushPromises()
    expect(wrapper.find('[data-test="retention-floor-error-retention_audit_log_days"]').exists()).toBe(false)
    expect(saveButton(wrapper).attributes('disabled')).toBeUndefined()
  })
})

describe('縮短確認與通知字樣', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getSyslogMock.mockResolvedValue({
      data: { dropped: 0, setting: { enabled: false, host: '', port: 514, protocol: 'udp', tls_ca: '' } },
    })
    updatePoliciesMock.mockResolvedValue(policyFixture())
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
  })

  it('操作日誌 365 改 30：跳出縮短確認，內含通知句', async () => {
    const wrapper = await mountPolicies()
    await rowInput(wrapper, '操作日誌保留天數').setValue('30')
    await flushPromises()
    await saveButton(wrapper).trigger('click')
    await flushPromises()

    expect(ElMessageBox.confirm).toHaveBeenCalledTimes(1)
    const message = ElMessageBox.confirm.mock.calls[0][0]
    expect(message).toContain('永久清除')
    expectNotice(message)
  })

  it('只把檢查點保留 0 改 30：若出現縮短確認則不含通知句', async () => {
    const wrapper = await mountPolicies()
    await rowInput(wrapper, '檢查點保留天數').setValue('30')
    await flushPromises()
    await saveButton(wrapper).trigger('click')
    await flushPromises()

    ElMessageBox.confirm.mock.calls.forEach((call) => {
      expect(call[0]).not.toContain('建立系統告警')
      expect(call[0]).not.toContain('取決於通知通道')
    })
    expect(updatePoliciesMock).toHaveBeenCalledWith({ retention_checkpoint_days: '30' })
  })

  it('標題列通知句、開關說明與區塊說明補句存在，且字樣合乎統一說法', async () => {
    const wrapper = await mountPolicies()

    const title = wrapper.find('[data-test="retention-alert-notice"]')
    expect(title.exists()).toBe(true)
    expect(title.text()).toBe('調短任何一項資料保留天數都會記錄並建立系統告警，送達取決於通知通道')
    expectNotice(title.text())

    const failClose = wrapper.find('[data-test="failclose-off-notice"]')
    expect(failClose.exists()).toBe(true)
    expect(failClose.text()).toBe('關閉時會記錄並建立系統告警，送達取決於通知通道。')
    expectNotice(failClose.text())

    // 區塊說明：補句在，現行內容仍在
    expect(wrapper.text()).toContain('四項資料保留天數都有最少天數，不能再短。')
    expect(wrapper.text()).toContain('檢查點保留天數出廠為 0＝永久')
  })
})

describe('其他四頁的通知句', () => {
  const SENTENCE = '這類變更會記錄並建立系統告警，送達取決於通知通道。'

  beforeEach(() => {
    vi.clearAllMocks()
    getSyslogMock.mockResolvedValue({
      data: { dropped: 0, setting: { enabled: false, host: '', port: 514, protocol: 'udp', tls_ca: '' } },
    })
  })

  it('存取管控頁（全系統預設）', async () => {
    setCapabilitiesForTests(['securitypolicy:manage', 'access_policy:manage'])
    getPoliciesMock.mockResolvedValue({
      data: [
        {
          key: 'access_policy_default',
          type: 'enum',
          enum_order: ['open', 'reason', 'approval'],
          label: '連線申請政策（全域預設）',
          value: 'open',
        },
      ],
      groups: [],
    })
    const wrapper = mount(AccessControl, {
      global: { plugins: [ElementPlus], stubs: { RouterLink: { template: '<a><slot /></a>' } } },
    })
    await flushPromises()
    const el = wrapper.find('[data-test="default-relax-alert-notice"]')
    expect(el.exists()).toBe(true)
    expect(el.text()).toBe(SENTENCE)
    expectNotice(el.text())
  })

  it('syslog 卡', async () => {
    const wrapper = mount(SyslogForwardCard, { global: { plugins: [ElementPlus] } })
    await flushPromises()
    const el = wrapper.find('[data-test="syslog-change-alert-notice"]')
    expect(el.exists()).toBe(true)
    expect(el.text()).toBe(SENTENCE)
    expectNotice(el.text())
  })

  it('離機儲存頁', async () => {
    statusMock.mockResolvedValue({
      configured: false,
      disabled: false,
      generation_id: 0,
      total_objects: 0,
      counts: {},
      oldest_pending_age_seconds: {},
      governance: {},
    })
    getPoliciesMock.mockResolvedValue({ data: [], groups: [] })
    const RouterLinkStub = { props: ['to'], template: '<a><slot /></a>' }
    const wrapper = mount(OffsiteStorage, {
      global: {
        plugins: [ElementPlus],
        stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub },
      },
    })
    await flushPromises()
    const el = wrapper.find('[data-test="offsite-change-alert-notice"]')
    expect(el.exists()).toBe(true)
    expect(el.text()).toBe(SENTENCE)
    expectNotice(el.text())
  })

  it('金鑰拓撲卡', async () => {
    setCapabilitiesForTests(['key:manage', 'securitypolicy:manage'])
    getPoliciesMock.mockResolvedValue({ data: [], groups: [] })
    getInventoryMock.mockResolvedValue({
      keys: [],
      env_keys: [],
      kek_history: [],
      kek_id: 'abcd1234',
      provider: 'kms',
      rewrap_pending: false,
      rotation_pending: 0,
      finalize_pending: 0,
      retire_backlog: 0,
      reminder_days: 0,
    })
    getTopologyMock.mockResolvedValue({
      provider: 'vault',
      configured: true,
      address: 'https://vault.corp.example:8200',
      transit_key_name: 'custodexa-kek',
      role_id: 'role-custodexa-operations',
      region: '',
      key_ref: 'vault:custodexa-kek',
      editable_fields: ['address'],
      digest: 'a'.repeat(64),
    })
    const wrapper = mount(KeyManagement, {
      global: {
        plugins: [ElementPlus],
        stubs: {
          ElTable: { template: '<div />' },
          ElTableColumn: true,
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })
    await flushPromises()
    const el = wrapper.find('[data-test="kek-topology-alert-notice"]')
    expect(el.exists()).toBe(true)
    expect(el.text()).toBe(SENTENCE)
    expectNotice(el.text())
  })
})
