import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AccessControl from '../AccessControl.vue'
import { t } from '@/i18n'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（與 Assets.spec.js 同法）
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

const previewComplianceMock = vi.fn()
const previewApplyMock = vi.fn()

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
  // 判定與套用預覽端點：判定一律由後端供給，前端不自己算一份
  previewCompliance: (...args) => previewComplianceMock(...args),
  previewApplyPolicies: (...args) => previewApplyMock(...args),
}))

const getAssetListMock = vi.fn()
const updateAssetMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
  updateAsset: (...args) => updateAssetMock(...args),
}))

// 判定由後端建構，前端只投影
const verdict = (key, result, expected, comparator = 'equals') => ({
  key,
  group_code: 'pci_dss_4_0_1',
  clause_no: '7.2',
  result,
  reason: result === 'deviating' ? 'value_mismatch' : 'meets_expectation',
  current: 'open',
  expected,
  comparator,
})

// 後端回全鍵集；本頁只承載存取域 7 鍵——password_min_length 為「不屬本頁」對照組
const policyFixture = () => ({
  data: [
    {
      key: 'access_policy_default',
      type: 'enum',
      enum_order: ['open', 'reason', 'approval'],
      label: '連線申請政策（全域預設）',
      value: 'open',
      verdicts: [verdict('access_policy_default', 'deviating', 'approval')],
    },
    {
      key: 'access_request_max_duration_minutes',
      type: 'int',
      direction: 'max',
      label: '申請時長上限',
      unit: '分鐘',
      value: '1440',
    },
    {
      key: 'access_request_pending_timeout_hours',
      type: 'int',
      direction: 'max',
      label: '待審逾時',
      unit: '小時',
      value: '72',
    },
    {
      key: 'break_glass_enabled',
      type: 'bool',
      label: '破窗緊急連線',
      value: 'false',
    },
    {
      key: 'break_glass_duration_minutes',
      type: 'int',
      label: '破窗連線時窗',
      unit: '分鐘',
      value: '60',
    },
    {
      key: 'break_glass_review_timeout_hours',
      type: 'int',
      label: '補審逾時告警',
      unit: '小時',
      value: '24',
    },
    {
      key: 'access_revoke_disconnect',
      type: 'bool',
      label: '撤銷即斷線',
      value: 'false',
    },
    {
      key: 'password_min_length',
      type: 'int',
      direction: 'min',
      label: '密碼最小長度',
      unit: '字元',
      value: '8',
      verdicts: [verdict('password_min_length', 'deviating', '12', 'min')],
    },
  ],
  groups: [{ code: 'pci_dss_4_0_1', name: 'PCI DSS 4.0.1', enabled: true }],
})

// 一次滿足所有政策：本頁只有連線政策要改
const applyPreviewFixture = () => ({
  mode: 'strictest',
  changes: [
    { key: 'access_policy_default', current: 'open', proposed: 'approval', source_group: 'pci_dss_4_0_1' },
  ],
  conflicts: [],
  unchanged_count: 6,
  unmapped_count: 0,
})

// 資產政策覆寫：高敏 SSH 已覆寫、一般 RDP 未覆寫
const assetsFixture = () => ({
  data: [
    { id: 1, name: '高敏SSH', protocol: 'ssh', access_policy: 'approval' },
    { id: 2, name: '一般RDP', protocol: 'rdp', access_policy: null },
  ],
  total: 2,
})

// el-select 的選中文案與選項清單走 teleported popper，happy-dom 下不渲染——
// 以具名 stub 讓選項文案（含動態繼承文案）直接落入 DOM，change 事件語義不變
// （沿 frontend-testing-quirks「測邏輯層不測 EP 內部」原則）
const ElSelectStub = {
  name: 'ElSelect',
  props: ['modelValue'],
  emits: ['change', 'update:modelValue'],
  template: '<div class="select-stub" :data-value="modelValue"><slot /></div>',
}
const ElOptionStub = {
  name: 'ElOption',
  props: ['label', 'value'],
  template: '<div class="option-stub">{{ label }}</div>',
}

const mountPage = async () => {
  const wrapper = mount(AccessControl, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        'el-select': ElSelectStub,
        'el-option': ElOptionStub,
        RouterLink: { template: '<a><slot /></a>' },
      },
    },
  })
  await flushPromises()
  return wrapper
}

describe('AccessControl', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
    previewComplianceMock.mockResolvedValue({ data: { draft: true, verdicts: [] } })
    previewApplyMock.mockResolvedValue({ data: applyPreviewFixture() })
    getAssetListMock.mockResolvedValue(assetsFixture())
    updateAssetMock.mockResolvedValue({})
  })

  it('renders access-domain sections only, with page-subset deviation count', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('連線政策')
    expect(wrapper.text()).toContain('連線申請參數')
    expect(wrapper.text()).toContain('緊急連線與撤銷')
    expect(wrapper.text()).toContain('申請時長上限')
    expect(wrapper.text()).toContain('破窗緊急連線')
    // 非本頁鍵不得出現（域承載邊界）
    expect(wrapper.text()).not.toContain('密碼最小長度')
    // 偏離數只算本頁鍵子集：僅 access_policy_default（open 劣於 approval）
    expect(wrapper.find('[data-test="section-deviation-access_policy"]').text()).toBe('偏離 1 項')
    expect(wrapper.find('[data-test="section-deviation-break_glass"]').text()).toBe('無偏離項目')
    // 頁首列說出現在對照的是哪幾組，並給合規對照頁入口
    expect(wrapper.text()).toContain('目前對照的政策組')
    expect(wrapper.text()).toContain('合規對照')
  })

  // 誠實邊界的條目數是規格條列，不是排版細節：少一項即為介面對外少講一件事
  it('資料傳輸區塊列出七項控制邊界', async () => {
    getPoliciesMock.mockResolvedValue({
      data: [
        ...policyFixture().data,
        {
          key: 'clipboard_send_enabled',
          type: 'bool',
          label: '允許貼入受管資產',
          value: 'true',
        },
      ],
      total: 3,
    })
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain(t('transferBoundary.title'))
    const items = wrapper.findAll('.transfer-boundary .boundary-list li')
    expect(items).toHaveLength(7)
    expect(items[5].text()).toBe(t('transferBoundary.item6'))
    expect(items[6].text()).toBe(t('transferBoundary.item7'))
  })

  it('lists only overridden assets with dynamic clear-option label', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('資產政策覆寫')
    expect(wrapper.text()).toContain('變更即時生效')
    const table = wrapper.findComponent({ name: 'AssetPolicyTable' })
    // 表格僅列已覆寫資產；未覆寫者出現在「加入覆寫」選項
    expect(table.text()).toContain('高敏SSH')
    expect(table.text()).toContain('一般RDP（RDP）')
    // 清除覆寫選項帶目前全域值動態文案（全域=open）
    expect(table.text()).toContain('清除覆寫（跟隨全域，目前：不需申請）')
  })

  it('saves asset policy inline via asset API with partial payload', async () => {
    const wrapper = await mountPage()

    const table = wrapper.findComponent({ name: 'AssetPolicyTable' })
    // 覆寫列的下拉（跳過「加入覆寫」的資產/段位兩個 select）
    const rowSelect = table
      .findAllComponents({ name: 'ElSelect' })
      .find((s) => s.attributes('aria-label') === '高敏SSH 連線政策')
    rowSelect.vm.$emit('change', 'reason')
    await flushPromises()

    expect(updateAssetMock).toHaveBeenCalledWith(1, { access_policy: 'reason' })
    // 政策鍵批次 API 不被觸發（兩種儲存語義分離）
    expect(updatePoliciesMock).not.toHaveBeenCalled()
    // 即存後重載（成功與失敗同收斂點）
    expect(getAssetListMock).toHaveBeenCalledTimes(2)
  })

  it('clears override via explicit row button (same path as dropdown option)', async () => {
    const wrapper = await mountPage()

    const table = wrapper.findComponent({ name: 'AssetPolicyTable' })
    const clearBtn = table.findAll('button').find((b) => b.text() === '清除覆寫')
    expect(clearBtn).toBeTruthy()
    await clearBtn.trigger('click')
    await flushPromises()

    expect(updateAssetMock).toHaveBeenCalledWith(1, { access_policy: '' })
    // 與下拉清除同收斂點：即存後重載
    expect(getAssetListMock).toHaveBeenCalledTimes(2)
  })

  it('reloads assets to roll back displayed value when inline save fails', async () => {
    updateAssetMock.mockRejectedValueOnce(new Error('boom'))
    const wrapper = await mountPage()

    const table = wrapper.findComponent({ name: 'AssetPolicyTable' })
    const rowSelect = table
      .findAllComponents({ name: 'ElSelect' })
      .find((s) => s.attributes('aria-label') === '高敏SSH 連線政策')
    rowSelect.vm.$emit('change', '')
    await flushPromises()

    // 失敗仍重載——顯示值回滾為伺服器現值，不留未生效的新值
    expect(getAssetListMock).toHaveBeenCalledTimes(2)
  })

  it('shows empty-state guidance when no overrides exist', async () => {
    getAssetListMock.mockResolvedValue({
      data: [{ id: 2, name: '一般RDP', protocol: 'rdp', access_policy: null }],
      total: 1,
    })
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('尚無政策覆寫')
  })

  it('全域預設變更僅在儲存後更新繼承文案（生效值才是事實）', async () => {
    const savedFixture = policyFixture()
    savedFixture.data[0].value = 'reason'
    savedFixture.data[0].compliant = false
    updatePoliciesMock.mockResolvedValue(savedFixture)
    const wrapper = await mountPage()

    // 未儲存的編輯不改繼承文案
    const radios = wrapper.findAllComponents({ name: 'ElRadioGroup' })
    radios[0].vm.$emit('update:modelValue', 'reason')
    await flushPromises()
    expect(wrapper.text()).toContain('清除覆寫（跟隨全域，目前：不需申請）')

    const saveBtn = wrapper.findAll('button').find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()
    expect(updatePoliciesMock).toHaveBeenCalledWith({ access_policy_default: 'reason' })
    expect(wrapper.text()).toContain('清除覆寫（跟隨全域，目前：填寫理由即可連線）')
  })

  it('套用預覽只算本頁鍵，確認後填表單、儲存只送本頁鍵', async () => {
    updatePoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()

    wrapper.findComponent({ name: 'PolicyGroupStrip' }).vm.$emit('apply', { mode: 'strictest' })
    await flushPromises()

    // 套用範圍限本頁鍵：非本頁的密碼最小長度不進 scope
    const request = previewApplyMock.mock.calls[0][0]
    expect(request.scope).toContain('access_policy_default')
    expect(request.scope).not.toContain('password_min_length')

    const dialog = wrapper.findComponent({ name: 'ApplyPreviewDialog' })
    dialog.vm.$emit('confirm', dialog.props('preview').changes)
    await flushPromises()

    expect(wrapper.text()).toContain('有未儲存變更')

    const saveBtn = wrapper.findAll('button').find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    // 只送本頁偏離鍵；非本頁鍵（password_min_length 偏離中）不得入 payload
    expect(updatePoliciesMock).toHaveBeenCalledWith({
      access_policy_default: 'approval',
    })
  })
})
