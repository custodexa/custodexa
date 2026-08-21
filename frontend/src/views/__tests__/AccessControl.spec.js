import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AccessControl from '../AccessControl.vue'

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

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
}))

const getAssetListMock = vi.fn()
const updateAssetMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
  updateAsset: (...args) => updateAssetMock(...args),
}))

// 後端回全鍵集；本頁只承載存取域 7 鍵——password_min_length 為「不屬本頁」對照組
const policyFixture = () => ({
  data: [
    {
      key: 'access_policy_default',
      type: 'enum',
      enum_order: ['open', 'reason', 'approval'],
      pci_value: 'approval',
      requirement: '7.2',
      label: '連線申請政策（全域預設）',
      value: 'open',
      compliant: false,
    },
    {
      key: 'access_request_max_duration_minutes',
      type: 'int',
      pci_value: '1440',
      direction: 'max',
      label: '申請時長上限',
      unit: '分鐘',
      value: '1440',
      compliant: true,
    },
    {
      key: 'access_request_pending_timeout_hours',
      type: 'int',
      pci_value: '72',
      direction: 'max',
      label: '待審逾時',
      unit: '小時',
      value: '72',
      compliant: true,
    },
    {
      key: 'break_glass_enabled',
      type: 'bool',
      label: '破窗緊急連線',
      value: 'false',
      compliant: true,
    },
    {
      key: 'break_glass_duration_minutes',
      type: 'int',
      label: '破窗連線時窗',
      unit: '分鐘',
      value: '60',
      compliant: true,
    },
    {
      key: 'break_glass_review_timeout_hours',
      type: 'int',
      label: '補審逾時告警',
      unit: '小時',
      value: '24',
      compliant: true,
    },
    {
      key: 'access_revoke_disconnect',
      type: 'bool',
      label: '撤銷即斷線',
      value: 'false',
      compliant: true,
    },
    {
      key: 'password_min_length',
      type: 'int',
      pci_value: '12',
      direction: 'min',
      label: '密碼最小長度',
      unit: '字元',
      value: '8',
      compliant: false,
    },
  ],
  deviation_count: 2,
})

// 資產政策覆寫（asset-level-access-policy）：高敏 SSH 已覆寫、一般 RDP 未覆寫
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
    expect(wrapper.text()).toContain('本頁與 PCI 建議偏離 1 項')
    // 雙向導覽：橫幅附全系統總數回母頁總覽連結（deviation_count=2）
    expect(wrapper.text()).toContain('全系統偏離 2 項 · 安全政策總覽')
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

  it('apply-page-PCI touches only page keys and save sends only page keys', async () => {
    updatePoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()

    const applyBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('套用本頁建議值'))
    await applyBtn.trigger('click')
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
