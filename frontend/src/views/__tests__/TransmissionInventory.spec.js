import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import TransmissionInventory from '../TransmissionInventory.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// transmission-security-policy 5.4：通道加密清冊儀表板

const getInventoryMock = vi.fn()
const exportInventoryMock = vi.fn()

vi.mock('@/api/transmissionInventory', () => ({
  getTransmissionInventory: (...args) => getInventoryMock(...args),
  exportTransmissionInventory: (...args) => exportInventoryMock(...args),
}))

// 傳輸政策鍵設定區與清冊同頁（settings-domain-restructure 3.1 域收編）
const getPoliciesMock = vi.fn()
const updatePoliciesMock = vi.fn()

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
}))

const policyFixture = () => ({
  data: [
    {
      key: 'transport_rdp_level',
      type: 'enum',
      enum_order: ['off', 'warn', 'strict'],
      pci_value: 'warn',
      requirement: '4.2.1',
      label: 'RDP 傳輸強制等級',
      value: 'off',
      compliant: false,
    },
    {
      key: 'transport_consent_ttl_days',
      type: 'int',
      pci_value: '90',
      direction: 'max',
      zero_disables: true,
      label: '傳輸風險同意效期',
      unit: '天',
      value: '90',
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

const inventoryFixture = () => ({
  data: {
    generated_at: '2026-07-16T00:00:00Z',
    channels: [
      { channel: 'ssh', total_count: 3, at_risk_count: 0, note: 'SSH 協議本身加密' },
      {
        channel: 'rdp', level: 'warn', total_count: 2, at_risk_count: 1,
        detail: { 'security=any,verify_cert=false': 1, 'security=nla,verify_cert=true': 1 },
        strict_preflight: '若切 strict 將拒絕 1 台 RDP 資產連線',
      },
      { channel: 'vnc', level: 'off', total_count: 1, at_risk_count: 1 },
      {
        // ldap-settings-migration：設定自部署層 env 遷入 UI，故 deployment 轉 false、
        // note 碼改 ldap_ui_managed（部署方徽章僅剩 nginx）
        channel: 'ldap', deployment: false, level: 'warn', total_count: 1, at_risk_count: 1,
        risks: [{ key: 'ldap_plaintext', label: '目錄連線未加密（非 ldaps）' }],
        strict_preflight: '若切 strict 將拒絕全部 LDAP 登入（本地帳號不受影響）',
        note_code: 'ldap_ui_managed', note: '設定於身分管理的目錄設定頁維護',
      },
      { channel: 'nginx', deployment: true, note: '前端 HTTPS 屬部署層' },
    ],
  },
})

const tableStub = {
  props: ['data'],
  template:
    '<div class="table-stub"><slot /><div v-for="(r, i) in data" :key="i" class="row-stub">{{ JSON.stringify(r) }}</div></div>',
}

// 逐列展開儲存格模板用的替身：ElTable 被 stub 後，欄位的 scoped slot 沒人呼叫，
// 儲存格內容（風險行、note、設定頁連結）就整片看不見。這組替身把 rows 由
// table 傳給 column，讓 column 自己逐列渲染 default slot
const cellTableStub = {
  props: ['data'],
  provide() {
    return { stubTable: this }
  },
  template: '<div class="table-stub"><slot /></div>',
}
const cellColumnStub = {
  inject: ['stubTable'],
  template:
    '<div class="col-stub"><template v-for="(r, i) in stubTable.data" :key="i"><slot :row="r" /></template></div>',
}

const mountPage = async () => {
  const wrapper = mount(TransmissionInventory, {
    global: {
      plugins: [ElementPlus],
      stubs: { ElTable: tableStub, ElTableColumn: true },
    },
  })
  await flushPromises()
  return wrapper
}

describe('TransmissionInventory 通道加密清冊', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getInventoryMock.mockResolvedValue(inventoryFixture())
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('政策鍵設定區只承載傳輸域鍵並附本頁偏離摘要', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('傳輸安全政策')
    expect(wrapper.text()).toContain('RDP 傳輸強制等級')
    expect(wrapper.text()).toContain('傳輸風險同意效期')
    // 非本域鍵不出現（域承載邊界）
    expect(wrapper.text()).not.toContain('密碼最小長度')
    // 偏離數只算本頁子集：僅 transport_rdp_level（off 劣於 warn）
    expect(wrapper.text()).toContain('本頁與 PCI 建議偏離 1 項')
    // 雙向導覽：橫幅附全系統總數回母頁總覽連結
    expect(wrapper.text()).toContain('全系統偏離 2 項 · 安全政策總覽')
  })

  it('儲存政策後重載清冊（政策等級欄同步）', async () => {
    updatePoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()
    expect(getInventoryMock).toHaveBeenCalledTimes(1)

    // 改等級產生 dirty 後儲存
    const radios = wrapper.findAllComponents({ name: 'ElRadioGroup' })
    radios[0].vm.$emit('update:modelValue', 'warn')
    await flushPromises()
    const saveBtn = wrapper.findAll('button').find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(updatePoliciesMock).toHaveBeenCalledWith({ transport_rdp_level: 'warn' })
    expect(getInventoryMock).toHaveBeenCalledTimes(2)
  })

  it('掛載即載入清冊並渲染全通道', async () => {
    const wrapper = await mountPage()
    expect(getInventoryMock).toHaveBeenCalledTimes(1)
    expect(wrapper.text()).toContain('"channel":"ssh"')
    expect(wrapper.text()).toContain('"channel":"rdp"')
    expect(wrapper.text()).toContain('"channel":"ldap"')
    expect(wrapper.text()).toContain('若切 strict 將拒絕 1 台 RDP 資產連線')
    // 部署層通道帶標示與 LDAP 登入預檢
    expect(wrapper.text()).toContain('"deployment":true')
    expect(wrapper.text()).toContain('若切 strict 將拒絕全部 LDAP 登入')
  })

  it('LDAP 列指得出設定頁入口（設定已由部署層 env 遷入產品 UI）', async () => {
    const wrapper = mount(TransmissionInventory, {
      global: {
        plugins: [ElementPlus],
        stubs: {
          ElTable: cellTableStub,
          ElTableColumn: cellColumnStub,
          RouterLink: { template: '<a class="router-link-stub"><slot /></a>' },
        },
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('設定於身分管理的目錄設定頁維護')
    // 說了「在設定頁維護」就必須指得出那一頁在哪
    // 只給「本產品 UI 可改」的通道：五個通道裡只有 LDAP 有頁可去，
    // 部署層通道（nginx）不給連結——送人去一個改不了東西的頁面比不給更糟
    const links = wrapper.findAll('.settings-link')
    expect(links).toHaveLength(1)
    expect(links[0].text()).toBe('前往設定頁')
  })

  it('匯出快照觸發下載', async () => {
    exportInventoryMock.mockResolvedValue({ generated_at: '2026-07-16T00:00:00Z', channels: [] })
    // jsdom/happy-dom 無 createObjectURL：stub 之
    const createURL = vi.fn(() => 'blob:x')
    const revokeURL = vi.fn()
    globalThis.URL.createObjectURL = createURL
    globalThis.URL.revokeObjectURL = revokeURL
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {})

    const wrapper = await mountPage()
    await wrapper.vm.handleExport()
    await flushPromises()

    expect(exportInventoryMock).toHaveBeenCalledTimes(1)
    expect(createURL).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
    clickSpy.mockRestore()
  })
})
