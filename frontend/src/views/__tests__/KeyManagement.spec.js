import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import KeyManagement from '../KeyManagement.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// key-management-envelope task 6：金鑰清冊與換鑰精靈前端

const getInventoryMock = vi.fn()
const rotateKeyMock = vi.fn()
const rewrapKEKMock = vi.fn()
const abandonRewrapMock = vi.fn()
const cleanupRetiredMock = vi.fn()

vi.mock('@/api/keys', () => ({
  getKeyInventory: (...args) => getInventoryMock(...args),
  rotateKey: (...args) => rotateKeyMock(...args),
  rewrapKEK: (...args) => rewrapKEKMock(...args),
  abandonRewrap: (...args) => abandonRewrapMock(...args),
  cleanupRetiredMaterial: (...args) => cleanupRetiredMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

// 金鑰政策鍵設定區與清冊同頁（settings-domain-restructure 3.2 域收編）
const getPoliciesMock = vi.fn()
const updatePoliciesMock = vi.fn()

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
}))

const policyFixture = () => ({
  data: [
    {
      key: 'key_cryptoperiod_reminder_days',
      type: 'int',
      pci_value: '365',
      direction: 'min',
      zero_disables: true,
      requirement: '3.7.4',
      label: '金鑰輪替提醒天數',
      unit: '天',
      value: '0',
      compliant: false,
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

const inventoryFixture = (overrides = {}) => ({
  keys: [
    { purpose: 'audit_integrity', version: 0, status: 'retired', kek_id: 'abcd1234', age_days: 10, over_cryptoperiod: false, created_at: '2026-07-05T00:00:00Z', retired_at: '2026-07-05T00:00:00Z' },
    { purpose: 'audit_integrity', version: 1, status: 'active', kek_id: 'abcd1234', age_days: 10, over_cryptoperiod: false, created_at: '2026-07-05T00:00:00Z' },
    { purpose: 'data', version: 1, status: 'active', kek_id: 'abcd1234', age_days: 10, over_cryptoperiod: false, created_at: '2026-07-05T00:00:00Z' },
  ],
  env_keys: [
    { name: 'ENCRYPTION_KEY (KEK)', fingerprint: 'abcd1234', managed_by: 'deployer', note: '信封主鑰' },
    { name: 'JWT_SECRET', managed_by: 'deployer', note: '登入簽章鑰' },
  ],
  kek_history: [],
  kek_id: 'abcd1234',
  // 執行期 KEK provider（D10 頂層欄，後端恆送）。切換指示依它分岔
  // （operator-guidance-fidelity）；缺欄的 fail-safe 態由個案 overrides 指定
  provider: 'env',
  rewrap_pending: false,
  rotation_pending: 0,
  // 切換收尾雙態預設收斂（kek-rewrap-hygiene-hardening）：未收斂態由個案 overrides 指定
  finalize_pending: 0,
  retire_backlog: 0,
  reminder_days: 0,
  ...overrides,
})

const findButton = (wrapper, text) =>
  wrapper.findAll('button').find((b) => b.text().includes(text))

// 清理確認框的內容自 uiux-keymgmt-r1 H2 起是結構化 VNode（段落＋清單）而非單一字串：
// 斷言改打在攤平後的文字上，順序資訊仍完整保留（清單項按渲染順序串接）
const vnodeText = (node) => {
  if (node === null || node === undefined || typeof node === 'boolean') return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(vnodeText).join('')
  if (typeof node === 'object') return vnodeText(node.children)
  return ''
}

// D7 反轉後：材料由使用者提供，回應恰三鍵且無明文欄
const VALID_KEK = 'NEWKEK1234567890abcdefABCDEF0000'
const rewrapResponseFixture = () => ({
  target_mode: 'local',
  new_kek_id: 'ffff9999',
  rewrapped_keys: 3,
})

// 精靈第 2 步（輸入新 KEK）：開窗 → 下一步
const openRewrapInputStep = async (wrapper) => {
  await findButton(wrapper, 'KEK 重包精靈').trigger('click')
  await flushPromises()
  await findButton(wrapper, '下一步').trigger('click')
  await flushPromises()
}

const kekInputs = (wrapper) => wrapper.findAll('.kek-input input')

const setKekInputs = async (wrapper, material, confirm) => {
  const inputs = kekInputs(wrapper)
  await inputs[0].setValue(material)
  await inputs[1].setValue(confirm)
  await flushPromises()
}

const checkSavedConfirm = async (wrapper) => {
  const checkbox = wrapper
    .findAllComponents({ name: 'ElCheckbox' })
    .find((c) => c.text().includes('我已將新 KEK 保存'))
  await checkbox.find('input').setValue(true)
  await flushPromises()
}

// 明文清除的斷言打在元件狀態本體（渲染看不到 ≠ 狀態已清），沿既有卸載測試的手法
const setupStateDump = (wrapper) =>
  JSON.stringify(
    Object.entries(wrapper.vm.$ ? wrapper.vm.$.setupState || {} : {}).map(
      ([, v]) => (v && v.value) ?? v
    )
  )

// el-table 在 happy-dom 下的 MutationObserver 會炸（frontend-testing-quirks）：
// 以簡易 stub 渲染 data 供文字斷言，欄位模板不在本測試範圍
const tableStub = {
  props: ['data'],
  template: '<div class="table-stub"><slot /><div v-for="(r, i) in data" :key="i" class="row-stub">{{ JSON.stringify(r) }}</div></div>',
}

const mountPage = async () => {
  const wrapper = mount(KeyManagement, {
    global: {
      plugins: [ElementPlus],
      stubs: { ElTable: tableStub, ElTableColumn: true },
    },
  })
  await flushPromises()
  return wrapper
}

describe('KeyManagement 金鑰清冊', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getInventoryMock.mockResolvedValue(inventoryFixture())
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('政策鍵設定區只承載金鑰提醒鍵並附本頁偏離摘要', async () => {
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('金鑰管理政策')
    expect(wrapper.text()).toContain('金鑰輪替提醒天數')
    expect(wrapper.text()).toContain('0 = 不提醒')
    // 非本域鍵不出現（域承載邊界）
    expect(wrapper.text()).not.toContain('密碼最小長度')
    // 偏離數只算本頁子集：僅提醒鍵（0 劣於 365）
    expect(wrapper.text()).toContain('本頁與 PCI 建議偏離 1 項')
    // 雙向導覽：橫幅附全系統總數回母頁總覽連結
    expect(wrapper.text()).toContain('全系統偏離 2 項 · 安全政策總覽')
  })

  it('儲存提醒鍵後重載清冊（超齡提醒即時反映）', async () => {
    updatePoliciesMock.mockResolvedValue(policyFixture())
    const wrapper = await mountPage()
    expect(getInventoryMock).toHaveBeenCalledTimes(1)

    const inputNumber = wrapper.findComponent({ name: 'ElInputNumber' })
    inputNumber.vm.$emit('update:modelValue', 365)
    await flushPromises()
    const saveBtn = wrapper.findAll('button').find((b) => b.text() === '儲存')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(updatePoliciesMock).toHaveBeenCalledWith({
      key_cryptoperiod_reminder_days: '365',
    })
    expect(getInventoryMock).toHaveBeenCalledTimes(2)
  })

  it('渲染 DB 側版本鏈與 env 側部署方管理標示', async () => {
    const wrapper = await mountPage()
    // 表格 stub 渲染原始列資料（欄位模板不在測試範圍）。
    // 註：退役列預設隱藏（見「系統管理金鑰退役列治理」describe），故此處只驗現行列
    expect(wrapper.text()).toContain('audit_integrity')
    expect(wrapper.text()).toContain('"purpose":"data"')
    expect(wrapper.text()).toContain('active')
    // 卡片標題與 env 側鑰
    expect(wrapper.text()).toContain('系統管理金鑰')
    expect(wrapper.text()).toContain('部署層金鑰')
    expect(wrapper.text()).toContain('ENCRYPTION_KEY (KEK)')
    expect(wrapper.text()).toContain('deployer')
  })

  // legacy 遷移狀態欄位已隨過渡機制整組拆除（release-transitional-cleanup 3.3）：
  // 清冊回應不再帶 migration／migration_pending，頁面亦無對應橫幅與禁用條件。
  it('清冊回應不含 legacy 遷移欄位時頁面正常渲染且重包可用', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture())
    const wrapper = await mountPage()
    expect(wrapper.text()).not.toContain('legacy 密文遷移未完成')
    const rewrapBtn = wrapper.findAll('button').find((b) => b.text().includes('KEK 重包精靈'))
    expect(rewrapBtn.attributes('disabled')).toBeUndefined()
  })

  it('KEK 重包待切換時顯示提醒並停用輪替按鈕', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ rewrap_pending: true }))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('KEK 重包尚未切換')
    // 重包待切換期間 DEK 與蓋章鑰輪替均停用（後端亦 409 守衛）
    const dekBtn = wrapper.findAll('button').find((b) => b.text().includes('輪替資料加密鑰'))
    const auditBtn = wrapper.findAll('button').find((b) => b.text().includes('輪替審計蓋章鑰'))
    expect(dekBtn.attributes('disabled')).toBeDefined()
    expect(auditBtn.attributes('disabled')).toBeDefined()
  })

  it('DEK 輪替未跑完時顯示續跑橫幅', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ rotation_pending: 7 }))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('資料加密鑰輪替未跑完')
    expect(wrapper.text()).toContain('續跑')
  })

  it('超齡金鑰顯示提醒橫幅', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({
        reminder_days: 365,
        keys: [{ purpose: 'data', version: 1, status: 'active', kek_id: 'abcd1234', age_days: 400, over_cryptoperiod: true, created_at: '2025-06-01T00:00:00Z' }],
      })
    )
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('金鑰年齡提醒')
    expect(wrapper.text()).toContain('超過提醒天數')
  })

  it('DEK 輪替確認後呼叫 API 並回報結果', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    rotateKeyMock.mockResolvedValue({ purpose: 'data', from_version: 1, to_version: 2, reencrypted: 3, failed: 0, pending: 0 })
    const wrapper = await mountPage()

    const rotateBtn = wrapper.findAll('button').find((b) => b.text().includes('輪替資料加密鑰'))
    await rotateBtn.trigger('click')
    await flushPromises()

    expect(rotateKeyMock).toHaveBeenCalledWith('data')
    expect(getInventoryMock).toHaveBeenCalledTimes(2) // 初載 + 輪替後刷新
  })

  it('KEK 重包精靈：第一步說明明文由使用者持有，委託目標標示為本版未提供', async () => {
    const wrapper = await mountPage()

    await findButton(wrapper, 'KEK 重包精靈').trigger('click')
    await flushPromises()

    // D7 明文流向反轉：伺服端不生成不回傳，措辭不得再宣稱「顯示一次」
    expect(wrapper.text()).toContain('新 KEK 只存在於你手上')
    expect(wrapper.text()).toContain('伺服端不生成')
    // 委託目標（kms／hsm）契約已定但本版後端回 501：以停用選項明示，不讓使用者送出後才吃錯誤
    expect(wrapper.text()).toContain('本版未提供')
    expect(rewrapKEKMock).not.toHaveBeenCalled()
  })

  it('對話框關閉事件當下清除新 KEK 明文（不得滯留至下次開窗）', async () => {
    // kek-rewrap-hygiene-hardening 1.2：斷言打在關閉事件完成當下。
    // 注意不得以「重開對話框看不到舊值」驗證——openRewrapWizard 既有 reset
    // 會使該寫法零改動即綠（審查 opus M8 假綠形態）
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)
    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    // 前置確認：明文確實已進入元件狀態（否則後面的「已清除」是空泛的先綠）
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)
    const inventoryCallsBefore = getInventoryMock.mock.calls.length

    // 直接發出 dialog closed 事件（happy-dom 不跑 transition），不重開對話框
    const rewrapDialog = wrapper
      .findAllComponents({ name: 'ElDialog' })
      .find((d) => d.props('modelValue') === true)
    rewrapDialog.vm.$emit('closed')
    await flushPromises()

    // 關閉事件處理完成當下：明文已自元件狀態清除（渲染中不再存在）＋清冊已刷新
    expect(setupStateDump(wrapper)).not.toContain(VALID_KEK)
    expect(getInventoryMock.mock.calls.length).toBe(inventoryCallsBefore + 1)
  })
})

// kek-provider-modularization D7／D8：明文流向反轉後的重包精靈
describe('KeyManagement 重包精靈（D7 明文由使用者提供）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getInventoryMock.mockResolvedValue(inventoryFixture())
    getPoliciesMock.mockResolvedValue(policyFixture())
    rewrapKEKMock.mockResolvedValue(rewrapResponseFixture())
  })

  it('本地生成鈕產出合格材料並同時填入 paste-back 欄', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)

    await findButton(wrapper, '本地生成').trigger('click')
    await flushPromises()

    const [first, second] = kekInputs(wrapper).map((i) => i.element.value)
    expect(first).toHaveLength(32)
    expect(first).toMatch(/^[A-Za-z0-9]{32}$/)
    expect(second).toBe(first)
  })

  it('格式不合即時提示且擋住送出（伺服端仍為權威，文案須明說）', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)

    await setKekInputs(wrapper, 'too-short', 'too-short')
    expect(wrapper.text()).toContain('無法解為 32 位元組金鑰')
    // 文案不得暗示前端驗證即足夠
    expect(wrapper.text()).toContain('以伺服端驗證為準')
    expect(findButton(wrapper, '執行重包').attributes('disabled')).toBeDefined()
  })

  it('paste-back 不符即前端擋住，完全不送出', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)

    await setKekInputs(wrapper, VALID_KEK, `${VALID_KEK.slice(0, 31)}X`)
    await checkSavedConfirm(wrapper)

    expect(wrapper.text()).toContain('兩次輸入不一致')
    const submitBtn = findButton(wrapper, '執行重包')
    expect(submitBtn.attributes('disabled')).toBeDefined()
    await submitBtn.trigger('click')
    await flushPromises()
    expect(rewrapKEKMock).not.toHaveBeenCalled()
  })

  it('未勾選保存確認前不可送出', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)

    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    expect(findButton(wrapper, '執行重包').attributes('disabled')).toBeDefined()

    await checkSavedConfirm(wrapper)
    expect(findButton(wrapper, '執行重包').attributes('disabled')).toBeUndefined()
  })

  it('送出的 payload 為 local 變體的精確鍵集（多一鍵即 400）', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)
    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    await checkSavedConfirm(wrapper)

    await findButton(wrapper, '執行重包').trigger('click')
    await flushPromises()

    expect(rewrapKEKMock).toHaveBeenCalledWith(
      {
        mode: 'local',
        new_kek: VALID_KEK,
        new_kek_confirm: VALID_KEK,
        confirm_saved: true,
      },
      { skipErrorToast: true }
    )
    // 鍵集精確比對：union 不允許選填欄位，夾帶任何額外鍵都會被後端整包拒絕
    expect(Object.keys(rewrapKEKMock.mock.calls[0][0]).sort()).toEqual([
      'confirm_saved',
      'mode',
      'new_kek',
      'new_kek_confirm',
    ])
  })

  it('回應無明文欄：只渲染指紋與重包列數，且送出後明文自元件狀態清除', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)
    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    await checkSavedConfirm(wrapper)
    // 前置確認：明文確實在元件狀態內，之後的「已清除」才不是空泛的先綠
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)

    await findButton(wrapper, '執行重包').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('ffff9999')
    expect(wrapper.text()).toContain('重包金鑰 3 列')
    // 明文清除時機之一：送出後。斷言打在元件狀態本體，不只是「畫面上看不到」
    expect(wrapper.text()).not.toContain(VALID_KEK)
    expect(setupStateDump(wrapper)).not.toContain(VALID_KEK)
  })

  it('送出失敗（400 材料不合格）：查譯機器碼呈現，明文同樣清除', async () => {
    const errorSpy = vi.spyOn(ElMessage, 'error')
    rewrapKEKMock.mockRejectedValue({
      response: { status: 400, data: { code: 'VALIDATION_KEY_REWRAP_MATERIAL' } },
    })
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)
    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    await checkSavedConfirm(wrapper)
    // 前置確認：明文確實在元件狀態內，之後的「已清除」才不是空泛的先綠
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)

    await findButton(wrapper, '執行重包').trigger('click')
    await flushPromises()

    expect(errorSpy.mock.calls[0][0]).toContain('新 KEK 材料不合格')
    expect(setupStateDump(wrapper)).not.toContain(VALID_KEK)
  })

  it('元件卸載時清除明文（離開頁面不留殘值）', async () => {
    const wrapper = await mountPage()
    await openRewrapInputStep(wrapper)
    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    expect(setupStateDump(wrapper)).toContain(VALID_KEK)
    const vm = wrapper.vm

    wrapper.unmount()

    const leaked = JSON.stringify(
      Object.entries(vm.$ ? vm.$.setupState || {} : {}).map(([, v]) => (v && v.value) ?? v)
    )
    expect(leaked).not.toContain(VALID_KEK)
  })
})

// kek-provider-modularization D10：清冊的 provider／key_ref／seal_state 顯示
describe('KeyManagement 清冊 provider 顯示（D10）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('後端提供 provider／key_ref 時渲染對應欄位', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({
        env_keys: [
          { name: 'KEK', fingerprint: 'abcd1234', provider: 'ui', key_ref: 'abcd1234', managed_by: 'deployer', note: '信封主鑰' },
          { name: 'JWT_SECRET', managed_by: 'deployer', note: '登入簽章鑰' },
        ],
      })
    )
    const wrapper = await mountPage()

    const labels = wrapper
      .findAllComponents({ name: 'ElTableColumn' })
      .map((c) => c.props('label'))
    expect(labels).toContain('KEK provider')
    expect(labels).toContain('金鑰引用')
  })

  it('後端未提供 provider 時不渲染該兩欄（不以空欄假裝資料存在）', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture())
    const wrapper = await mountPage()

    const labels = wrapper
      .findAllComponents({ name: 'ElTableColumn' })
      .map((c) => c.props('label'))
    expect(labels).not.toContain('KEK provider')
    expect(labels).not.toContain('金鑰引用')
  })

  it('seal_state 與 degraded 並存呈現（正交兩軸，不互相覆蓋）', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({ seal_state: 'unsealed', retire_backlog: 2 })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('已解封')
    expect(wrapper.text()).toContain('KEK 退役收斂失敗（degraded）')
  })

  it('後端未提供 seal_state 時不顯示封印徽章', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture())
    const wrapper = await mountPage()
    expect(wrapper.text()).not.toContain('已解封')
  })
})

// kek-rewrap-hygiene-hardening D7：切換收尾橫幅雙態
describe('KeyManagement 切換收尾橫幅雙態', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('僅 finalize_pending>0：待切換態（info，指引存 KEK 後重啟）', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ finalize_pending: 2 }))
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('KEK 重包已完成，等待切換生效')
    expect(wrapper.text()).toContain('ENCRYPTION_KEY')
    expect(wrapper.text()).not.toContain('degraded')
    const banner = wrapper
      .findAllComponents({ name: 'ElAlert' })
      .find((a) => a.props('title') === 'KEK 重包已完成，等待切換生效')
    expect(banner.props('type')).toBe('info')
  })

  it('retire_backlog>0：degraded 態（warning，指引重啟收斂）', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ retire_backlog: 3 }))
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('KEK 退役收斂失敗（degraded）')
    expect(wrapper.text()).toContain('重啟後端服務')
    const banner = wrapper
      .findAllComponents({ name: 'ElAlert' })
      .find((a) => a.props('title') === 'KEK 退役收斂失敗（degraded）')
    expect(banner.props('type')).toBe('warning')
  })

  it('兩態並存時 degraded 優先且只顯示一則', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({ retire_backlog: 3, finalize_pending: 2 })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('KEK 退役收斂失敗（degraded）')
    expect(wrapper.text()).not.toContain('KEK 重包已完成，等待切換生效')
  })

  it('全數收斂時不顯示切換收尾橫幅', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture())
    const wrapper = await mountPage()

    expect(wrapper.text()).not.toContain('KEK 退役收斂失敗')
    expect(wrapper.text()).not.toContain('KEK 重包已完成，等待切換生效')
  })
})

// kek-rewrap-hygiene-hardening D9 3.6：顯式清理退役資料
describe('KeyManagement 清理退役資料', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getInventoryMock.mockResolvedValue(inventoryFixture())
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('全數收斂時清理按鈕可用', async () => {
    const wrapper = await mountPage()
    expect(findButton(wrapper, '清理退役資料').attributes('disabled')).toBeUndefined()
  })

  it('retire_backlog>0 時清理按鈕禁用並附未收斂 tooltip', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ retire_backlog: 1 }))
    const wrapper = await mountPage()

    expect(findButton(wrapper, '清理退役資料').attributes('disabled')).toBeDefined()
    const tip = wrapper
      .findAllComponents({ name: 'ElTooltip' })
      .find((t) => String(t.props('content')).includes('尚未全數收斂'))
    expect(tip, '未收斂原因應以 tooltip 說明').toBeTruthy()
  })

  it('finalize_pending>0 時清理按鈕亦禁用（全收斂閘含待切換）', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ finalize_pending: 1 }))
    const wrapper = await mountPage()
    expect(findButton(wrapper, '清理退役資料').attributes('disabled')).toBeDefined()
  })

  it('確認後呼叫清理 API、摘要 purged/skipped 並刷新清冊', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    cleanupRetiredMock.mockResolvedValue({
      purged: [{ purpose: 'data', version: 1, kek_id: 'abcd1234' }],
      skipped: [
        { purpose: 'data', version: 2, kek_id: 'abcd1234', refs: 7, reason: 'version_referenced' },
      ],
    })
    const errorSpy = vi.spyOn(ElMessage, 'error')
    const successSpy = vi.spyOn(ElMessage, 'success')
    const warningSpy = vi.spyOn(ElMessage, 'warning')
    const wrapper = await mountPage()

    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    expect(ElMessageBox.confirm).toHaveBeenCalled()
    expect(cleanupRetiredMock).toHaveBeenCalledWith({ skipErrorToast: true })
    expect(successSpy.mock.calls[0][0]).toContain('已清理 1 筆')
    // 拒清逐項可讀：用途 vN：仍被 M 筆引用
    // 拒清逐項須說明「為什麼不能清」而非泛稱有引用（稽核需求文案）
    expect(warningSpy.mock.calls[0][0].message).toContain('v2：保留中')
    expect(warningSpy.mock.calls[0][0].message).toContain('7 筆存量密文')
    expect(warningSpy.mock.calls[0][0].message).toContain('永久不可解')
    expect(warningSpy.mock.calls[0][0].message).toContain('1 筆保留未清')
    expect(errorSpy).not.toHaveBeenCalled()
    expect(getInventoryMock).toHaveBeenCalledTimes(2) // 初載 + 清理後刷新
  })

  it('取消確認不呼叫清理 API', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = await mountPage()

    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    expect(cleanupRetiredMock).not.toHaveBeenCalled()
  })

  it('409 未收斂：查譯 apierror 碼呈現、不炸且按鈕恢復可點', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const errorSpy = vi.spyOn(ElMessage, 'error')
    cleanupRetiredMock.mockRejectedValue({
      response: {
        status: 409,
        data: { code: 'CONFLICT_KEY_CLEANUP_NOT_CONVERGED', error: 'raw backend message' },
      },
    })
    const wrapper = await mountPage()

    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    // apierror 譯文優先於後端裸訊息
    expect(errorSpy.mock.calls[0][0]).toContain('尚未全數收斂')
    expect(errorSpy.mock.calls[0][0]).not.toContain('raw backend message')
    // loading 已釋放（按鈕未卡在 loading 態）；清冊已刷新使禁用態與後端一致
    expect(findButton(wrapper, '清理退役資料').classes()).not.toContain('is-loading')
    expect(getInventoryMock).toHaveBeenCalledTimes(2)
  })

  it('409 鎖忙：走 CONFLICT_KEY_OP_BUSY 譯文', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const errorSpy = vi.spyOn(ElMessage, 'error')
    cleanupRetiredMock.mockRejectedValue({
      response: { status: 409, data: { code: 'CONFLICT_KEY_OP_BUSY' } },
    })
    const wrapper = await mountPage()

    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    expect(errorSpy.mock.calls[0][0]).toContain('另一金鑰操作進行中')
  })
})

// release-transitional-cleanup：系統管理金鑰表的退役列呈現治理。
// 退役列因稽核需求永久保留、只增不減，混排會讓現行鑰在數次輪替後被歷史淹沒
describe('KeyManagement 系統管理金鑰退役列治理', () => {
  // 兩用途各輪替過數次：現行 audit v2／data v3，退役 audit v1／v0、data v2／v1。
  //
  // fixture 刻意讓**版本序與退役時序相反**（uiux-keymgmt-r1 H1）：最新退役的是
  // audit v1（07-10），版本卻只有 1；版本最大的 data v2 反而早它 20 天退役。
  // 舊版以 version desc 排序在「版本序＝時序」的資料下與正解無從區分，測試因此
  // 鎖住假綠。version desc 於本資料會排成 data v2 → data v1 → audit v1 → audit v0，
  // 與下方期望值不同——排序若退回版本序，本檔必紅。
  // 陣列順序另刻意打散，確保通過的不是「照後端原序輸出」
  const rotatedInventory = (overrides = {}) =>
    inventoryFixture({
      ...overrides,
      keys: [
        { purpose: 'data', version: 1, status: 'retired', kek_id: 'abcd1234', age_days: 90, over_cryptoperiod: false, created_at: '2026-04-01T00:00:00Z', retired_at: '2026-06-05T00:00:00Z' },
        { purpose: 'audit_integrity', version: 0, status: 'retired', kek_id: 'abcd1234', age_days: 120, over_cryptoperiod: false, created_at: '2026-03-01T00:00:00Z', retired_at: '2026-05-01T00:00:00Z' },
        { purpose: 'audit_integrity', version: 2, status: 'active', kek_id: 'abcd1234', age_days: 20, over_cryptoperiod: false, created_at: '2026-07-10T00:00:00Z' },
        { purpose: 'data', version: 3, status: 'active', kek_id: 'abcd1234', age_days: 30, over_cryptoperiod: false, created_at: '2026-06-20T00:00:00Z' },
        { purpose: 'audit_integrity', version: 1, status: 'retired', kek_id: 'abcd1234', age_days: 60, over_cryptoperiod: false, created_at: '2026-05-01T00:00:00Z', retired_at: '2026-07-10T00:00:00Z' },
        { purpose: 'data', version: 2, status: 'retired', kek_id: 'abcd1234', age_days: 45, over_cryptoperiod: false, created_at: '2026-06-05T00:00:00Z', retired_at: '2026-06-20T00:00:00Z' },
      ],
    })

  // 只取系統管理金鑰表（.keys-table）的列；env／KEK 退役史表不在本範圍
  const systemKeyRows = (wrapper) =>
    wrapper.findAll('.keys-table .row-stub').map((el) => {
      const row = JSON.parse(el.text())
      return `${row.purpose} v${row.version} ${row.status}`
    })

  const retiredToggle = (wrapper) =>
    wrapper
      .findAllComponents({ name: 'ElCheckbox' })
      .find((c) => c.text().includes('顯示已退役'))

  const toggleRetired = async (wrapper) => {
    await retiredToggle(wrapper).find('input').setValue(true)
    await flushPromises()
  }

  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('預設只顯示現行鑰，退役列不渲染', async () => {
    getInventoryMock.mockResolvedValue(rotatedInventory())
    const wrapper = await mountPage()

    expect(systemKeyRows(wrapper)).toEqual([
      'audit_integrity v2 active',
      'data v3 active',
    ])
  })

  it('切換控制標示退役列數，開啟後 active 在前、退役按退役時間新到舊接續', async () => {
    getInventoryMock.mockResolvedValue(rotatedInventory())
    const wrapper = await mountPage()

    const toggle = retiredToggle(wrapper)
    expect(toggle.text()).toContain('顯示已退役（4）')

    await toggle.find('input').setValue(true)
    await flushPromises()

    // 排序基準＝retired_at desc（07-10 → 06-20 → 06-05 → 05-01），跨用途不比版本號
    expect(systemKeyRows(wrapper)).toEqual([
      'audit_integrity v2 active',
      'data v3 active',
      'audit_integrity v1 retired',
      'data v2 retired',
      'data v1 retired',
      'audit_integrity v0 retired',
    ])
  })

  it('退役列套降階列樣式，交界列另帶分隔線 class（展開態一眼可分現行／歷史）', async () => {
    getInventoryMock.mockResolvedValue(rotatedInventory())
    const wrapper = await mountPage()
    const rowClass = wrapper.vm.keyRowClass

    expect(rowClass({ row: { status: 'active' }, rowIndex: 0 })).toBe('')
    // 現行鑰 2 列，故 index 2 是第一筆退役列＝歷史區起點
    expect(rowClass({ row: { status: 'retired' }, rowIndex: 2 })).toBe(
      'retired-key-row retired-key-row--first'
    )
    expect(rowClass({ row: { status: 'retired' }, rowIndex: 3 })).toBe('retired-key-row')
  })

  it('零退役列時整個切換控制不存在（全新安裝零噪音）', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({
        keys: [
          { purpose: 'audit_integrity', version: 1, status: 'active', kek_id: 'abcd1234', age_days: 3, over_cryptoperiod: false, created_at: '2026-07-05T00:00:00Z' },
          { purpose: 'data', version: 1, status: 'active', kek_id: 'abcd1234', age_days: 3, over_cryptoperiod: false, created_at: '2026-07-05T00:00:00Z' },
        ],
      })
    )
    const wrapper = await mountPage()

    expect(retiredToggle(wrapper)).toBeUndefined()
    expect(wrapper.text()).not.toContain('顯示已退役')
  })

  it('顯示過濾不縮減清理確認的銷毀候選清單（告知範圍不隨呈現改變）', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    getInventoryMock.mockResolvedValue(rotatedInventory())
    const wrapper = await mountPage()

    // 退役列此刻隱藏中，但確認文案仍須列出全部銷毀候選
    expect(systemKeyRows(wrapper)).toHaveLength(2)
    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    const message = vnodeText(confirmSpy.mock.calls[0][0])
    expect(message).toContain('審計蓋章鑰（HMAC） v0')
    expect(message).toContain('審計蓋章鑰（HMAC） v1')
    expect(message).toContain('資料加密鑰（DEK） v1')
    expect(message).toContain('資料加密鑰（DEK） v2')
  })

  it('確認框的候選清單與表格同序（兩份清單要能逐項對照）', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    getInventoryMock.mockResolvedValue(rotatedInventory())
    const wrapper = await mountPage()

    await toggleRetired(wrapper)
    const tableOrder = systemKeyRows(wrapper)
      .filter((r) => r.endsWith('retired'))
      .map((r) => r.replace(' retired', ''))

    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    // 確認框逐項的出現位置須與表格退役段同序（比對 index 而非只驗有列到）
    const message = vnodeText(confirmSpy.mock.calls[0][0])
    const labels = {
      'audit_integrity v1': '審計蓋章鑰（HMAC） v1',
      'audit_integrity v0': '審計蓋章鑰（HMAC） v0',
      'data v2': '資料加密鑰（DEK） v2',
      'data v1': '資料加密鑰（DEK） v1',
    }
    const positions = tableOrder.map((key) => message.indexOf(labels[key]))
    expect(positions.every((p) => p >= 0), '候選清單須列出全部退役列').toBe(true)
    expect(positions).toEqual([...positions].sort((a, b) => a - b))
    // 退役時間逐項附上（散文改結構化清單後的可掃描性依據）
    expect(message).toContain('退役於')
  })

  // uiux-keymgmt-r1 S1：本頁三處確認框皆屬不可逆／高後果操作，一律走 confirmDestructive。
  // 守的是「Enter 關掉這個框」＝執行銷毀的肌肉記憶（EP 預設 autofocus 落在確認鈕上）
  it('清理／輪替／放棄重包三處確認框皆關閉 autofocus 且確認鈕為 danger', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    getInventoryMock.mockResolvedValue(rotatedInventory({ rewrap_pending: true }))
    const wrapper = await mountPage()

    await findButton(wrapper, '放棄本次切換').trigger('click')
    await flushPromises()
    // 重包待切換會禁用輪替與清理：改以無 pending 的清冊再跑另外兩處
    getInventoryMock.mockResolvedValue(rotatedInventory())
    const wrapper2 = await mountPage()
    await findButton(wrapper2, '輪替資料加密鑰').trigger('click')
    await flushPromises()
    await findButton(wrapper2, '清理退役資料').trigger('click')
    await flushPromises()

    expect(confirmSpy.mock.calls).toHaveLength(3)
    for (const [, , options] of confirmSpy.mock.calls) {
      expect(options.autofocus).toBe(false)
      expect(options.confirmButtonClass).toBe('el-button--danger')
    }
    expect(wrapper.exists() && wrapper2.exists()).toBe(true)
  })
})

describe('KeyManagement 第一輪審查修正（未知態／確認清單）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
  })

  it('converge_state_error：未知態警示橫幅且清理按鈕保守禁用（不得假健康）', async () => {
    getInventoryMock.mockResolvedValue(inventoryFixture({ converge_state_error: true }))
    const wrapper = await mountPage()

    const alert = wrapper.findComponent({ name: 'ElAlert' })
    expect(wrapper.text()).toContain('金鑰收斂狀態未知')
    expect(alert.props('type')).toBe('warning')
    expect(findButton(wrapper, '清理退役資料').attributes('disabled')).toBeDefined()
    const tip = wrapper
      .findAllComponents({ name: 'ElTooltip' })
      .find((t) => String(t.props('content')).includes('狀態未知'))
    expect(tip, '未知態原因應以 tooltip 說明').toBeTruthy()
  })

  it('清理確認文案列明銷毀候選版本、退役 KEK 列數與重啟提醒', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    getInventoryMock.mockResolvedValue(
      inventoryFixture({
        keys: [
          { purpose: 'data', version: 1, status: 'retired', kek_id: 'abcd1234', age_days: 20, over_cryptoperiod: false, created_at: '2026-07-05T00:00:00Z', retired_at: '2026-07-20T00:00:00Z', material_purged: false },
          { purpose: 'data', version: 2, status: 'active', kek_id: 'abcd1234', age_days: 1, over_cryptoperiod: false, created_at: '2026-07-24T00:00:00Z' },
          // 已清理佔位：不得再列入銷毀候選
          { purpose: 'audit_integrity', version: 0, status: 'retired', kek_id: 'abcd1234', age_days: 30, over_cryptoperiod: false, created_at: '2026-07-01T00:00:00Z', retired_at: '2026-07-01T00:00:00Z', material_purged: true },
          { purpose: 'audit_integrity', version: 1, status: 'active', kek_id: 'abcd1234', age_days: 30, over_cryptoperiod: false, created_at: '2026-07-01T00:00:00Z' },
        ],
        kek_history: [
          { from_kek_id: 'deadbeef', to_kek_id: 'abcd1234', retired_at: '2026-07-25T00:00:00Z', rows: 3, material_rows: 3 },
        ],
      })
    )
    const wrapper = await mountPage()
    await findButton(wrapper, '清理退役資料').trigger('click')
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    const message = vnodeText(confirmSpy.mock.calls[0][0])
    expect(message).toContain('v1')
    expect(message).toContain('包裹列 3 筆')
    expect(message).toContain('重啟')
    // 已清理佔位（audit v0）不得出現在候選清單
    expect(message).not.toContain('v0')
    // 三段警語各自獨立、可掃描（H2）：不可逆警語與結尾提問不再混在同一段散文裡
    expect(message).toContain('此操作無法復原。')
    expect(message).toContain('確定清理？')
  })
})

// 註：「放棄成功後清值」無法非空泛地測——UI 上放棄鈕僅出現於對話框關閉後的
// 待切換橫幅，而關窗當下明文已由 @closed 清除，任何斷言都必然先綠（假綠形態）。
// 該時機為縱深防禦（未來若放棄入口移入對話框內即成為第一道），碼中已註明。

// operator-guidance-fidelity：完成切換的指示依**執行期 KEK provider** 分岔。
//
// 守衛的是一條安全性質，不是措辭偏好：ui 模式的不變式是金鑰材料永不落地，
// 而舊版精靈無條件指示「把新 KEK 存入 ENCRYPTION_KEY 後重啟」——ui 模式的使用者
// 照做即把根金鑰以明文寫上磁碟。故每個分支的斷言都成對：**正確指示要在**、
// **錯誤指示不得在**。只驗前者會讓「兩種指示並陳」這種修法假綠。
describe('KeyManagement 切換指示依 KEK provider 分岔', () => {
  // env 模式指示的判別句（本次不得改動其文案，故可作為逐字錨點）
  const ENV_INSTRUCTION = '將 ENCRYPTION_KEY 環境變數改為剛才保存的新 KEK'

  beforeEach(() => {
    vi.clearAllMocks()
    getPoliciesMock.mockResolvedValue(policyFixture())
    rewrapKEKMock.mockResolvedValue(rewrapResponseFixture())
  })

  // 走完精靈到第 3 步（完成頁＝最後步驟所在）
  const openRewrapFinalStep = async (wrapper) => {
    await openRewrapInputStep(wrapper)
    await setKekInputs(wrapper, VALID_KEK, VALID_KEK)
    await checkSavedConfirm(wrapper)
    await findButton(wrapper, '執行重包').trigger('click')
    await flushPromises()
  }

  const mountWithProvider = async (provider) => {
    getInventoryMock.mockResolvedValue(
      provider === undefined
        ? inventoryFixture({ provider: undefined })
        : inventoryFixture({ provider })
    )
    return mountPage()
  }

  it('env 模式：維持既有指示（寫入 ENCRYPTION_KEY 後重啟）', async () => {
    const wrapper = await mountWithProvider('env')
    await openRewrapFinalStep(wrapper)

    expect(wrapper.text()).toContain(ENV_INSTRUCTION)
    expect(wrapper.text()).toContain('重啟後端服務')
    // env 部署不該被導去解封頁——那是 ui 模式的路徑
    expect(wrapper.text()).not.toContain('在解封頁輸入剛才保存的新 KEK')
  })

  it('ui 模式：指示重啟後於解封頁輸入，且明確禁止寫入 .env', async () => {
    const wrapper = await mountWithProvider('ui')
    await openRewrapFinalStep(wrapper)

    expect(wrapper.text()).toContain('在解封頁輸入剛才保存的新 KEK')
    expect(wrapper.text()).toContain('不要把新 KEK 寫入 .env 或環境變數')
    // 有害指示必須消失。只是「不再指示錯事」不夠——使用者可能已在別處讀過 env 做法，
    // 故上一條的明確否定與本條的缺席兩者都要成立
    expect(wrapper.text()).not.toContain(ENV_INSTRUCTION)
  })

  it('ui 模式：精靈第 1 步的流程說明同樣走 ui 版（不只完成頁）', async () => {
    const wrapper = await mountWithProvider('ui')
    await findButton(wrapper, 'KEK 重包精靈').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('切勿把新 KEK 寫入')
    expect(wrapper.text()).not.toContain('你把新 KEK 存入')
  })

  it('kms 委託模式：指向營運文件，不給逐步指示', async () => {
    const wrapper = await mountWithProvider('kms')
    await openRewrapFinalStep(wrapper)

    expect(wrapper.text()).toContain('委託模式')
    expect(wrapper.text()).toContain('docs/ops/privileged-credential-rotation.md')
    expect(wrapper.text()).not.toContain(ENV_INSTRUCTION)
    expect(wrapper.text()).not.toContain('在解封頁輸入剛才保存的新 KEK')
  })

  it('hsm 委託模式：與 kms 同走委託分支', async () => {
    const wrapper = await mountWithProvider('hsm')
    await openRewrapFinalStep(wrapper)

    expect(wrapper.text()).toContain('docs/ops/privileged-credential-rotation.md')
    expect(wrapper.text()).not.toContain(ENV_INSTRUCTION)
    expect(wrapper.text()).not.toContain('在解封頁輸入剛才保存的新 KEK')
  })

  it('provider 取不到：列出各模式做法，不回落 env 版本', async () => {
    const wrapper = await mountWithProvider(undefined)
    await openRewrapFinalStep(wrapper)

    expect(wrapper.text()).toContain('請依部署的 KEK_PROVIDER 選擇對應做法')
    expect(wrapper.text()).toContain('env 模式：')
    expect(wrapper.text()).toContain('ui 模式：')
    expect(wrapper.text()).toContain('kms／hsm 委託模式：')
    // fail-safe 的方向：不得逕自呈現 env 版本的「最後兩步」
    expect(wrapper.text()).not.toContain('最後兩步（在部署主機上執行）')
  })

  it('未知的新 provider 值走 fail-safe，不被歸類為 env', async () => {
    const wrapper = await mountWithProvider('tpm')
    await openRewrapFinalStep(wrapper)

    expect(wrapper.text()).toContain('請依部署的 KEK_PROVIDER 選擇對應做法')
    expect(wrapper.text()).not.toContain('最後兩步（在部署主機上執行）')
  })

  it('待切換橫幅：ui 模式指向解封頁而非環境變數', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({ provider: 'ui', rewrap_pending: true })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('在解封頁輸入你在精靈輸入的那把新 KEK')
    expect(wrapper.text()).not.toContain('請將你在精靈輸入的新 KEK 存入 ENCRYPTION_KEY 環境變數')
  })

  it('切換待生效橫幅：ui 模式指向解封頁而非環境變數', async () => {
    getInventoryMock.mockResolvedValue(
      inventoryFixture({ provider: 'ui', finalize_pending: 2 })
    )
    const wrapper = await mountPage()

    expect(wrapper.text()).toContain('在解封頁輸入新 KEK 完成切換')
    expect(wrapper.text()).not.toContain('請將新 KEK 存入 ENCRYPTION_KEY 後重啟後端服務')
  })
})
