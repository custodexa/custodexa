import { describe, it, expect, vi, beforeEach } from 'vitest'

// 「套用電支基準」的取嚴語義（security-backlog-settlement 塊 6）。
//
// **這是本塊唯一容易做錯的地方**：兩基準在部分項目上方向相反——密碼最小長度
// PCI 要求 >=12、電支只要求 >=6。若套用實作為「無條件填入 epayment_value」，
// 一個已設 12 的系統會被改成 6，「套用合規基準」這個動作反而降低了安全性。
//
// 前端填入的必須是後端算好的 `strictest_value`（兩基準取嚴），不是 `epayment_value`。

vi.mock('element-plus', () => ({
  ElMessage: { info: vi.fn(), success: vi.fn(), warning: vi.fn(), error: vi.fn() },
  ElMessageBox: { confirm: vi.fn(() => Promise.resolve()) },
}))

const getSecurityPolicies = vi.fn()
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getSecurityPolicies(...a),
  updateSecurityPolicies: vi.fn(),
}))

vi.mock('@/i18n', () => ({
  t: (k) => k,
  currentLocale: () => 'zh-TW',
}))

const { usePolicyForm } = await import('../usePolicyForm')

// 兩個真實政策項：一個電支較寬（密碼長度），一個電支較嚴（鎖定次數）。
// strictest_value 由後端算，此處以後端實際會回的值 fixture 化
const POLICIES = [
  {
    key: 'password_min_length',
    type: 'int',
    value: '12',
    default: '12',
    direction: 'min',
    pci_value: '12',
    epayment_value: '6', // 寬於 PCI
    strictest_value: '12', // 取嚴 → 維持 12
    compliant: true,
    epayment_compliant: true,
    label: '密碼最小長度',
  },
  {
    key: 'lockout_max_attempts',
    type: 'int',
    value: '10',
    default: '10',
    direction: 'max',
    zero_disables: true,
    pci_value: '10',
    epayment_value: '5', // 嚴於 PCI
    strictest_value: '5',
    compliant: true,
    epayment_compliant: false, // 10 > 5
    label: '登入失敗鎖定次數上限',
  },
]

const SECTIONS = [
  { title: '測試區塊', hint: '', keys: ['password_min_length', 'lockout_max_attempts'] },
]

describe('usePolicyForm：套用電支基準取兩基準較嚴值', () => {
  beforeEach(() => {
    getSecurityPolicies.mockReset()
    getSecurityPolicies.mockResolvedValue({
      data: POLICIES.map((p) => ({ ...p })),
      deviation_count: 0,
      epayment_deviation_count: 1,
    })
  })

  it('電支較寬的項目不被下調（密碼長度維持 12，不得變成 6）', async () => {
    const form = usePolicyForm(SECTIONS)
    await form.loadPolicies()

    form.applyPageEPayment()

    expect(form.formValues.value.password_min_length).toBe(12)
    expect(form.formValues.value.password_min_length).not.toBe(6)
  })

  it('電支較嚴的項目被收緊（鎖定次數 10 → 5）', async () => {
    const form = usePolicyForm(SECTIONS)
    await form.loadPolicies()

    form.applyPageEPayment()

    expect(form.formValues.value.lockout_max_attempts).toBe(5)
  })

  it('套用 PCI 基準維持既有語義（填入 pci_value，不受電支欄影響）', async () => {
    const form = usePolicyForm(SECTIONS)
    await form.loadPolicies()

    form.applyPagePCI()

    expect(form.formValues.value.password_min_length).toBe(12)
    expect(form.formValues.value.lockout_max_attempts).toBe(10)
  })

  it('電支偏離數與 PCI 偏離數各自獨立計算', async () => {
    const form = usePolicyForm(SECTIONS)
    await form.loadPolicies()

    // 現值：密碼 12（兩基準皆符）、鎖定 10（符 PCI、偏離電支）
    expect(form.pageDeviationCount.value).toBe(0)
    expect(form.pageEPaymentDeviationCount.value).toBe(1)
  })

  it('無 strictest_value 的項目被略過（不寫入 undefined）', async () => {
    getSecurityPolicies.mockResolvedValue({
      data: [{ ...POLICIES[0], strictest_value: '', epayment_value: '' }],
      deviation_count: 0,
      epayment_deviation_count: 0,
    })
    const form = usePolicyForm([{ title: 'x', hint: '', keys: ['password_min_length'] }])
    await form.loadPolicies()

    form.applyPageEPayment()

    expect(form.formValues.value.password_min_length).toBe(12)
  })
})
