import { describe, it, expect, vi, afterEach } from 'vitest'
import i18n from '@/i18n'
import {
  policyLabel,
  policyMin,
  policyUnit,
  formatValue,
  isNonCompliantEPayment,
  isNonCompliantValue,
} from '@/utils/policyFormat'

function setLocale(l) {
  i18n.global.locale.value = l
}
afterEach(() => vi.restoreAllMocks())

describe('policyLabel — key 錨點查譯 + 降級', () => {
  const p = { key: 'lockout_max_attempts', label: '登入失敗鎖定次數上限' }

  it('zh：查 policyLabel.<key>', () => {
    expect(policyLabel(p)).toBe('登入失敗鎖定次數上限')
  })

  it('en：切語言得英文', () => {
    setLocale('en-US')
    expect(policyLabel(p)).toBe('Max failed login attempts')
  })

  it('未知 key → 降級後端 label + dev warn', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    setLocale('en-US')
    expect(policyLabel({ key: 'made_up', label: '後端中文' })).toBe('後端中文')
    expect(warn).toHaveBeenCalled()
  })

  it('無 key → label', () => {
    expect(policyLabel({ label: 'x' })).toBe('x')
  })

  it('prod：缺鍵靜默不 warn（rr-Minor3）', () => {
    vi.stubEnv('DEV', false)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    setLocale('en-US')
    expect(policyLabel({ key: 'made_up', label: '後端中文' })).toBe('後端中文')
    expect(warn).not.toHaveBeenCalled()
    vi.unstubAllEnvs()
  })
})

describe('policyUnit — unit_key 查譯 + 降級不回空字串（rr-I9）', () => {
  it('zh/en：查 policyUnit.<unit_key>', () => {
    expect(policyUnit({ unit_key: 'minutes', unit: '分鐘' })).toBe('分鐘')
    setLocale('en-US')
    expect(policyUnit({ unit_key: 'minutes', unit: '分鐘' })).toBe('minutes')
  })

  it('無 unit_key（舊後端）→ 回 unit，不回空字串', () => {
    setLocale('en-US')
    expect(policyUnit({ unit: '分鐘' })).toBe('分鐘')
  })

  it('未知 unit_key → 回 unit', () => {
    setLocale('en-US')
    expect(policyUnit({ unit_key: 'made_up', unit: '分鐘' })).toBe('分鐘')
  })

  it('formatValue int 型用 policyUnit', () => {
    setLocale('en-US')
    expect(formatValue({ type: 'int', unit_key: 'minutes', unit: '分鐘' }, 30)).toBe('30 minutes')
  })
})

// policyMin：下界要在輸入當下就擋住，
// 不能只靠存檔時的後端驗證
describe('policyMin — 數值輸入框下界', () => {
  it('非 zero_disables 且有 min → 用 min（三個搬遷鍵的實際形態）', () => {
    expect(policyMin({ key: 'retention_max_per_run', min: 5000, max: 10000000 })).toBe(5000)
    expect(policyMin({ key: 'key_rotation_max_per_run', min: 500, max: 10000000 })).toBe(500)
    expect(policyMin({ key: 'k8s_list_timeout_seconds', min: 3, max: 300 })).toBe(3)
  })

  it('非 zero_disables 且無 min → 沿用既有的 1', () => {
    expect(policyMin({ key: 'access_request_min_approvals', max: 10 })).toBe(1)
  })

  it('zero_disables → 0（0 是明著關閉的合法值）', () => {
    expect(policyMin({ key: 'retention_audit_log_days', zero_disables: true, max: 3650 })).toBe(0)
  })

  it('zero_disables 蓋過 min（值域不連續，輸入框只表達得了連續區間）', () => {
    expect(policyMin({ key: 'hypothetical', zero_disables: true, min: 10 })).toBe(0)
  })

  it('無 policy → 回 1，不回 undefined', () => {
    expect(policyMin(null)).toBe(1)
  })
})

// 文字型鍵沒有合規基準建議值：符合性比對必須短路回 false，
// 不得落到 enum 分支（那裡以 enum_order 的索引比大小，對自由文字沒有意義）
describe('符合性比對 — 文字型鍵短路', () => {
  const textPolicy = {
    key: 'login_banner_body',
    type: 'text',
    max_length: 2000,
    multiline: true,
    compliant: null,
    epayment_compliant: null,
  }

  it('值未改動時不因缺基準而判為偏離', () => {
    expect(isNonCompliantValue(textPolicy, '告示', '告示')).toBe(false)
    expect(isNonCompliantEPayment(textPolicy, '告示', '告示')).toBe(false)
  })

  it('編輯中的值也一律回 false（無基準可比）', () => {
    expect(isNonCompliantValue(textPolicy, '新內文', '舊內文')).toBe(false)
    expect(isNonCompliantEPayment(textPolicy, '新內文', '舊內文')).toBe(false)
  })

  it('清空與含換行的長文同樣不判偏離', () => {
    expect(isNonCompliantValue(textPolicy, '', '舊內文')).toBe(false)
    expect(isNonCompliantValue(textPolicy, '第一行\n第二行', '')).toBe(false)
  })
})
