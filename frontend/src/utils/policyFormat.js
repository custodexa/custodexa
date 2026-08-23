// 安全政策鍵的呈現與換算純函式：
// 四個設定域頁與共用元件同源，避免 enum 文案與符合性判定跨頁複製。
// 譯文住 locale 檔 enum.policyEnum/transportLevel/accessPolicy.*

import { t } from '@/i18n'
import { translated, warnMissingTranslation } from '@/utils/i18nDisplay'

// policyLabel 政策項顯示名：錨定既有 policy.key，當前語言有
// 非空 policyLabel.<key> 才譯，否則後端 label（zh fallback），再缺回 key。getter 內呼 t()
// → render/computed 取值被依賴追蹤，切語言自動重繪。
export function policyLabel(policy) {
  if (!policy) return ''
  if (policy.key) {
    const key = `policyLabel.${policy.key}`
    const v = translated(key, () => t(key))
    if (v != null) return v
    warnMissingTranslation(key, policy.key)
  }
  return policy.label || policy.key || ''
}

// policyNote 政策項的生效時機／適用範圍附註（data-transfer-control 6.1）。
//
// 為何是逐鍵附註而非區塊 hint：資料傳輸區塊裡剪貼簿兩鍵「需重新連線才生效」、
// 檔案三鍵「即時生效」，兩種時機並存於同一區塊——只寫在區塊層等於要使用者
// 自己分辨哪句話管哪一列。無 policyNote.<key> 譯文者回空字串（不顯示），
// 故本機制對其餘政策鍵零影響。
export function policyNote(policy) {
  if (!policy?.key) return ''
  const key = `policyNote.${policy.key}`
  const v = translated(key, () => t(key))
  return v == null ? '' : v
}

// policyUnit 單位：無 unit_key／當前語言無鍵／空 → 一律回
// policy.unit（zh fallback），不回空字串。
export function policyUnit(policy) {
  if (!policy) return ''
  if (policy.unit_key) {
    const key = `policyUnit.${policy.unit_key}`
    const v = translated(key, () => t(key))
    if (v != null) return v
    warnMissingTranslation(key, policy.unit_key)
  }
  return policy.unit || ''
}

const localizedEnum = (ns, values) => {
  const map = {}
  for (const value of values) {
    Object.defineProperty(map, value, {
      enumerable: true,
      get: () => t(`enum.${ns}.${value}`),
    })
  }
  return map
}

const enumLabels = localizedEnum('policyEnum', ['off', 'admin_only', 'all'])

// 傳輸等級鍵的枚舉文案：off 與 mfa 的「未啟用」語義不同
const transportEnumLabels = localizedEnum('transportLevel', ['off', 'warn', 'strict'])

// 存取政策段位文案：白話呈現三段語義
export const accessPolicyEnumLabels = localizedEnum('accessPolicy', [
  'open',
  'reason',
  'approval',
])

export const enumLabel = (policy, option) => {
  if (policy.key.startsWith('transport_')) {
    return transportEnumLabels[option] || option
  }
  if (policy.key === 'access_policy_default') {
    return accessPolicyEnumLabels[option] || option
  }
  return enumLabels[option] || option
}

export const toFormValue = (policy) => {
  if (policy.type === 'int') return Number(policy.value)
  if (policy.type === 'bool') return policy.value === 'true'
  return policy.value
}

export const toApiValue = (policy, value) => {
  if (policy.type === 'int') return String(value)
  if (policy.type === 'bool') return value ? 'true' : 'false'
  return value
}

export const formatValue = (policy, raw) => {
  if (policy.type === 'bool')
    return raw === 'true' ? t('policyValue.on') : t('policyValue.off')
  if (policy.type === 'enum') return enumLabel(policy, raw)
  return `${raw} ${policyUnit(policy)}`.trim()
}

// policyMin 數值輸入框的下界。
//
// 後端的合法值域是 `{0 若 zero_disables} ∪ [min, max]`——**不連續**，而數字
// 輸入框只表達得了連續區間。兩種情形分開處理：
//   - zero_disables：下界取 0（0 是明著關閉的合法值）。此時若該鍵另有 min，
//     1..min-1 仍可鍵入但會被後端擋下——目前無此類鍵，真出現時應改用
//     能表達不連續值域的控制項，而不是在這裡靜默夾值（夾值會讓畫面顯示的
//     數字與使用者輸入的不同而未告知）。
//   - 非 zero_disables：下界即 min；未設 min 時沿用既有的 1。
//
// **下界要在輸入當下就擋住**，不能只靠存檔時的後端驗證：管理員把清理上限
// 打成 1 卻要等存檔才知道不行，等於把「這個值會讓機制停擺」的資訊藏到最後一步
export const policyMin = (policy) => {
  if (!policy) return 1
  if (policy.zero_disables) return 0
  return policy.min || 1
}

// 保留天數鍵的 0 是「永久保留」語義、
// 金鑰提醒鍵的 0 是「不提醒」，
// 與其他鍵的「0 = 停用」區分標註
export const zeroHelperText = (policy) => {
  if (policy.key.startsWith('retention_')) return t('policyValue.zeroRetention')
  if (policy.key === 'key_cryptoperiod_reminder_days')
    return t('policyValue.zeroKeyReminder')
  if (policy.key === 'transport_consent_ttl_days')
    return t('policyValue.zeroConsentTtl')
  return t('policyValue.zeroDisable')
}

// 未儲存的編輯即時反映符合性（儲存後以後端計算為準）。
// 基準值與後端已算好的符合性欄位由呼叫端指定，使兩個基準共用同一套比較邏輯
// （複製比較邏輯會使兩側日後漂移）
const isNonCompliantAgainst = (policy, value, savedValue, baseline, backendCompliant) => {
  if (value === savedValue) {
    return backendCompliant === false
  }
  if (!baseline) return false
  if (policy.type === 'int') {
    const base = Number(baseline)
    if (policy.zero_disables && value === 0) return true
    return policy.direction === 'min' ? value < base : value > base
  }
  if (policy.type === 'bool') {
    return toApiValue(policy, value) !== baseline
  }
  const order = policy.enum_order || []
  return order.indexOf(value) < order.indexOf(baseline)
}

// 對 PCI 建議值的符合性
export const isNonCompliantValue = (policy, value, savedValue) =>
  isNonCompliantAgainst(policy, value, savedValue, policy.pci_value, policy.compliant)

// 對電支基準建議值的符合性。與 PCI 各自獨立——同一項可能符合其一而偏離另一
export const isNonCompliantEPayment = (policy, value, savedValue) =>
  isNonCompliantAgainst(
    policy,
    value,
    savedValue,
    policy.epayment_value,
    policy.epayment_compliant
  )
