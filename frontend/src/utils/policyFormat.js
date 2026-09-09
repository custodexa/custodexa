// 安全政策鍵的呈現與換算純函式：
// 五個設定域頁與共用元件同源，避免 enum 文案與要求句型跨頁複製。
// 符合性判定不在這裡——它由後端的判定契約供給，前端只投影。
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

// expectationText 政策組對某個鍵的要求，寫成一句人話。
//
// 抽屜的逐組要求與套用預覽的衝突說明共用這一支：同一件事在兩個畫面上寫成兩種
// 說法，管理者會以為它們指的不是同一條規則。整數型才有方向（至少／至多），
// 開關與枚舉只能是明確值；未定值（review）沒有可寫的要求，由呼叫端另外處理
export const expectationText = (policy, comparator, expected) => {
  const value = formatValue(policy, expected)
  if (comparator === 'min') return t('policyDrawer.expectMin', { value })
  if (comparator === 'max') return t('policyDrawer.expectMax', { value })
  return t('policyDrawer.expectEquals', { value })
}

// 零值有特別語義的鍵 → 那個語義的譯文鍵。
//
// 「0」在不同鍵上不是同一件事：保留天數的 0 是永久保留，鎖定次數的 0 是不啟用
// 這項限制。合規頁與政策組管理頁只印一個「0」，非專業讀者無從分辨；印錯一邊
// 比不印更糟，故逐鍵登記而不用單一句子涵蓋全部。
const ZERO_MEANING_KEYS = {
  retention_audit_log_days: 'retention',
  retention_session_command_days: 'retention',
  retention_alert_days: 'retention',
  retention_recording_days: 'retention',
  retention_checkpoint_days: 'retention',
  offsite_local_retention_days: 'localRetention',
  key_cryptoperiod_reminder_days: 'keyReminder',
  transport_consent_ttl_days: 'consentTtl',
}

// zeroMeaning 某鍵的 0 是什麼意思；沒有停用語義的鍵回空字串
export const zeroMeaning = (key, zeroDisables) => {
  if (!zeroDisables) return ''
  const variant = ZERO_MEANING_KEYS[key] || 'disabled'
  return t(`policyZero.${variant}`)
}

// formatKeyValue 只知道鍵與一個字串值時的人話呈現（判定結果與條文要求共用）。
//
// 與 formatValue 的差別在輸入：那一支拿得到完整的 policy 物件，這一支只拿得到
// 判定回應帶的顯示中繼資料（unit_key、zero_disables）。兩支都在本檔，單位與
// 零值語義因此只有一份寫法——設定頁、合規頁與管理頁不會各自長出一套。
//
// @param {string} key 政策鍵
// @param {string} raw 值（字串）
// @param {Object} [meta] { unit_key, unit, zero_disables }
export const formatKeyValue = (key, raw, meta = {}) => {
  const text = String(raw)
  if (raw === 'true') return t('policyValue.on')
  if (raw === 'false') return t('policyValue.off')
  if (!/^-?\d+$/.test(text)) return enumLabel({ key: key || '' }, raw)
  const unit = policyUnit({ unit_key: meta.unit_key, unit: meta.unit })
  const withUnit = unit ? `${text} ${unit}` : text
  if (text !== '0') return withUnit
  const meaning = zeroMeaning(key, meta.zero_disables)
  return meaning ? `${withUnit}（${meaning}）` : withUnit
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
