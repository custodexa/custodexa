/**
 * 後端 API 錯誤的共用解析（i18n-backend-error-codes）。
 * 攔截器與直讀 data.error 的呼叫端共用同一函式，三層降級：
 *   1. 合法 code 且 apiError.<code> 有當前語言譯文 → 顯示譯文（params 語義 ID 經 enum 查譯後插值）
 *   2. 否則後端 error 欄（僅接受非空字串，防非字串進 Element Plus）
 *   3. 否則通用狀態訊息
 * 後端未 code 化的錯誤沿用第 2 層，達成零迴歸。
 */
import i18n, { t } from '@/i18n'
import { auditResourceLabel } from '@/constants/audit-enums'
import { roleLabel } from '@/constants/roles'

// 與後端 apierror.CodeGrammar 一致；不符者不送入 vue-i18n path（防 '.'/'[' 汙染、超長）
const CODE_GRAMMAR = /^[A-Z][A-Z0-9_]{0,63}$/

// param key → 前端 enum 標籤 getter 的固定映射。
// 數值型 param 無 getter，原樣帶入；未知 key 亦原樣（後端已 schema 驗、值受控）。
const PARAM_ENUM_GETTERS = {
  resource: auditResourceLabel,
  role: roleLabel,
}

function translateParams(params) {
  if (!params || typeof params !== 'object') return {}
  const out = {}
  for (const [key, value] of Object.entries(params)) {
    const getter = PARAM_ENUM_GETTERS[key]
    out[key] = getter ? getter(value) : value
  }
  return out
}

/**
 * 解析後端錯誤回應為使用者可讀字串。
 * @param {object|undefined} data 後端回應 body（{ error, code?, params? }）
 * @param {number|undefined} status HTTP 狀態碼
 * @param {string} [fallback] 呼叫端專屬第三層 fallback（省略時用通用狀態訊息）
 * @returns {string}
 */
export function resolveApiError(data, status, fallback) {
  const code = data?.code
  if (code && CODE_GRAMMAR.test(code)) {
    if (i18n.global.te(`apiError.${code}`)) {
      return t(`apiError.${code}`, translateParams(data.params))
    }
    // 合法 code 卻查無譯文：偵測譯文退化（後端發碼、前端漏補）。開發期警告、
    // 正式環境靜默退回 error fallback（不外洩、不阻斷）。
    if (import.meta.env?.DEV) {
      console.warn(`[apiError] 後端 code "${code}" 無前端譯文，退回後端 error`)
    }
  }
  const err = data?.error
  if (typeof err === 'string' && err.trim()) return err
  return fallback || t('api.requestFailedStatus', { status })
}
