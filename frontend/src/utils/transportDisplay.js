// 傳輸風險 label 與清冊 note/preflight/detail 的查譯。
// 錨定後端穩定機器碼（risk.key、note_code、preflight_code、detail_codes 的鍵），
// 當前語言精確命中且 required params 齊全才譯，否則降級後端 zh 字串。四頁與資產列表、
// 連線同意、告警、syslog 卡共用同源。
import { t } from '@/i18n'
import {
  translated,
  hasCurrentTranslation,
  warnMissingTranslation,
  paramsPresent,
} from '@/utils/i18nDisplay'

// 各碼所需 params（鏡射後端 registry RequiredParams）：缺參數時降級回後端 zh，
// 避免 vue-i18n 對缺 named param 渲染空字串而露殘缺文案。export 供跨層防漂移測試
// （transportDisplay.spec 從 locale placeholder 導出比對，locale 又由後端完備性測試釘死
//  ↔ registry，形成 registry↔locale↔前端常數 閉環）。
export const RISK_REQUIRED_PARAMS = { syslog_non_tls: ['protocol'] }
export const NOTE_REQUIRED_PARAMS = { syslog_protocol: ['protocol'] }
// 帶 {n}（vue-i18n 隱式 plural 參數）的 preflight 碼
export const PREFLIGHT_COUNT_CODES = new Set(['rdp_reject', 'vnc_reject', 'db_reject'])

// riskLabel 風險項顯示（徽章／同意／確認）：params 由 caller 從自身 context 供
//（如 syslog 的 {protocol}）。無 params 需求者傳 undefined 即可。
export function riskLabel(risk, params) {
  if (!risk) return ''
  const code = risk.key
  const key = `riskLabel.${code}`
  if (code && paramsPresent(RISK_REQUIRED_PARAMS[code], params)) {
    const v = translated(key, () => t(key, params || {}))
    if (v != null) return v
  }
  if (code) warnMissingTranslation(key, code)
  return risk.label || code || ''
}

// inventoryNote 清冊通道說明：優先 note_code 查譯，缺則後端 note。
export function inventoryNote(ch) {
  if (!ch) return ''
  const code = ch.note_code
  if (!code) return ch.note || ''
  const key = `transportNote.${code}`
  if (paramsPresent(NOTE_REQUIRED_PARAMS[code], ch.note_params)) {
    const v = translated(key, () => t(key, ch.note_params || {}))
    if (v != null) return v
  }
  warnMissingTranslation(key, code)
  return ch.note || ''
}

// inventoryPreflight 清冊 strict 預檢：帶 {n} 者走 vue-i18n 隱式 plural（t(key, n)），
// ldap_reject 無參。n 缺或非整數時降級後端 strict_preflight。
export function inventoryPreflight(ch) {
  if (!ch) return ''
  const code = ch.preflight_code
  if (!code) return ch.strict_preflight || ''
  const key = `transportPreflight.${code}`
  let v = null
  if (!PREFLIGHT_COUNT_CODES.has(code)) {
    v = translated(key, () => t(key))
  } else {
    const n = ch.preflight_params?.n
    if (Number.isInteger(n)) v = translated(key, () => t(key, n))
  }
  if (v != null) return v
  warnMissingTranslation(key, code)
  return ch.strict_preflight || ''
}

// inventoryDetail 清冊明細：有 detail_codes 則整份採用之——逐鍵
// transportDetail.<code> 命中則譯（如 unset），否則原樣（技術複合鍵語言中性）；
// 無 detail_codes（舊後端）才回舊 detail。回傳 {顯示鍵: 數量} 供模板 v-for。
export function inventoryDetail(ch) {
  if (!ch) return {}
  const codes = ch.detail_codes
  if (!codes) return ch.detail || {}
  const out = {}
  for (const [code, count] of Object.entries(codes)) {
    const key = `transportDetail.${code}`
    const label = hasCurrentTranslation(key) ? t(key) : code
    // 累加而非覆蓋：多個 code 映到同一顯示鍵時 count 守恆
    out[label] = (out[label] || 0) + count
  }
  return out
}
