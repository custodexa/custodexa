// 後端顯示字串查譯共用工具。
// 三類後端顯示字串（policy label/unit、risk label、inventory note/preflight）皆錨定穩定
// 機器碼、前端查譯，共用「當前語言精確命中才譯，否則降級後端 zh」的規則。
import i18n, { currentLocale } from '@/i18n'

// hasCurrentTranslation 當前語言精確命中檢查：明確帶 currentLocale，不走
// vue-i18n 的 ja→en→zh fallback——缺鍵時降級回後端 zh，而非誤命中他語譯文。
export function hasCurrentTranslation(key) {
  return i18n.global.te(key, currentLocale())
}

// translated 精確命中且產出非空（且非退回 key path）才回譯文，否則 null（供 getter 降級）。
// produce 由各 getter 自訂（t(key)／t(key,params)／t(key,n)），涵蓋「存在但值為空」契約
// （te 對空值仍為 true）。
export function translated(key, produce) {
  if (!hasCurrentTranslation(key)) return null
  const v = produce()
  return v && v !== key ? v : null
}

// warnMissingTranslation dev 期缺鍵告警（比照 resolveApiError），prod 靜默降級。
export function warnMissingTranslation(key, code) {
  if (import.meta.env?.DEV) {
    // eslint-disable-next-line no-console
    console.warn(`[i18n-labels] "${key}" 無當前語言譯文，退回後端 zh（code ${code}）`)
  }
}

// paramsPresent required 參數是否齊全（缺則降級，避免 vue-i18n 對缺 named param
// 渲染空字串而露殘缺文案，如 "val ()"）。required 為空即視為齊全。
export function paramsPresent(required, params) {
  if (!required || !required.length) return true
  return required.every((p) => params && params[p] != null && params[p] !== '')
}
