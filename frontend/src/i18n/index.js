/**
 * 前端 i18n 唯一入口（i18n-foundation）。
 * zh-TW 為譯文事實源；en-US/ja-JP 與其 key 集合完全對齊（結構單測釘住）。
 * 語言偏好存 localStorage `ot-lang`（裝置級、不分角色——登入前就要生效）。
 */
import { watch } from 'vue'
import { createI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import zhTW from './locales/zh-TW.json'
import enUS from './locales/en-US.json'
import jaJP from './locales/ja-JP.json'

export const SUPPORTED_LOCALES = ['zh-TW', 'en-US', 'ja-JP']
export const DEFAULT_LOCALE = 'zh-TW'
export const LANG_STORAGE_KEY = 'ot-lang'

// 語言原生名：切換選單恆以各語言自身文字顯示，不隨介面語言翻譯
export const LOCALE_LABELS = {
  'zh-TW': '繁體中文',
  'en-US': 'English',
  'ja-JP': '日本語',
}

// 讀取順序：有效 ot-lang > navigator 前綴（zh→zh-TW、ja→ja-JP、其餘→en-US）> zh-TW。
// 無效/舊版存值視為未設定（防 ot-lang=fr-FR 把 i18n 與 EP 映射打成 undefined）
export function resolveInitialLocale() {
  const stored = localStorage.getItem(LANG_STORAGE_KEY)
  if (stored && SUPPORTED_LOCALES.includes(stored)) return stored
  const nav = (typeof navigator !== 'undefined' && navigator.language) || ''
  if (nav.startsWith('zh')) return 'zh-TW'
  if (nav.startsWith('ja')) return 'ja-JP'
  if (nav) return 'en-US'
  return DEFAULT_LOCALE
}

const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  locale: resolveInitialLocale(),
  fallbackLocale: {
    'ja-JP': ['en-US', 'zh-TW'],
    default: ['zh-TW'],
  },
  messages: {
    'zh-TW': zhTW,
    'en-US': enUS,
    'ja-JP': jaJP,
  },
  missingWarn: import.meta.env.DEV,
  fallbackWarn: false,
})

/** 切換語言：僅接受支援清單內的值；即時生效（免 reload）並持久化 */
export function setLanguage(lang) {
  if (!SUPPORTED_LOCALES.includes(lang)) return
  i18n.global.locale.value = lang
  localStorage.setItem(LANG_STORAGE_KEY, lang)
}

export function currentLocale() {
  return i18n.global.locale.value
}

// 非元件模組共用的 t（render 期呼叫可被依賴追蹤，切語言自動重繪）
export const t = (...args) => i18n.global.t(...args)

// te：鍵是否存在。用於「後端回機器碼、前端查表；查無則原樣顯示」這類
// 需要先探測再決定的場景——直接呼叫 t 會在 DEV 噴 missing 警告
export const te = (...args) => i18n.global.te(...args)

/**
 * document metadata 隨語言切換（codex r1 F4/F8）：title 與 <html lang>
 * 不可只在模組載入時賦值一次——watch immediate 集中更新
 */
export function setupDocumentMetadata() {
  watch(
    () => i18n.global.locale.value,
    (lang) => {
      document.title = `${BRAND.name} - ${i18n.global.t('brand.subtitle')}`
      document.documentElement.lang = lang
    },
    { immediate: true }
  )
}

export default i18n
