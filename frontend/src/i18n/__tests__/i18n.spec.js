// i18n 骨架單測：
// 解析順序、無效存值、fallback 鏈確定性、三語 key 對齊、document metadata、
// singleton locale 汙染防護（順序獨立）
import { describe, it, expect, afterEach, vi } from 'vitest'
import i18n, {
  DEFAULT_LOCALE,
  LANG_STORAGE_KEY,
  resolveInitialLocale,
  setLanguage,
  setupDocumentMetadata,
  t,
} from '@/i18n'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// 對齊測試讀磁碟原始檔：runtime messages 與 import 共用同一物件，
// mergeLocaleMessage 探針會污染 module 快取，import 版本不可作對齊基準。
// 路徑以 cwd（frontend 根）為錨——vitest 轉換後的 import.meta.url 非真實檔案路徑
const loadLocale = (name) =>
  JSON.parse(
    readFileSync(join(process.cwd(), 'src/i18n/locales', `${name}.json`), 'utf8')
  )
const zhTW = loadLocale('zh-TW')
const enUS = loadLocale('en-US')
const jaJP = loadLocale('ja-JP')

const leafKeys = (obj, prefix = '') =>
  Object.entries(obj).flatMap(([k, v]) =>
    v && typeof v === 'object'
      ? leafKeys(v, `${prefix}${k}.`)
      : [`${prefix}${k}`]
  )

const withNavigatorLanguage = (lang, fn) => {
  const spy = vi
    .spyOn(window.navigator, 'language', 'get')
    .mockReturnValue(lang)
  try {
    fn()
  } finally {
    spy.mockRestore()
  }
}

describe('resolveInitialLocale 解析順序', () => {
  afterEach(() => {
    localStorage.removeItem(LANG_STORAGE_KEY)
  })

  it('有效 ot-lang 優先於瀏覽器語言', () => {
    localStorage.setItem(LANG_STORAGE_KEY, 'ja-JP')
    withNavigatorLanguage('en-US', () => {
      expect(resolveInitialLocale()).toBe('ja-JP')
    })
  })

  it('無 ot-lang 時走瀏覽器前綴比對（zh→zh-TW、ja→ja-JP、其餘→en-US）', () => {
    withNavigatorLanguage('zh-CN', () => {
      expect(resolveInitialLocale()).toBe('zh-TW')
    })
    withNavigatorLanguage('ja', () => {
      expect(resolveInitialLocale()).toBe('ja-JP')
    })
    withNavigatorLanguage('fr-FR', () => {
      expect(resolveInitialLocale()).toBe('en-US')
    })
  })

  it('無效存值（fr-FR/空字串）視為未設定，續走瀏覽器偵測', () => {
    localStorage.setItem(LANG_STORAGE_KEY, 'fr-FR')
    withNavigatorLanguage('en-GB', () => {
      expect(resolveInitialLocale()).toBe('en-US')
    })
    localStorage.setItem(LANG_STORAGE_KEY, '')
    withNavigatorLanguage('ja-JP', () => {
      expect(resolveInitialLocale()).toBe('ja-JP')
    })
  })
})

describe('setLanguage', () => {
  afterEach(() => {
    localStorage.removeItem(LANG_STORAGE_KEY)
  })

  it('切換即時生效並持久化 ot-lang', () => {
    setLanguage('en-US')
    expect(i18n.global.locale.value).toBe('en-US')
    expect(localStorage.getItem(LANG_STORAGE_KEY)).toBe('en-US')
    expect(t('menu.users')).toBe('Users')
  })

  it('拒絕不支援的語言值（不改 locale、不寫入）', () => {
    setLanguage('fr-FR')
    expect(i18n.global.locale.value).toBe(DEFAULT_LOCALE)
    expect(localStorage.getItem(LANG_STORAGE_KEY)).toBeNull()
  })
})

describe('fallback 鏈（確定性案例）', () => {
  const KEY = '__fallbackProbe'

  afterEach(() => {
    // mergeLocaleMessage 無對應移除 API：探針 key 以覆寫空物件的方式隔離於
    // 各案例自行設定，測後重設 locale 即可（探針不影響三語對齊測試——那組
    // 直接讀 JSON 檔）
    i18n.global.locale.value = DEFAULT_LOCALE
  })

  it('ja 缺 key、en 有 → 顯示 en 文字', () => {
    i18n.global.mergeLocaleMessage('zh-TW', { [KEY]: '中文值' })
    i18n.global.mergeLocaleMessage('en-US', { [KEY]: 'english value' })
    i18n.global.locale.value = 'ja-JP'
    expect(t(KEY)).toBe('english value')
  })

  it('ja 與 en 都缺 → 落到 zh-TW，永不顯示裸 key', () => {
    const KEY2 = '__fallbackProbeZhOnly'
    i18n.global.mergeLocaleMessage('zh-TW', { [KEY2]: '只有中文' })
    i18n.global.locale.value = 'ja-JP'
    expect(t(KEY2)).toBe('只有中文')
    i18n.global.locale.value = 'en-US'
    expect(t(KEY2)).toBe('只有中文')
  })
})

describe('三語 locale 檔 key 集合完全一致（結構鐵則）', () => {
  it('zh-TW / en-US / ja-JP leaf key 集合逐一相等', () => {
    const zh = leafKeys(zhTW).sort()
    const en = leafKeys(enUS).sort()
    const ja = leafKeys(jaJP).sort()
    expect(en).toEqual(zh)
    expect(ja).toEqual(zh)
  })

  it('全部 leaf 值非空字串', () => {
    for (const messages of [zhTW, enUS, jaJP]) {
      for (const key of leafKeys(messages)) {
        const value = key.split('.').reduce((o, k) => o[k], messages)
        expect(value, `${key} 不得為空`).toBeTruthy()
      }
    }
  })
})

describe('document metadata 隨語言', () => {
  it('title 與 <html lang> 隨切換即時更新', async () => {
    setupDocumentMetadata()
    await Promise.resolve()
    expect(document.title).toContain('Custodexa')
    expect(document.title).toContain('開源堡壘機系統')
    expect(document.documentElement.lang).toBe('zh-TW')

    setLanguage('en-US')
    await new Promise((r) => setTimeout(r))
    expect(document.title).toContain('Open-Source Bastion Host')
    expect(document.documentElement.lang).toBe('en-US')
    localStorage.removeItem(LANG_STORAGE_KEY)
  })
})

describe('locale 汙染防護（setup afterEach 重設）', () => {
  it('（前置）本案例故意切到 en-US', () => {
    setLanguage('en-US')
    expect(i18n.global.locale.value).toBe('en-US')
    localStorage.removeItem(LANG_STORAGE_KEY)
  })

  it('（後置）上一案例切過語言，本案例仍以 zh-TW 起始', () => {
    expect(i18n.global.locale.value).toBe(DEFAULT_LOCALE)
    expect(t('menu.users')).toBe('使用者管理')
  })
})

// vue-i18n 訊息語法防呆：
// 編譯器把 `@` 當 linked message（`@:key`）起手，訊息內出現裸 `@` 會在 render
// 期拋 "Invalid linked format"——**不是漏字而是整個元件渲染中斷**，且只有那條
// 錯誤訊息真的被顯示時才會炸，正常測試路徑碰不到。字面 `@` 一律寫成 {'@'}。
// 本守衛於 2026-08-02 補上時，修掉了兩個既有的裸 `@`（帳號範圍相關 apiError）
describe('locale 訊息語法（linked message 轉義）', () => {
  const collect = (messages, prefix = '', out = []) => {
    for (const [key, value] of Object.entries(messages)) {
      const path = prefix ? `${prefix}.${key}` : key
      if (value && typeof value === 'object') collect(value, path, out)
      else if (typeof value === 'string') out.push([path, value])
    }
    return out
  }

  it.each(['zh-TW', 'en-US', 'ja-JP'])('%s 無未轉義的 @', (name) => {
    const offenders = collect(loadLocale(name))
      // 先移除合法轉義形式，剩下的 @ 即為裸 @
      .filter(([, value]) => value.replace(/\{'@'\}/g, '').includes('@'))
      .map(([path]) => path)
    expect(offenders, `以下 key 含未轉義的 @（請改寫成 {'@'}）：${offenders.join(', ')}`)
      .toEqual([])
  })

  // `|` 是複數分支分隔符：訊息內出現字面 `|` 時，t(key) 只會回傳第一段——
  // **無聲截斷**，不報錯、不留線索。補上本守衛時，
  // 修掉了一個既有實例（filter 佔位符位置的 apiError 三語譯文寫了「OR（|）」，
  // 實際渲染成「…不可位於 OR（」）。要用複數形請登記於下方清單。
  const PLURAL_KEYS = new Set([
    'assets.riskCount',
    'format.durationDays',
    'format.durationHours',
    'format.durationMinutes',
    'format.durationSeconds',
    // 單實例守衛：偵測到的對等實例數（en 單複數）
    'instanceGuard.headline.peers',
    'ldapDirectory.matched',
    'ldapDirectory.matchedAtLeast',
    // PCI 偏離摘要三處（英文寫死複數，1 項時顯示 "1 deviations"）
    'pciBanner.overviewLink',
    'policyForm.pageDeviation',
    'securityPolicies.systemDeviation',
    'transportPreflight.db_reject',
    'transportPreflight.rdp_reject',
    'transportPreflight.vnc_reject',
  ])

  it.each(['zh-TW', 'en-US', 'ja-JP'])('%s 的字面 | 僅出現於已登記的複數訊息', (name) => {
    const offenders = collect(loadLocale(name))
      .filter(([path, value]) => value.includes('|') && !PLURAL_KEYS.has(path))
      .map(([path]) => path)
    expect(
      offenders,
      `以下 key 含字面 |（會被當成複數分支而截斷，請改寫）：${offenders.join(', ')}`
    ).toEqual([])
  })

  it('已登記的複數訊息確實渲染完整（確認清單不是放行後門）', () => {
    expect(t('format.durationDays', 2)).toContain('2')
    expect(t('apiError.VALIDATION_LDAP_FILTER_PLACEHOLDER_SCOPE')).toContain('NOT')
  })

  // en 的命中筆數曾寫死複數（「1 entries matched」）：登記為複數 key 之後，
  // 單複數兩支都必須真的選對——只驗其中一支等於沒驗
  it('命中筆數的英文單複數各自選對分支', () => {
    setLanguage('en-US')
    expect(t('ldapDirectory.matched', 1)).toBe('1 entry matched')
    expect(t('ldapDirectory.matched', 2)).toBe('2 entries matched')
    expect(t('ldapDirectory.matchedAtLeast', 1)).toContain('At least 1 entry matched')
    expect(t('ldapDirectory.matchedAtLeast', 5)).toContain('At least 5 entries matched')
    setLanguage(DEFAULT_LOCALE)
    localStorage.removeItem(LANG_STORAGE_KEY)
  })

  // 同型缺陷：PCI 偏離摘要的英文亦寫死複數。呼叫端須以
  // named + plural 兩參數傳（{ n } 供插值、count 供分支），少傳 count 會恆選第一支
  it('PCI 偏離摘要的英文單複數各自選對分支', () => {
    setLanguage('en-US')
    expect(t('policyForm.pageDeviation', { n: 1 }, 1)).toBe(
      'This page has 1 deviation from the PCI recommendations'
    )
    expect(t('policyForm.pageDeviation', { n: 3 }, 3)).toBe(
      'This page has 3 deviations from the PCI recommendations'
    )
    expect(t('securityPolicies.systemDeviation', { n: 1 }, 1)).toContain('1 system-wide deviation ')
    expect(t('securityPolicies.systemDeviation', { n: 2 }, 2)).toContain('2 system-wide deviations ')
    expect(t('pciBanner.overviewLink', { n: 1 }, 1)).toContain('1 system-wide deviation ·')
    expect(t('pciBanner.overviewLink', { n: 4 }, 4)).toContain('4 system-wide deviations ·')
    setLanguage(DEFAULT_LOCALE)
    localStorage.removeItem(LANG_STORAGE_KEY)
  })

  it("{'@'} 轉義實際渲染為字面 @（確認轉義形式可用而非只是繞過守衛）", () => {
    expect(t('apiError.VALIDATION_ACCOUNT_USERNAME_RESERVED')).toContain('@')
    expect(t('authorizations.accountScopeReserved', { names: '@ALL' })).toContain(
      '@ALL'
    )
  })
})
