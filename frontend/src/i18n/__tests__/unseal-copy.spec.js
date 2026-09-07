import { describe, it, expect } from 'vitest'
import zhTW from '../locales/zh-TW.json'
import enUS from '../locales/en-US.json'
import jaJP from '../locales/ja-JP.json'

// 服務前頁面文案的操作者可讀性守衛（i18n spec「解封頁文案的操作者可讀性與其守衛」）。
//
// 讀者是**疲勞狀態下的維運人員**：他懂環境變數與十六進位，但工作記憶已耗盡、
// 而且會跳著看。本組守衛掃三語 `unseal.*` 與 `instanceGuard.*` 的全部葉鍵
// （後者含守衛攔下頁 `instanceGuard.halt.*` 與常駐橫幅——同一批讀者、同一個處境）。
//
// **這支守衛擋得住什麼、擋不住什麼（誠實界線）**：
// 擋得住「行話回流」與「內部設計理由被寫回去」的**字面**形態；
// **擋不住「這句話人看不看得懂」**——那沒有機械判準，由人工驗收承擔
// （同一 Requirement 的「機械守衛之誠實界線」段：該驗收 SHALL 由未讀過本設計文件者執行）。
// 本檔通過 SHALL NOT 被解讀為「文案可讀性已驗證」。
//
// 詞表與 `views/__tests__/CheckpointVerification.spec.js` 的稽核文案守衛**刻意不同**：
// 該處讀者是稽核人員，`kek` 屬黑名單；此處讀者是維運人員，主金鑰是他要輸入的東西，
// 標註 KEK 反而是他與 `.env`／營運文件對得上的錨點。兩份詞表各自對應各自的讀者，
// 不要互相複製。

const collect = (node, prefix, out) => {
  for (const [k, v] of Object.entries(node)) {
    if (v && typeof v === 'object') collect(v, `${prefix}${k}.`, out)
    // 插值變數是程式碼契約而非可讀文案，掃描前先剝除
    else if (typeof v === 'string') out.push([`${prefix}${k}`, v.replace(/\{[^}]*\}/g, '')])
  }
  return out
}

const LOCALES = [
  ['zh-TW', zhTW],
  ['en-US', enUS],
  ['ja-JP', jaJP],
]

// 掃空防護：namespace 更名或鍵被大批移除時守衛必須轉紅，不得因無項目可檢而通過。
// 下限釘在 50（本 change 交付時為 58 鍵）。
const MIN_LEAF_KEYS = 50

// `instanceGuard.*` 的獨立下限（交付時 74 鍵：橫幅 26＋detail 24＋halt 24）。
// 套 unseal 的下限等於沒有掃空防護——兩組各自的鍵數差一倍以上
const GUARD_MIN_LEAF_KEYS = 60

// `kekCommands.*` 渲染於解封頁的同一個展開區（`UnsealFormatDetails` → `KEKGenerateCommands`），
// 讀者與規範同上，故納入同一組掃描。獨立下限：這組只有 4 鍵，套 unseal 的下限等於沒有掃空防護。
const KEK_MIN_LEAF_KEYS = 4

// 狀態機器碼形態（initialization_required、stage2_timeout）。刻意只比對小寫：
// 環境變數名（ADMIN_INITIAL_PASSWORD）是技術識別字，規格明列不得視為行話。
const SNAKE_CASE = /[a-z0-9]+_[a-z0-9_]+/
// 內部函式名形態（getSealStatus、crypto.getRandomValues）
const CAMEL_CASE = /\b[a-z]+[A-Z][A-Za-z]*/
// 行話（拉丁字母面）：本 change 逐一替換掉的工程用語
const JARGON_LATIN = /\b(envelope ciphertext|envelope-ciphertext|unwrap|unwraps|unwrapping|fail-close|failclose|keying material|material|materials)\b/i
// 行話（中日文面）
const JARGON_CJK = /信封密文|遺失語義|解包|收束|収束|留痕|材料|エンベロープ暗号文|エンベロープ/

// 本 change 刪除的三鍵：內容為純內部設計理由，SHALL NOT 以任何形式回流
const REMOVED_KEYS = ['serverAuthorityHint', 'lossNotice', 'materialFormatHint']

const scanEntries = (entries) => {
  for (const [key, text] of entries) {
    expect(SNAKE_CASE.test(text), `${key} 出現機器碼：${text}`).toBe(false)
    expect(CAMEL_CASE.test(text), `${key} 出現函式名：${text}`).toBe(false)
    expect(JARGON_LATIN.test(text), `${key} 出現行話：${text}`).toBe(false)
    expect(JARGON_CJK.test(text), `${key} 出現行話：${text}`).toBe(false)
  }
}

describe('解封頁文案：不含機器碼、函式名或工程行話', () => {
  for (const [name, locale] of LOCALES) {
    it(`${name} 的 unseal 文案通過行話掃描`, () => {
      const entries = collect(locale.unseal, '', [])
      expect(
        entries.length,
        `${name} 的 unseal 葉鍵僅 ${entries.length} 個，低於下限——射程可能已靜默縮小`
      ).toBeGreaterThanOrEqual(MIN_LEAF_KEYS)

      scanEntries(entries)
    })
  }

  for (const [name, locale] of LOCALES) {
    it(`${name} 的守衛攔下頁與橫幅文案通過同一組掃描`, () => {
      const entries = collect(locale.instanceGuard, '', [])
      expect(
        entries.length,
        `${name} 的 instanceGuard 葉鍵僅 ${entries.length} 個，低於下限——射程可能已靜默縮小`
      ).toBeGreaterThanOrEqual(GUARD_MIN_LEAF_KEYS)
      // 攔下頁的 halt 子樹必須真的在掃描集合裡（namespace 改名時這條先紅）
      expect(
        entries.some(([key]) => key.startsWith('halt.')),
        `${name} 的 instanceGuard.halt.* 不在掃描集合內`
      ).toBe(true)

      scanEntries(entries)
    })
  }

  for (const [name, locale] of LOCALES) {
    it(`${name} 的生成指令說明文案通過同一組掃描`, () => {
      const entries = collect(locale.kekCommands, '', [])
      expect(
        entries.length,
        `${name} 的 kekCommands 葉鍵僅 ${entries.length} 個，低於下限——射程可能已靜默縮小`
      ).toBeGreaterThanOrEqual(KEK_MIN_LEAF_KEYS)
      scanEntries(entries)
    })
  }

  it('純內部設計理由的三鍵在三語皆已移除', () => {
    for (const [name, locale] of LOCALES) {
      for (const key of REMOVED_KEYS) {
        expect(locale.unseal[key], `${name} 殘留 unseal.${key}`).toBeUndefined()
      }
    }
  })
})

describe('解封頁文案：遺失警語三語齊備且強度一致', () => {
  // 翻譯弱化＝安全指示失效。三語雙射守衛只驗鍵存在，攔不到「英日文寫得比較軟」，
  // 故此處另驗：警語鍵有值，且不含在其他語言不存在的軟化限定詞。
  const WARNING_KEYS = ['lossTitle', 'lossBody', 'confirmSavedCheckbox', 'initWarningTitle']
  const HEDGE =
    /(\b(may|might|maybe|probably|possibly|in most cases|usually|generally)\b)|可能|多半|通常|一般而言|おそらく|場合によっては|たいてい/i

  for (const [name, locale] of LOCALES) {
    it(`${name} 的遺失與保存警語齊備且未被軟化`, () => {
      for (const key of WARNING_KEYS) {
        const text = locale.unseal[key]
        expect(typeof text, `${name} 缺 unseal.${key}`).toBe('string')
        expect(text.trim().length, `${name} 的 unseal.${key} 為空`).toBeGreaterThan(0)
        expect(HEDGE.test(text), `${name} 的 unseal.${key} 出現軟化限定詞：${text}`).toBe(
          false
        )
      }
    })
  }

  it('三語的遺失警語都同時載明「永久不可回復」與「產品不提供救援」', () => {
    const REQUIRED = {
      'zh-TW': [/永久/, /沒有任何救援/],
      'en-US': [/for good|permanent/i, /no recovery path/i],
      'ja-JP': [/永久/, /復旧手段もありません/],
    }
    for (const [name, locale] of LOCALES) {
      const text = `${locale.unseal.lossTitle}\n${locale.unseal.lossBody}`
      for (const pattern of REQUIRED[name]) {
        expect(pattern.test(text), `${name} 的遺失警語缺 ${pattern}：${text}`).toBe(true)
      }
    }
  })
})

// 守衛攔下頁的文案密度（i18n spec「守衛攔下頁文案每元件不逾兩句」）。
// 讀者正在處理中斷，一個元件塞三句就等於沒寫。
describe('守衛攔下頁文案：每元件不逾兩句、承擔勾選三語同強度', () => {
  // 句末標點（中日文的句號、英文的句點與驚嘆號）計數；冒號與頓號不算句界
  const countSentences = (text) =>
    (text.match(/[。．！]|[.!](\s|$)/g) || []).length || 1

  for (const [name, locale] of LOCALES) {
    it(`${name} 的 instanceGuard.halt.* 每則不超過兩句`, () => {
      const entries = collect(locale.instanceGuard.halt, '', [])
      expect(entries.length).toBeGreaterThan(0)
      for (const [key, text] of entries) {
        expect(countSentences(text), `halt.${key} 超過兩句：${text}`).toBeLessThanOrEqual(2)
      }
    })
  }

  // 承擔勾選是這一頁唯一不可逆的那一步：翻譯弱化＝安全指示失效
  const HEDGE =
    /(\b(may|might|maybe|probably|possibly|in most cases|usually|generally)\b)|可能|多半|通常|一般而言|おそらく|場合によっては|たいてい/i

  for (const [name, locale] of LOCALES) {
    it(`${name} 的承擔勾選與風險警語未被軟化`, () => {
      for (const key of ['confirmCheckbox', 'riskTitle', 'riskBody', 'formDesc']) {
        const text = locale.instanceGuard.halt[key]
        expect(typeof text, `${name} 缺 instanceGuard.halt.${key}`).toBe('string')
        expect(text.trim().length, `${name} 的 instanceGuard.halt.${key} 為空`).toBeGreaterThan(0)
        expect(
          HEDGE.test(text),
          `${name} 的 instanceGuard.halt.${key} 出現軟化限定詞：${text}`
        ).toBe(false)
      }
    })
  }

  // 「事實不減少」的三條：另一實例仍在執行時停止它即可、後果由確認者承擔、
  // 本實例尚未寫入任何資料
  it('三語都能讀到攔下頁的三條必要事實', () => {
    const REQUIRED = {
      'zh-TW': [/停止它/, /後果由確認者承擔/, /尚未寫入任何資料/],
      'en-US': [/stop it/i, /you own the outcome/i, /has not written any data/i],
      'ja-JP': [/停止すれば/, /確認者が負い/, /まだ何も書き込んでいません/],
    }
    for (const [name, locale] of LOCALES) {
      const text = Object.values(locale.instanceGuard.halt).join('\n')
      for (const pattern of REQUIRED[name]) {
        expect(pattern.test(text), `${name} 的攔下頁缺 ${pattern}`).toBe(true)
      }
    }
  })
})
