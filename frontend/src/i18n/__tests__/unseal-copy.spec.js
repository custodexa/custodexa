import { describe, it, expect } from 'vitest'
import zhTW from '../locales/zh-TW.json'
import enUS from '../locales/en-US.json'
import jaJP from '../locales/ja-JP.json'

// 解封頁文案的操作者可讀性守衛（i18n spec「解封頁文案的操作者可讀性與其守衛」）。
//
// 讀者是**疲勞狀態下的維運人員**：他懂環境變數與十六進位，但工作記憶已耗盡、
// 而且會跳著看。本組守衛掃三語 `unseal.*` 的全部葉鍵。
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
// 下限釘在 50（本 change 交付時為 57 鍵）。
const MIN_LEAF_KEYS = 50

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

describe('解封頁文案：不含機器碼、函式名或工程行話', () => {
  for (const [name, locale] of LOCALES) {
    it(`${name} 的 unseal 文案通過行話掃描`, () => {
      const entries = collect(locale.unseal, '', [])
      expect(
        entries.length,
        `${name} 的 unseal 葉鍵僅 ${entries.length} 個，低於下限——射程可能已靜默縮小`
      ).toBeGreaterThanOrEqual(MIN_LEAF_KEYS)

      for (const [key, text] of entries) {
        expect(SNAKE_CASE.test(text), `${key} 出現機器碼：${text}`).toBe(false)
        expect(CAMEL_CASE.test(text), `${key} 出現函式名：${text}`).toBe(false)
        expect(JARGON_LATIN.test(text), `${key} 出現行話：${text}`).toBe(false)
        expect(JARGON_CJK.test(text), `${key} 出現行話：${text}`).toBe(false)
      }
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
