// 審核範圍與最少核准人數的說明文案守衛：管理角色本身不構成核准資格，
// 說明不得再出現「由管理員補位、兜底」這類已不成立的說法。
import { describe, it, expect } from 'vitest'
import zhTW from '../locales/zh-TW.json'
import enUS from '../locales/en-US.json'
import jaJP from '../locales/ja-JP.json'

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }
const KEYS = ['approverScope.semantics4', 'policyDomain.section.request_params.hint']
const FORBIDDEN = /補位|兜底|恆可核|backfill|backstop|can always approve|補完|常に承認/i

const lookup = (messages, path) => path.split('.').reduce((o, k) => (o == null ? o : o[k]), messages)

describe('核准人數與審核範圍說明', () => {
  for (const [lang, messages] of Object.entries(LOCALES)) {
    for (const key of KEYS) {
      it(`${lang} ${key}：存在、非空，且不含管理員補位類字樣`, () => {
        const text = lookup(messages, key)
        expect(typeof text).toBe('string')
        expect(text.trim()).not.toBe('')
        expect(text).not.toMatch(FORBIDDEN)
      })
    }
  }
})
