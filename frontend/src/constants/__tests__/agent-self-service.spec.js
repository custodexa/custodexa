import { describe, it, expect } from 'vitest'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

describe('agent self-service locale completeness', () => {
  for (const [lang, messages] of Object.entries({ zhTW, enUS, jaJP })) {
    it(`${lang} has policy labels and public errors`, () => {
      for (const key of ['agent_self_create_enabled', 'agent_self_create_max_per_owner']) {
        expect(messages.policyLabel[key]).toEqual(expect.any(String))
        expect(messages.policyLabel[key].trim()).not.toBe('')
      }
      for (const code of ['RULE_AGENT_SELF_CREATE_DISABLED', 'RULE_AGENT_SELF_CREATE_LIMIT']) {
        expect(messages.apiError[code]).toEqual(expect.any(String))
        expect(messages.apiError[code].trim()).not.toBe('')
      }
    })
  }
})
