import { describe, it, expect } from 'vitest'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 「進行中授權被撤銷而斷線」在會話列表、會話詳情、任務詳情三畫面必須是同一詞組。
// 唯一事實源＝enum.endReason.revoked；agentSession.* 只能沿用，不得另起說法。
const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }

describe('revoked-during-session wording is shared across screens', () => {
  for (const [name, messages] of Object.entries(LOCALES)) {
    it(`${name}: agentSession.revokedShort equals enum.endReason.revoked`, () => {
      expect(messages.agentSession.revokedShort).toBe(messages.enum.endReason.revoked)
    })
    it(`${name}: agentSession.revoked starts with the same phrase and keeps {time}`, () => {
      expect(messages.agentSession.revoked.startsWith(messages.enum.endReason.revoked)).toBe(true)
      expect(messages.agentSession.revoked).toContain('{time}')
    })
    it(`${name}: no separate agentTasks.sessionRevoked phrase remains`, () => {
      expect(messages.agentTasks.sessionRevoked).toBeUndefined()
    })
  }
})
