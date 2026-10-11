import { describe, it, expect, afterEach } from 'vitest'
import { setLanguage } from '@/i18n'
import { dateWithWeekday, offsetLabel, zoneOffsetLabel } from '../dailyReviewFormat'

describe('dailyReviewFormat', () => {
  afterEach(() => {
    setLanguage('zh-TW')
  })

  // 防：中文寫成「（週三）」，與畫面規格「（三）」不一致；其他語言跟著被改成單字母
  it('所屬日的星期：中文單字、日文單字、英文縮寫', () => {
    setLanguage('zh-TW')
    expect(dateWithWeekday('2026-10-07')).toBe('2026-10-07（三）')
    expect(dateWithWeekday('2026-10-10')).toBe('2026-10-10（六）')
    setLanguage('ja-JP')
    expect(dateWithWeekday('2026-10-07')).toBe('2026-10-07（水）')
    setLanguage('en-US')
    expect(dateWithWeekday('2026-10-07')).toBe('2026-10-07 (Wed)')
  })

  // 防：時區選項寫成「UTC（UTC）」看不出位移；紀錄上的時刻註記仍維持 (UTC)
  it('時區名並列的位移在零位移時寫 UTC+0', () => {
    const winter = new Date('2026-01-15T12:00:00Z')
    expect(zoneOffsetLabel('UTC', winter)).toBe('UTC+0')
    expect(zoneOffsetLabel('Europe/London', winter)).toBe('UTC+0')
    expect(zoneOffsetLabel('Asia/Taipei', winter)).toBe('UTC+8')
    expect(offsetLabel('UTC', winter)).toBe('UTC')
  })
})
