import { describe, it, expect } from 'vitest'
import {
  formatDateTime,
  formatDate,
  formatDurationSeconds,
  formatRelativeTime,
  formatBytes,
} from '../format'
import i18n, { DEFAULT_LOCALE } from '@/i18n'

const withLocale = (locale, fn) => {
  i18n.global.locale.value = locale
  try {
    return fn()
  } finally {
    i18n.global.locale.value = DEFAULT_LOCALE
  }
}

describe('formatDateTime（全站唯一實作：zh-TW 24 小時制含秒）', () => {
  it('renders 24-hour time with seconds', () => {
    const out = formatDateTime('2026-07-20T18:44:05+08:00')
    expect(out).toContain('2026')
    expect(out).not.toContain('下午')
    expect(out).not.toContain('上午')
    expect(out).toMatch(/\d{2}:\d{2}:\d{2}/)
  })

  it('falls back to dash on empty input', () => {
    expect(formatDateTime('')).toBe('-')
    expect(formatDateTime(null)).toBe('-')
  })
})

describe('formatDate', () => {
  it('renders date only', () => {
    const out = formatDate('2026-07-20T18:44:05+08:00')
    expect(out).toContain('2026')
    expect(out).not.toMatch(/:/)
  })

  it('falls back to dash on empty input', () => {
    expect(formatDate(undefined)).toBe('-')
  })
})

describe('formatDurationSeconds', () => {
  it('composes 時/分/秒 parts', () => {
    expect(formatDurationSeconds(3725)).toBe('1 時 2 分 5 秒')
    expect(formatDurationSeconds(65)).toBe('1 分 5 秒')
    expect(formatDurationSeconds(9)).toBe('9 秒')
  })

  it('falls back to dash on zero/empty', () => {
    expect(formatDurationSeconds(0)).toBe('-')
    expect(formatDurationSeconds(null)).toBe('-')
  })

  // en 單複數、ja 無空格排版
  it('en-US distinguishes singular and plural (never "1 hours")', () => {
    withLocale('en-US', () => {
      expect(formatDurationSeconds(3600)).toBe('1 hour')
      expect(formatDurationSeconds(7200)).toBe('2 hours')
      expect(formatDurationSeconds(3725)).toBe('1 hour 2 minutes 5 seconds')
      expect(formatDurationSeconds(61)).toBe('1 minute 1 second')
    })
  })

  it('ja-JP joins parts without spaces', () => {
    withLocale('ja-JP', () => {
      expect(formatDurationSeconds(3725)).toBe('1時間2分5秒')
      expect(formatDurationSeconds(65)).toBe('1分5秒')
    })
  })
})

describe('formatRelativeTime', () => {
  it('renders 剛剛 for now and 分鐘前 for recent', () => {
    expect(formatRelativeTime(new Date().toISOString())).toBe('剛剛')
    const fiveMinAgo = new Date(Date.now() - 5 * 60000).toISOString()
    expect(formatRelativeTime(fiveMinAgo)).toBe('5 分鐘前')
  })

  it('renders locale month-day beyond a day and empty for missing input', () => {
    const twoDaysAgo = new Date(Date.now() - 48 * 3600000)
    expect(formatRelativeTime(twoDaysAgo.toISOString())).toMatch(/^\d{2}\/\d{2}$/)
    expect(formatRelativeTime('')).toBe('')
  })

  // 相對時間走 Intl.RelativeTimeFormat 隨語言
  it('localizes relative time per active language', () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60000).toISOString()
    withLocale('en-US', () => {
      expect(formatRelativeTime(fiveMinAgo)).toBe('5 minutes ago')
      expect(formatRelativeTime(new Date().toISOString())).toBe('just now')
    })
    withLocale('ja-JP', () => {
      expect(formatRelativeTime(fiveMinAgo)).toBe('5 分前')
      expect(formatRelativeTime(new Date().toISOString())).toBe('たった今')
    })
  })

  it('date order follows active locale (24h preserved)', () => {
    const ts = '2026-07-20T18:44:05+08:00'
    const en = withLocale('en-US', () => formatDateTime(ts))
    expect(en).toMatch(/\d{2}:\d{2}:\d{2}/)
    expect(en).not.toContain('PM')
    expect(en).toContain('07')
    const zh = formatDateTime(ts)
    expect(zh).toContain('2026')
  })
})

// 1024 進位、至 TB、一位小數。
// 逐級邊界各一，確保進位基數不是 1000（1000 進位時 1024 B 會顯示 1.0 KB 而
// 1500 B 會顯示 1.5 KB——後者在 1024 進位下是 1.5 KB 之外的值，故取可分辨的點）
describe('formatBytes（錄影佔用顯示）', () => {
  it('renders bytes below 1 KiB without a unit jump', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(931)).toBe('931 B')
    expect(formatBytes(1023)).toBe('1023 B')
  })

  it('steps through KB / MB / GB / TB at 1024 boundaries', () => {
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytes(1024 * 1024)).toBe('1.0 MB')
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1.0 GB')
    expect(formatBytes(1024 ** 4)).toBe('1.0 TB')
  })

  it('uses 1024 (not 1000) as the base', () => {
    expect(formatBytes(1536)).toBe('1.5 KB')
    // 兩個能分辨進位基數的點：1000 B 在 1000 進位下會是 "1.0 KB"，
    // 1,000,000 B 在 1000 進位下會是 "1.0 MB"
    expect(formatBytes(1000)).toBe('1000 B')
    expect(formatBytes(1000000)).toBe('976.6 KB')
  })

  it('stays in TB beyond 1024 TB instead of inventing a larger unit', () => {
    expect(formatBytes(1024 ** 5)).toBe('1024.0 TB')
  })

  it('falls back to 0 B on non-numeric or negative input', () => {
    expect(formatBytes(null)).toBe('0 B')
    expect(formatBytes(undefined)).toBe('0 B')
    expect(formatBytes(-1)).toBe('0 B')
  })
})
