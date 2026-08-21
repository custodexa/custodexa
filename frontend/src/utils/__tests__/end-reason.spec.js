import { describe, it, expect } from 'vitest'
import { getEndReasonText, getEndReasonTagType, END_REASON_TEXT } from '../end-reason'

// 值域硬拷後端（完備性守護，role-enum-metadata-sync）：
// model/session.go:20-26＋bridge.go/tunnel.go/migrations default
const BACKEND_END_REASONS = [
  'normal', 'idle_timeout', 'max_duration', 'admin_terminate',
  'user_terminate', 'backend_restart', 'orphaned', 'revoked', 'block_clear_failed',
]

describe('END_REASON 完備性（前後端值域一致）', () => {
  it('與後端 8 值互為全集且每值有文字與 tag 色', () => {
    expect(Object.keys(END_REASON_TEXT).sort()).toEqual([...BACKEND_END_REASONS].sort())
    for (const r of BACKEND_END_REASONS) {
      expect(getEndReasonText(r), `${r} 缺文字`).not.toBe(r)
      expect(getEndReasonTagType(r), `${r} 缺 tag`).toBeTruthy()
    }
  })
})

describe('getEndReasonText', () => {
  it('maps known reasons to Traditional Chinese labels', () => {
    expect(getEndReasonText('normal')).toBe('正常結束')
    expect(getEndReasonText('idle_timeout')).toBe('閒置逾時')
    expect(getEndReasonText('max_duration')).toBe('達時間上限')
    expect(getEndReasonText('admin_terminate')).toBe('管理員強制')
  })

  it('returns the raw value for unknown reasons', () => {
    expect(getEndReasonText('future_reason')).toBe('future_reason')
  })

  it('returns dash for empty values', () => {
    expect(getEndReasonText('')).toBe('-')
    expect(getEndReasonText(undefined)).toBe('-')
    expect(getEndReasonText(null)).toBe('-')
  })
})

describe('getEndReasonTagType', () => {
  it('maps reasons to tag types by severity', () => {
    expect(getEndReasonTagType('normal')).toBe('info')
    expect(getEndReasonTagType('idle_timeout')).toBe('warning')
    expect(getEndReasonTagType('max_duration')).toBe('warning')
    expect(getEndReasonTagType('admin_terminate')).toBe('danger')
  })

  it('falls back to info for unknown or empty values', () => {
    expect(getEndReasonTagType('future_reason')).toBe('info')
    expect(getEndReasonTagType(undefined)).toBe('info')
  })
})
