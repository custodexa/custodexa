import { describe, it, expect } from 'vitest'
import {
  REASON_MAX, MARKER_CODES, FAILURE_CAUSES, holdKeystrokeView, takeKeystrokeView, clearKeystrokeView,
  reasonLength, classifyKeystrokeError, describeNoContent, describeIntegrity, formatOffsetMs,
} from '../keystrokeView'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

const err = (status, code) => ({ response: { status, data: code ? { code } : {} } })

describe('記憶體交接', () => {
  it('取走即清空，連線編號對不上時取不到', () => {
    holdKeystrokeView(7, '調查', { data: { events: [] } })
    expect(takeKeystrokeView(8)).toBeNull()
    expect(takeKeystrokeView(7)).toBeNull()
    holdKeystrokeView(7, '調查', { data: {} })
    expect(takeKeystrokeView('7')).toMatchObject({ reason: '調查' })
    expect(takeKeystrokeView(7)).toBeNull()
  })

  it('clear 後取不到', () => {
    holdKeystrokeView(7, 'x', {})
    clearKeystrokeView()
    expect(takeKeystrokeView(7)).toBeNull()
  })

  it('不寫任何瀏覽器儲存', () => {
    const before = [localStorage.length, sessionStorage.length]
    holdKeystrokeView(1, 'secret-reason', { data: { events: [{ data_b64: 'AAAA' }] } })
    takeKeystrokeView(1)
    expect([localStorage.length, sessionStorage.length]).toEqual(before)
  })
})

describe('reasonLength', () => {
  it('以字元計並去除前後空白', () => {
    expect(reasonLength('  追查事件單  ')).toBe(5)
    expect(reasonLength('')).toBe(0)
    expect(reasonLength('   ')).toBe(0)
    expect(reasonLength('一'.repeat(REASON_MAX))).toBe(1000)
    expect(reasonLength('😀'.repeat(3))).toBe(3)
  })
})

describe('classifyKeystrokeError', () => {
  it('各錯誤碼與會好轉與否', () => {
    expect(classifyKeystrokeError(err(409, 'RULE_KEYSTROKE_VAULT_SEALED'))).toMatchObject({ kind: 'sealed', retryable: true })
    expect(classifyKeystrokeError(err(422, 'RULE_KEYSTROKE_RECORD_REJECTED'))).toMatchObject({ kind: 'rejected', retryable: false })
    expect(classifyKeystrokeError(err(500, 'INTERNAL_KEYSTROKE_VIEW'))).toMatchObject({ kind: 'audit', retryable: true })
    expect(classifyKeystrokeError(err(404, 'RESOURCE_KEYSTROKE_NOT_VIEWABLE'))).toMatchObject({ kind: 'notViewable', retryable: false })
    expect(classifyKeystrokeError(err(403, 'AUTH_PERMISSION_DENIED'))).toMatchObject({ kind: 'noPermission', retryable: false })
    expect(classifyKeystrokeError(err(400, 'VALIDATION_KEYSTROKE_REASON_REQUIRED')).kind).toBe('reasonRequired')
    expect(classifyKeystrokeError(err(400, 'VALIDATION_KEYSTROKE_REASON_TOO_LONG')).kind).toBe('reasonTooLong')
    expect(classifyKeystrokeError(err(502))).toMatchObject({ kind: 'other', retryable: true })
    expect(classifyKeystrokeError(new Error('network'))).toMatchObject({ kind: 'other' })
  })
})

describe('describeNoContent（viewable=false 的各狀態）', () => {
  it('上線前、已清除帶時間', () => {
    expect(describeNoContent({ state: 'pre_feature', feature_since: '2026-11-20T02:31:00Z' })).toMatchObject({ key: 'preFeature', tone: 'info' })
    expect(describeNoContent({ state: 'purged', purged_at: '2027-02-01T03:00:00Z' })).toMatchObject({ key: 'purged', tone: 'warn' })
  })
  it('不產生依原因分流，未知原因走通用', () => {
    for (const r of ['k8s_logs_readonly', 'db_console', 'graphics_pending', 'file_transfer']) {
      expect(describeNoContent({ state: 'not_covered', coverage_reason: r }).key).toBe(`notCovered.${r}`)
    }
    expect(describeNoContent({ state: 'not_covered', coverage_reason: 'future_reason' }).key).toBe('notCovered.generic')
  })
  it('啟動失敗：未建立與沒有檔案（帶已知原因）', () => {
    expect(describeNoContent({ state: 'record_missing' })).toMatchObject({ key: 'recordMissing', tone: 'error' })
    expect(describeNoContent({ state: 'failed', failure_cause: 'KEYSTROKE_DIR_UNWRITABLE' })).toMatchObject({ key: 'failedNoFile', cause: 'KEYSTROKE_DIR_UNWRITABLE' })
    expect(describeNoContent({ state: 'failed', failure_cause: 'UNKNOWN' }).cause).toBe('')
  })
})

describe('describeIntegrity 優先序', () => {
  it('各狀態', () => {
    expect(describeIntegrity('file_missing', 'complete').kind).toBe('fileMissing')
    expect(describeIntegrity('tampered', 'recording').kind).toBe('tampered')
    expect(describeIntegrity('truncated', 'recording').kind).toBe('recording')
    expect(describeIntegrity('truncated', 'failed').kind).toBe('failed')
    expect(describeIntegrity('truncated', 'incomplete').kind).toBe('incomplete')
    expect(describeIntegrity('complete', 'incomplete').kind).toBe('incomplete')
    expect(describeIntegrity('truncated', 'complete').kind).toBe('truncated')
    expect(describeIntegrity('complete', 'complete')).toMatchObject({ kind: 'complete', tag: 'success' })
  })
})

describe('formatOffsetMs', () => {
  it('時分秒與十分之一秒', () => {
    expect(formatOffsetMs(0)).toBe('00:00:00.0')
    expect(formatOffsetMs(3100)).toBe('00:00:03.1')
    expect(formatOffsetMs(17 * 60000 + 30600)).toBe('00:17:30.6')
    expect(formatOffsetMs(-5)).toBe('00:00:00.0')
  })
})

describe('三語查譯完整', () => {
  for (const [name, loc] of [['zh-TW', zhTW], ['en-US', enUS], ['ja-JP', jaJP]]) {
    it(`${name}：8 個標記碼與 5 個失敗原因都有譯文`, () => {
      for (const code of MARKER_CODES) expect(loc.keystrokeView.viewer.marker[code], code).toBeTruthy()
      expect(loc.keystrokeView.viewer.marker.unknown).toContain('{code}')
      for (const c of FAILURE_CAUSES) expect(loc.keystrokeView.failureCause[c], c).toBeTruthy()
      for (const kind of ['sealed', 'rejected', 'audit', 'noPermission', 'notViewable', 'other']) {
        expect(loc.keystrokeView.error[kind].title).toBeTruthy()
        expect(loc.keystrokeView.error[kind].body).toBeTruthy()
      }
    })
  }
})
