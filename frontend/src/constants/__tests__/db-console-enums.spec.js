import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  RESULT_STATUS_VALUES,
  RESULT_REASON_VALUES,
  TX_STATE_VALUES,
  CLOSED_REASON_VALUES,
  RESTRICTED_NOTICE_VALUES,
  resultStatusLabel,
  resultStatusTagType,
  resultReasonLabel,
  txStateLabel,
  closedReasonLabel,
  isAlertStatus,
  isTxUnsettled,
} from '../db-console'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }
const lookup = (messages, path) =>
  path.split('.').reduce((o, k) => (o == null ? o : o[k]), messages)

const expectKeyInAllLocales = (path) => {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const value = lookup(messages, path)
    expect(value, `${locale} 缺 ${path}`).toBeTruthy()
    expect(typeof value, `${locale} 的 ${path} 應為字串`).toBe('string')
  }
}

// 後端 model 目錄由 docker-compose.dev.yml 唯讀掛載；無掛載的環境該案例 skip
// （測試清單可見 skipped，非靜默通過），僅剩硬拷斷言把關
const backendModelPath = [
  join(process.cwd(), '../backend/internal/model/session_command.go'),
  join(process.cwd(), '../../backend/internal/model/session_command.go'),
  '/repo/backend/internal/model/session_command.go',
].find((p) => existsSync(p))

const parseConst = (src, prefix) => [
  ...new Set(
    [...src.matchAll(new RegExp(`^\\s*${prefix}\\w+\\s*=\\s*"([a-z0-9_]+)"`, 'gm'))].map(
      (m) => m[1]
    )
  ),
]

describe('主控台枚舉值域（硬拷後端）', () => {
  it('八值狀態齊備且不含空字串（空字串＝命令列列的判別鍵）', () => {
    expect(RESULT_STATUS_VALUES).toEqual([
      'running',
      'ok',
      'error',
      'partial',
      'blocked',
      'cancelled',
      'timeout',
      'effect_unknown',
    ])
    expect(RESULT_STATUS_VALUES).not.toContain('')
  })

  it('原因碼十值、交易態四值、關閉原因六值、受限成因兩值', () => {
    expect(RESULT_REASON_VALUES).toHaveLength(10)
    expect(TX_STATE_VALUES).toEqual(['none', 'active', 'failed', 'unknown'])
    expect(CLOSED_REASON_VALUES).toEqual([
      'target_closed',
      'slow_consumer',
      'idle_timeout',
      'max_duration',
      'terminated',
      'client_gone',
    ])
    expect(RESTRICTED_NOTICE_VALUES).toEqual([
      'database_not_allowed',
      'database_drift_denied',
    ])
  })

  it.skipIf(!backendModelPath)('與後端常數區雙向等同', () => {
    const src = readFileSync(backendModelPath, 'utf8')
    expect([...RESULT_STATUS_VALUES].sort()).toEqual(
      [...parseConst(src, 'ResultStatus')].sort()
    )
    expect([...RESULT_REASON_VALUES].sort()).toEqual([...parseConst(src, 'Reason')].sort())
    expect([...TX_STATE_VALUES].sort()).toEqual([...parseConst(src, 'TxState')].sort())
  })
})

describe('主控台枚舉三語完備性（值域 × locale）', () => {
  it('resultStatus 每值三語皆有非空 key', () => {
    for (const v of RESULT_STATUS_VALUES) expectKeyInAllLocales(`enum.resultStatus.${v}`)
  })

  it('resultReason 每值三語皆有非空 key', () => {
    for (const v of RESULT_REASON_VALUES) expectKeyInAllLocales(`enum.resultReason.${v}`)
  })

  it('txState 每值三語皆有非空 key', () => {
    for (const v of TX_STATE_VALUES) expectKeyInAllLocales(`enum.txState.${v}`)
  })

  it('關閉原因每值三語皆有非空 key', () => {
    for (const v of CLOSED_REASON_VALUES) expectKeyInAllLocales(`dbConsole.closed.${v}`)
  })

  it('受限成因每值三語皆有非空 key', () => {
    for (const v of RESTRICTED_NOTICE_VALUES) expectKeyInAllLocales(`dbConsole.restricted.${v}`)
  })
})

describe('主控台枚舉查譯與語義判準', () => {
  it('未知值降級為原值，空值回空字串', () => {
    expect(resultStatusLabel('nope')).toBe('nope')
    expect(resultStatusLabel('')).toBe('')
    expect(resultReasonLabel('')).toBe('')
    expect(txStateLabel('')).toBe('')
    expect(closedReasonLabel('')).toBe('')
    expect(resultStatusTagType('nope')).toBe('info')
  })

  it('部分生效與結果未知不得呈現為成功或失敗', () => {
    expect(resultStatusTagType('partial')).toBe('warning')
    expect(resultStatusTagType('effect_unknown')).toBe('warning')
    expect(isAlertStatus('partial')).toBe(true)
    expect(isAlertStatus('effect_unknown')).toBe(true)
    expect(isAlertStatus('ok')).toBe(false)
    expect(isAlertStatus('error')).toBe(false)
  })

  it('交易未收束＝active 或 failed', () => {
    expect(isTxUnsettled('active')).toBe(true)
    expect(isTxUnsettled('failed')).toBe(true)
    expect(isTxUnsettled('none')).toBe(false)
    expect(isTxUnsettled('unknown')).toBe(false)
    expect(isTxUnsettled('')).toBe(false)
  })
})
