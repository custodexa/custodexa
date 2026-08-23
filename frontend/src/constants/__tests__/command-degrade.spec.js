// 降級／限定原因碼的值域與文案守衛。
//
// 三件事：
// 1. **雙向完備性**：直讀後端 session_command.go 取 Degrade*／Qualify* 常數值，
//    兩側互為全集——後端加碼而前端沒補（介面顯示裸碼）、或前端多列一個不存在的碼，
//    任一方向都紅。慣例同 audit-enums.spec.js。
// 2. **三語非空**：每個碼 × 三 locale。
// 3. **禁止文案**：降級是設計上的狀態，不是故障，也不是空指令。
//    「(空)」「-」「解析失敗」「系統錯誤」四類措辭一旦混進來就紅。
import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  DEGRADE_REASON_VALUES,
  QUALIFY_REASON_VALUES,
  COMMAND_REASON_VALUES,
  degradeReasonLabel,
  degradeRecordingHint,
  COMMAND_ALERT_REASON_VALUES,
  commandAlertReasonLabel,
  isDegradedAlert,
  isDegradedRow,
  isQualifiedRow,
} from '../command-degrade'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }

const lookup = (messages, path) =>
  path.split('.').reduce((o, k) => (o == null ? o : o[k]), messages)

// 值域硬拷後端：backend/internal/model/session_command.go 的 Degrade*／Qualify* 常數
const BACKEND_DEGRADE = [
  'altscreen_round',
  'redraw_unanchored',
  'fullscreen_input',
  'queue_discarded',
  'queue_discarded_at_close',
  'queue_uncounted',
  'queue_overflow',
  'input_without_echo',
]
const BACKEND_QUALIFY = ['replay_input_bytes']

// 直讀後端原始碼（容器內有 ./backend/internal/model 唯讀掛載；無掛載環境 skip）
const resolveBackendSource = (file) =>
  [
    join(process.cwd(), `../backend/internal/model/${file}`),
    join(process.cwd(), `../../backend/internal/model/${file}`),
    `/repo/backend/internal/model/${file}`,
  ].find((p) => existsSync(p))

const backendSourcePath = resolveBackendSource('session_command.go')

// `Degraded bool` 這類欄位宣告沒有 `= "..."`，正則因此不會誤收
const parseConsts = (src, prefix) => [
  ...new Set(
    [...src.matchAll(new RegExp(`^\\s*${prefix}\\w+\\s*=\\s*"([a-z0-9_]+)"`, 'gm'))].map(
      (m) => m[1]
    )
  ),
]

describe('降級原因碼值域', () => {
  it('前端值域與硬拷對照組一致', () => {
    expect([...DEGRADE_REASON_VALUES].sort()).toEqual([...BACKEND_DEGRADE].sort())
    expect([...QUALIFY_REASON_VALUES].sort()).toEqual([...BACKEND_QUALIFY].sort())
  })

  it('Degrade* 與 Qualify* 兩個值域不重疊（合併會讓「無標記＝文字可信」變成假話）', () => {
    const overlap = DEGRADE_REASON_VALUES.filter((v) => QUALIFY_REASON_VALUES.includes(v))
    expect(overlap).toEqual([])
  })

  const maybe = backendSourcePath ? it : it.skip
  maybe('與後端原始碼雙向等同（直讀 session_command.go）', () => {
    const src = readFileSync(backendSourcePath, 'utf8')
    const backendDegrade = parseConsts(src, 'Degrade')
    const backendQualify = parseConsts(src, 'Qualify')
    expect(backendDegrade.length).toBeGreaterThan(0)
    expect(backendQualify.length).toBeGreaterThan(0)
    expect([...DEGRADE_REASON_VALUES].sort()).toEqual([...backendDegrade].sort())
    expect([...QUALIFY_REASON_VALUES].sort()).toEqual([...backendQualify].sort())
  })
})

describe('原因碼三語完備性', () => {
  it('每個碼 × 三 locale 皆有非空字串', () => {
    for (const code of COMMAND_REASON_VALUES) {
      for (const [locale, messages] of Object.entries(LOCALES)) {
        const value = lookup(messages, `enum.commandDegrade.${code}`)
        expect(value, `${locale} 缺 enum.commandDegrade.${code}`).toBeTruthy()
        expect(typeof value).toBe('string')
      }
    }
  })

  it('降級 UI 文案 × 三 locale 皆有非空字串', () => {
    const uiKeys = [
      'title',
      'reasonUnknown',
      'reasonMissing',
      'recordingMaybe',
      'recordingNoEcho',
      'recordingUnavailable',
      'seekAction',
      'qualifiedTag',
      'bannerExact',
      'bannerAtLeast',
      'bannerUnknown',
      'bannerClear',
    ]
    for (const key of uiKeys) {
      for (const [locale, messages] of Object.entries(LOCALES)) {
        const value = lookup(messages, `commands.degrade.${key}`)
        expect(value, `${locale} 缺 commands.degrade.${key}`).toBeTruthy()
      }
    }
  })
})

describe('降級告警的原因碼', () => {
  it('每個碼 × 三 locale 皆有非空字串', () => {
    for (const code of COMMAND_ALERT_REASON_VALUES) {
      for (const [locale, messages] of Object.entries(LOCALES)) {
        const value = lookup(messages, `enum.commandAlertReason.${code}`)
        expect(value, `${locale} 缺 enum.commandAlertReason.${code}`).toBeTruthy()
      }
    }
  })

  it('未知碼走 default 分支，並與 Degrade* 值域分離', () => {
    const label = commandAlertReasonLabel('future_alert_reason')
    expect(label).toContain('future_alert_reason')
    expect(label).not.toContain('enum.commandAlertReason')
    // 兩個值域不共用：降級列的原因碼不該被當成告警原因碼查譯
    expect(COMMAND_ALERT_REASON_VALUES.some((v) => DEGRADE_REASON_VALUES.includes(v))).toBe(false)
  })

  it('kind 判定只認 audit_degraded', () => {
    expect(isDegradedAlert({ kind: 'audit_degraded' })).toBe(true)
    expect(isDegradedAlert({ kind: 'rule' })).toBe(false)
    expect(isDegradedAlert({})).toBe(false)
  })
})

describe('禁止文案', () => {
  // 前兩者看起來像「使用者按了 Enter 但沒打字」，後兩者把設計上的降級講成故障
  const FORBIDDEN = ['(空)', '（空）', '解析失敗', '系統錯誤', '系統異常', 'parse failed']

  it('原因碼譯文與降級 UI 文案不得出現故障／空指令措辭', () => {
    for (const [locale, messages] of Object.entries(LOCALES)) {
      const bag = {
        ...(lookup(messages, 'enum.commandDegrade') || {}),
        ...(lookup(messages, 'enum.commandAlertReason') || {}),
        ...(lookup(messages, 'commands.degrade') || {}),
      }
      for (const [key, value] of Object.entries(bag)) {
        for (const bad of FORBIDDEN) {
          expect(String(value).includes(bad), `${locale} 的 ${key} 含禁止文案「${bad}」`).toBe(
            false
          )
        }
        // 整句就是一個符號＝看起來像空指令
        expect(String(value).trim()).not.toBe('-')
        expect(String(value).trim().length).toBeGreaterThan(1)
      }
    }
  })
})

describe('查譯與旗標', () => {
  it('已知碼回傳譯文而非機器碼', () => {
    const label = degradeReasonLabel('altscreen_round')
    expect(label).not.toBe('altscreen_round')
    expect(label.length).toBeGreaterThan(4)
  })

  it('未知碼走 default 分支：帶出原碼、不回裸鍵、不空白', () => {
    const label = degradeReasonLabel('some_future_code_from_backend')
    expect(label).toContain('some_future_code_from_backend')
    expect(label).not.toContain('commands.degrade')
    expect(label.trim()).not.toBe('')
  })

  it('無碼時仍有可讀文案（紀錄未帶原因碼）', () => {
    const label = degradeReasonLabel('')
    expect(label.trim()).not.toBe('')
    expect(label).not.toContain('commands.degrade')
  })

  it('沒有錄影時不得說「錄影可能保留」', () => {
    const hint = degradeRecordingHint('altscreen_round', 'unavailable')
    expect(hint).toBe(zhTW.commands.degrade.recordingUnavailable)
  })

  it('回顯關閉類不得沿用「錄影可能保留」（那類連錄影都救不回）', () => {
    expect(degradeRecordingHint('input_without_echo', 'available')).toBe(
      zhTW.commands.degrade.recordingNoEcho
    )
    expect(degradeRecordingHint('altscreen_round', 'available')).toBe(
      zhTW.commands.degrade.recordingMaybe
    )
  })

  it('degraded 與 qualified 互斥判定', () => {
    expect(isDegradedRow({ degraded: true, degrade_reason: 'altscreen_round' })).toBe(true)
    expect(isQualifiedRow({ degraded: true, degrade_reason: 'altscreen_round' })).toBe(false)
    expect(isQualifiedRow({ degraded: false, degrade_reason: 'replay_input_bytes' })).toBe(true)
    expect(isDegradedRow({ degraded: false, degrade_reason: 'replay_input_bytes' })).toBe(false)
    // 存量資料沒有這兩欄，兩者皆為否
    expect(isDegradedRow({ command: 'ls' })).toBe(false)
    expect(isQualifiedRow({ command: 'ls' })).toBe(false)
  })
})
