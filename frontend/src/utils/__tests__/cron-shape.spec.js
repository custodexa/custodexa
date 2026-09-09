import { describe, it, expect } from 'vitest'
import {
  QUARTER_START_MONTHS,
  SCHEDULE_MODES,
  buildCron,
  cronTextIssue,
  describeSchedule,
  isCronText,
  parseCron,
  quarterMonths,
} from '@/utils/cron-shape'

// 形狀轉換的兩條鐵則：
//  1. 反推只認本檔自己生成得出的寫法，其餘一律落到自訂並原樣保留——
//     讀取一次不得改寫既有排程；
//  2. 生成與反推互為反函式（往返），否則「編輯了別的欄位」會順手改掉時刻。

describe('buildCron 六種形狀', () => {
  it('每日、每週、每月、每季、每年各自生成預期字串', () => {
    expect(buildCron('daily', { hour: 3, minute: 30 })).toBe('30 3 * * *')
    expect(buildCron('weekly', { hour: 3, minute: 0, weekday: 0 })).toBe('0 3 * * 0')
    expect(buildCron('monthly', { hour: 1, minute: 0, day: 1 })).toBe('0 1 1 * *')
    expect(buildCron('quarterly', { hour: 0, minute: 0, day: 1, quarterStartMonth: 1 })).toBe(
      '0 0 1 1,4,7,10 *'
    )
    expect(buildCron('yearly', { hour: 0, minute: 0, day: 1, month: 1 })).toBe('0 0 1 1 *')
  })

  it('每季明列四個月而非步進寫法（起始月可調）', () => {
    expect(buildCron('quarterly', { day: 15, quarterStartMonth: 3 })).toBe('0 0 15 3,6,9,12 *')
    expect(quarterMonths(2)).toEqual([2, 5, 8, 11])
  })

  it('自訂原樣輸出，不排程輸出空字串', () => {
    expect(buildCron('custom', { custom: '*/15 * * * *' })).toBe('*/15 * * * *')
    expect(buildCron('none')).toBe('')
  })
})

describe('parseCron 反推', () => {
  it('每季形狀：0 0 1 1,4,7,10 * 反推為每季、季度從 1 月起、當季第 1 日 00:00', () => {
    const shape = parseCron('0 0 1 1,4,7,10 *')
    expect(shape.mode).toBe('quarterly')
    expect(shape.quarterStartMonth).toBe(1)
    expect(shape.day).toBe(1)
    expect(shape.hour).toBe(0)
    expect(shape.minute).toBe(0)
  })

  it('不明形狀：*/15 * * * * 落到自訂並保留原字串', () => {
    const shape = parseCron('*/15 * * * *')
    expect(shape.mode).toBe('custom')
    expect(shape.raw).toBe('*/15 * * * *')
  })

  it('每日、每週、每月、每年各自認回對應形狀', () => {
    expect(parseCron('30 3 * * *').mode).toBe('daily')
    expect(parseCron('0 3 * * 0')).toMatchObject({ mode: 'weekly', weekday: 0, hour: 3 })
    expect(parseCron('0 1 1 * *')).toMatchObject({ mode: 'monthly', day: 1, hour: 1 })
    expect(parseCron('0 0 1 1 *')).toMatchObject({ mode: 'yearly', month: 1, day: 1 })
  })

  it('月份組合不是完整一季者落到自訂', () => {
    expect(parseCron('0 0 1 1,4,7 *').mode).toBe('custom')
    expect(parseCron('0 0 1 1,3,5,7 *').mode).toBe('custom')
  })

  it('超出範圍或非正規寫法一律落自訂，不做修正', () => {
    expect(parseCron('70 0 * * *').mode).toBe('custom')
    expect(parseCron('0 25 * * *').mode).toBe('custom')
    expect(parseCron('0 0 0 * *').mode).toBe('custom')
    // 補零寫法與本檔生成格式不同，認回去會在存回時被改寫
    expect(parseCron('00 03 * * *')).toMatchObject({ mode: 'custom', raw: '00 03 * * *' })
  })

  it('空字串視為未設定', () => {
    expect(parseCron('').mode).toBe('none')
    expect(parseCron(null).mode).toBe('none')
  })
})

describe('往返：生成再反推等於原輸入', () => {
  const cases = [
    ['daily', { hour: 3, minute: 30 }],
    ['weekly', { hour: 8, minute: 15, weekday: 5 }],
    ['monthly', { hour: 1, minute: 0, day: 28 }],
    ['quarterly', { hour: 2, minute: 45, day: 10, quarterStartMonth: 2 }],
    ['yearly', { hour: 23, minute: 59, day: 31, month: 12 }],
    ['custom', { custom: '*/15 * * * *' }],
  ]

  it.each(cases)('%s 形狀：欄位 → cron → 欄位 一致', (mode, fields) => {
    const cron = buildCron(mode, fields)
    const shape = parseCron(cron)
    expect(shape.mode).toBe(mode)
    for (const [key, value] of Object.entries(fields)) {
      if (key === 'custom') continue
      expect(shape[key]).toBe(value)
    }
  })

  it.each(cases)('%s 形狀：cron → 欄位 → cron 逐字相同', (mode, fields) => {
    const cron = buildCron(mode, fields)
    expect(buildCron(parseCron(cron).mode, parseCron(cron))).toBe(cron)
  })

  it('六種形狀都在支援清單內', () => {
    expect(SCHEDULE_MODES).toEqual([
      'daily',
      'weekly',
      'monthly',
      'quarterly',
      'yearly',
      'custom',
    ])
    expect(QUARTER_START_MONTHS).toEqual([1, 2, 3])
  })
})

describe('cronTextIssue 自訂欄格式檢查', () => {
  it('五欄合法寫法沒有問題', () => {
    expect(cronTextIssue('*/15 * * * *')).toBeNull()
    expect(cronTextIssue('0 0 1,15 * 1-5')).toBeNull()
    expect(isCronText('0 3 * * 0')).toBe(true)
  })

  it('四欄回報欄位數不足並帶實際欄數', () => {
    expect(cronTextIssue('0 0 1 *')).toEqual({ reason: 'fieldCount', count: 4 })
    expect(isCronText('0 0 1 *')).toBe(false)
  })

  it('空白回報未輸入', () => {
    expect(cronTextIssue('   ')).toEqual({ reason: 'empty' })
  })

  it('欄位寫法不合法時指出是第幾欄', () => {
    expect(cronTextIssue('0 0 1 * ??')).toMatchObject({ reason: 'fieldSyntax', index: 5 })
  })
})

describe('describeSchedule 人話摘要', () => {
  it('每季案顯示「每季 1 日 00:00」', () => {
    expect(describeSchedule('0 0 1 1,4,7,10 *')).toBe('每季 1 日 00:00')
  })

  it('其餘已知形狀各自成句', () => {
    expect(describeSchedule('30 3 * * *')).toBe('每日 03:30')
    expect(describeSchedule('0 3 * * 0')).toBe('每星期日 03:00')
    expect(describeSchedule('0 1 1 * *')).toBe('每月 1 日 01:00')
    expect(describeSchedule('0 0 1 1 *')).toBe('每年 1 月 1 日 00:00')
  })

  it('自訂形狀回原字串，未設定回空字串', () => {
    expect(describeSchedule('*/15 * * * *')).toBe('*/15 * * * *')
    expect(describeSchedule('')).toBe('')
  })
})
