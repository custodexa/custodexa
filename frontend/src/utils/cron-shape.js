/**
 * 排程時刻的形狀轉換：五欄排程字串 ↔「每日／每週／每月／每季／每年」的說法。
 *
 * 兩條不可退讓的性質：
 *  1. 反推只認本檔生成得出的寫法。補零、順序不同、步進寫法一律落到自訂並原樣保留
 *     ——既有排程被讀取一次不得因此被改寫。
 *  2. 生成與反推互為反函式：改動某一欄不會順手改掉沒碰過的欄位。
 *
 * 每季刻意明列四個月而非步進寫法，因為起始月可調（步進寫法固定從 1 月起算）。
 */
import { t } from '@/i18n'

/** 選擇器提供的六種頻率（不含「不排程」，那是宿主允許空值時才有的狀態） */
export const SCHEDULE_MODES = ['daily', 'weekly', 'monthly', 'quarterly', 'yearly', 'custom']

/** 未設定排程（宿主允許空值時） */
export const NO_SCHEDULE_MODE = 'none'
export const CUSTOM_MODE = 'custom'

export const WEEKDAYS = [0, 1, 2, 3, 4, 5, 6]
export const MONTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

/** 季度起始月只有三種：其餘月份的四個月組合與這三種之一完全相同 */
export const QUARTER_START_MONTHS = [1, 2, 3]

const QUARTER_OFFSETS = [0, 3, 6, 9]
const MINUTE_MAX = 59
const HOUR_MAX = 23
const DAY_MAX = 31

// 無前導零的兩位數，與 buildCron 的輸出格式逐字對應
const NUM = '(?:0|[1-9]\\d?)'
const RE_DAILY = new RegExp(`^(${NUM}) (${NUM}) \\* \\* \\*$`)
const RE_WEEKLY = new RegExp(`^(${NUM}) (${NUM}) \\* \\* ([0-6])$`)
const RE_MONTHLY = new RegExp(`^(${NUM}) (${NUM}) (${NUM}) \\* \\*$`)
const RE_QUARTERLY = new RegExp(
  `^(${NUM}) (${NUM}) (${NUM}) (${NUM}),(${NUM}),(${NUM}),(${NUM}) \\*$`
)
const RE_YEARLY = new RegExp(`^(${NUM}) (${NUM}) (${NUM}) (${NUM}) \\*$`)

// 自訂欄只做形態檢查（欄數與各欄字元組成），語義由後端排程解析器裁定
const FIELD_TERM = '(?:\\*|\\d{1,4}|[A-Za-z]{3}(?:-[A-Za-z]{3})?|\\d{1,4}-\\d{1,4})'
const RE_CRON_FIELD = new RegExp(`^${FIELD_TERM}(?:/\\d{1,4})?(?:,${FIELD_TERM}(?:/\\d{1,4})?)*$`)

const inRange = (value, min, max) => Number.isInteger(value) && value >= min && value <= max

const pad2 = (value) => String(value).padStart(2, '0')

/** 一季四個月的完整清單（起始月 1–3） */
export function quarterMonths(startMonth) {
  return QUARTER_OFFSETS.map((offset) => startMonth + offset)
}

/** 表單初值：午夜、星期一、每月 1 日、1 月、第一季起 */
export function defaultShapeFields() {
  return {
    minute: 0,
    hour: 0,
    weekday: 1,
    day: 1,
    month: 1,
    quarterStartMonth: 1,
  }
}

/** 時刻顯示（24 小時制，與全站審計時間一致） */
export function formatClock(hour, minute) {
  return `${pad2(hour)}:${pad2(minute)}`
}

/**
 * 執行時刻顯示。後端回的是排程器所在時區的時刻，此處只截取不換算——
 * 交給 Date 解析會被瀏覽器時區改寫成另一個時間，而那不是排程實際跑的時刻。
 */
export function formatRunTime(value) {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(String(value ?? ''))
  return match ? `${match[1]} ${match[2]}` : String(value ?? '')
}

/**
 * 依形狀與欄位生成五欄排程字串。
 *
 * @param {string} mode - SCHEDULE_MODES 之一，或 NO_SCHEDULE_MODE
 * @param {Object} fields - { minute, hour, weekday, day, month, quarterStartMonth, custom }
 * @returns {string} 五欄字串；不排程回空字串
 */
export function buildCron(mode, fields = {}) {
  if (mode === NO_SCHEDULE_MODE) return ''
  if (mode === CUSTOM_MODE) return String(fields.custom ?? '')

  const f = { ...defaultShapeFields(), ...fields }
  const time = `${f.minute} ${f.hour}`
  if (mode === 'daily') return `${time} * * *`
  if (mode === 'weekly') return `${time} * * ${f.weekday}`
  if (mode === 'monthly') return `${time} ${f.day} * *`
  if (mode === 'quarterly') return `${time} ${f.day} ${quarterMonths(f.quarterStartMonth).join(',')} *`
  if (mode === 'yearly') return `${time} ${f.day} ${f.month} *`
  return ''
}

const shapeOf = (mode, overrides, raw) => ({
  ...defaultShapeFields(),
  ...overrides,
  mode,
  raw,
  custom: raw,
})

const asCustom = (raw) => shapeOf(CUSTOM_MODE, {}, raw)

const parseTime = (minuteText, hourText) => {
  const minute = Number(minuteText)
  const hour = Number(hourText)
  if (!inRange(minute, 0, MINUTE_MAX) || !inRange(hour, 0, HOUR_MAX)) return null
  return { minute, hour }
}

const parseQuarter = (match, raw) => {
  const time = parseTime(match[1], match[2])
  const day = Number(match[3])
  if (!time || !inRange(day, 1, DAY_MAX)) return asCustom(raw)
  const months = match.slice(4, 8).map(Number)
  const start = months[0]
  if (!QUARTER_START_MONTHS.includes(start)) return asCustom(raw)
  if (quarterMonths(start).join(',') !== months.join(',')) return asCustom(raw)
  return shapeOf('quarterly', { ...time, day, quarterStartMonth: start }, raw)
}

/**
 * 反推五欄排程字串為形狀與欄位。認不出來的一律回 custom 並在 raw 保留原字串。
 *
 * @param {string} cron
 * @returns {{mode: string, minute: number, hour: number, weekday: number, day: number,
 *   month: number, quarterStartMonth: number, raw: string, custom: string}}
 */
export function parseCron(cron) {
  const raw = typeof cron === 'string' ? cron.trim() : ''
  if (!raw) return shapeOf(NO_SCHEDULE_MODE, {}, '')

  const daily = RE_DAILY.exec(raw)
  if (daily) {
    const time = parseTime(daily[1], daily[2])
    return time ? shapeOf('daily', time, raw) : asCustom(raw)
  }

  const weekly = RE_WEEKLY.exec(raw)
  if (weekly) {
    const time = parseTime(weekly[1], weekly[2])
    return time ? shapeOf('weekly', { ...time, weekday: Number(weekly[3]) }, raw) : asCustom(raw)
  }

  const monthly = RE_MONTHLY.exec(raw)
  if (monthly) {
    const time = parseTime(monthly[1], monthly[2])
    const day = Number(monthly[3])
    return time && inRange(day, 1, DAY_MAX) ? shapeOf('monthly', { ...time, day }, raw) : asCustom(raw)
  }

  const quarterly = RE_QUARTERLY.exec(raw)
  if (quarterly) return parseQuarter(quarterly, raw)

  const yearly = RE_YEARLY.exec(raw)
  if (yearly) {
    const time = parseTime(yearly[1], yearly[2])
    const day = Number(yearly[3])
    const month = Number(yearly[4])
    return time && inRange(day, 1, DAY_MAX) && inRange(month, 1, 12)
      ? shapeOf('yearly', { ...time, day, month }, raw)
      : asCustom(raw)
  }

  return asCustom(raw)
}

/**
 * 自訂欄的形態檢查。
 *
 * @param {string} text
 * @returns {null|{reason: string, count?: number, index?: number, field?: string}}
 *   null 表示形態沒問題；reason 為 empty / fieldCount / fieldSyntax
 */
export function cronTextIssue(text) {
  const trimmed = typeof text === 'string' ? text.trim() : ''
  if (!trimmed) return { reason: 'empty' }

  const fields = trimmed.split(/\s+/)
  if (fields.length !== 5) return { reason: 'fieldCount', count: fields.length }

  const badIndex = fields.findIndex((field) => !RE_CRON_FIELD.test(field))
  if (badIndex >= 0) {
    return { reason: 'fieldSyntax', index: badIndex + 1, field: fields[badIndex] }
  }
  return null
}

/** 自訂欄形態是否可送出 */
export function isCronText(text) {
  return cronTextIssue(text) === null
}

/**
 * 人話摘要（列表時刻欄與選擇器的第一層文字）。
 * 認不出形狀者回原字串——那是唯一還說得出實情的寫法。
 */
export function describeSchedule(cron) {
  const shape = parseCron(cron)
  if (shape.mode === NO_SCHEDULE_MODE) return ''
  if (shape.mode === CUSTOM_MODE) return shape.raw

  const time = formatClock(shape.hour, shape.minute)
  if (shape.mode === 'weekly') {
    return t('scheduleFrequency.summary.weekly', {
      weekday: t(`scheduleFrequency.weekday.d${shape.weekday}`),
      time,
    })
  }
  return t(`scheduleFrequency.summary.${shape.mode}`, {
    day: shape.day,
    month: shape.month,
    time,
  })
}
