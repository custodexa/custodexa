// 每日簽核畫面共用的呈現函式。
//
// 時間一律以「該所屬日自己的切日時區」呈現並帶位移：一筆紀錄若以 UTC 切日，
// 卻用瀏覽器時區顯示，讀者會把它讀成另一天。位移固定寫成 UTC±H[:MM]，
// 與 utils/format 的 formatDateTime 同一種寫法（三語逐字相同）。
// 數字（期間、分母、晚幾天）一律取自後端，這裡只做格式化，不推算。
import { currentLocale, t } from '@/i18n'

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

export const isReviewDate = (value) => typeof value === 'string' && DATE_RE.test(value)

const formatterCache = new Map()
const formatter = (key, options) => {
  const cacheKey = `${key}|${options.timeZone || ''}|${currentLocale()}`
  let f = formatterCache.get(cacheKey)
  if (!f) {
    f = new Intl.DateTimeFormat('en-CA', options)
    formatterCache.set(cacheKey, f)
  }
  return f
}

// 時區名稱不合法時（瀏覽器時區資料與後端不同）退回 UTC，不讓整個畫面炸掉
const safeZone = (tz) => {
  if (!tz) return 'UTC'
  try {
    new Intl.DateTimeFormat('en-CA', { timeZone: tz })
    return tz
  } catch {
    return 'UTC'
  }
}

const partsOf = (date, tz) => {
  const parts = formatter('parts', {
    timeZone: safeZone(tz),
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(date)
  const out = {}
  for (const p of parts) out[p.type] = p.value
  // 部分引擎把午夜寫成 24
  if (out.hour === '24') out.hour = '00'
  return out
}

/** 某時刻在某時區的 UTC 位移字樣：UTC、UTC+8、UTC-3:30 */
export function offsetLabel(tz, at = new Date()) {
  const date = at instanceof Date ? at : new Date(at)
  if (!Number.isFinite(date.getTime())) return 'UTC'
  const p = partsOf(date, tz)
  const asUTC = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second)
  const minutes = Math.round((asUTC - Math.floor(date.getTime() / 1000) * 1000) / 60000)
  if (minutes === 0) return 'UTC'
  const sign = minutes > 0 ? '+' : '-'
  const abs = Math.abs(minutes)
  const rest = abs % 60
  return `UTC${sign}${Math.floor(abs / 60)}${rest ? `:${String(rest).padStart(2, '0')}` : ''}`
}

/**
 * 「時區名（位移）」並列時的位移：零位移寫成 UTC+0。
 * 「UTC（UTC）」讀起來像重複，看不出位移是多少；時刻與紀錄註記仍用 offsetLabel
 */
export function zoneOffsetLabel(tz, at = new Date()) {
  const label = offsetLabel(tz, at)
  return label === 'UTC' ? 'UTC+0' : label
}

/** 2026/10/10 09:12 (UTC+8)：簽核時間等「哪個時刻」的呈現 */
export function formatInZone(iso, tz, { seconds = false } = {}) {
  if (!iso) return '-'
  const date = new Date(iso)
  if (!Number.isFinite(date.getTime())) return String(iso)
  const p = partsOf(date, tz)
  const time = seconds ? `${p.hour}:${p.minute}:${p.second}` : `${p.hour}:${p.minute}`
  return `${p.year}/${p.month}/${p.day} ${time} (${offsetLabel(tz, date)})`
}

/** 只取時刻 HH:mm（同一天內的事件列、可簽時刻） */
export function timeInZone(iso, tz) {
  if (!iso) return '-'
  const date = new Date(iso)
  if (!Number.isFinite(date.getTime())) return String(iso)
  const p = partsOf(date, tz)
  return `${p.hour}:${p.minute}`
}

/** YYYY-MM-DD HH:mm（同一天以外的時刻，例如準時期限） */
export function dateTimeInZone(iso, tz) {
  if (!iso) return '-'
  const date = new Date(iso)
  if (!Number.isFinite(date.getTime())) return String(iso)
  const p = partsOf(date, tz)
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`
}

/** 準時期限是「隔天結束」的那一刻；呈現為前一分鐘（23:59）讀起來才是「這一天之內」 */
export function lastMinuteBefore(iso) {
  const date = new Date(iso)
  if (!Number.isFinite(date.getTime())) return iso
  return new Date(date.getTime() - 60000).toISOString()
}

// 星期寫法：中文用單字「三」（畫面寫成「2026-10-07（三）」），日文 short 本來就是單字「水」，
// 英文 narrow 會變成有歧義的單字母（T、S），維持 short「Wed」
const WEEKDAY_STYLE = { 'zh-TW': 'narrow' }

/** 所屬日加星期：2026-10-10（六） */
export function dateWithWeekday(date) {
  if (!isReviewDate(date)) return date || ''
  const locale = currentLocale()
  const weekday = new Intl.DateTimeFormat(locale, { weekday: WEEKDAY_STYLE[locale] || 'short', timeZone: 'UTC' })
    .format(new Date(`${date}T00:00:00Z`))
  return t('dailyReview.weekdayDate', { date, weekday })
}

/** 月-日：卡片上的日期標籤 */
export const monthDay = (date) => (isReviewDate(date) ? date.slice(5) : date || '')

/** 日期加減天數（只用於伺服器給的日期，不讀本機時鐘） */
export function addDays(date, days) {
  if (!isReviewDate(date)) return date
  const d = new Date(`${date}T00:00:00Z`)
  d.setUTCDate(d.getUTCDate() + days)
  return d.toISOString().slice(0, 10)
}

/**
 * 所屬日的實際起訖。一般日寫成 00:00–23:59（UTC+8）；改時區的轉換日不是 24 小時，
 * 照實寫出兩端完整時刻與長度——用日期推算會把那天說成整天
 */
export function windowText(start, end, tz) {
  const s = new Date(start)
  const e = new Date(end)
  if (!Number.isFinite(s.getTime()) || !Number.isFinite(e.getTime())) return ''
  const hours = (e.getTime() - s.getTime()) / 3600000
  const startOffset = offsetLabel(tz, s)
  const endOffset = offsetLabel(tz, new Date(e.getTime() - 1000))
  if (hours === 24 && startOffset === endOffset && timeInZone(start, tz) === '00:00') {
    return t('dailyReview.drawer.window24', {
      start: '00:00',
      end: timeInZone(lastMinuteBefore(end), tz),
      offset: startOffset,
    })
  }
  return t('dailyReview.drawer.windowSpan', {
    start: formatInZone(start, tz),
    end: formatInZone(end, tz),
    hours: Number.isInteger(hours) ? hours : hours.toFixed(1),
  })
}

/**
 * 一項計數的呈現：來源已清除顯示「已清除」、部分清除顯示「至少 N」，
 * 絕不把未知寫成 0。舊制快照沒有來源欄，照數字呈現；缺值為「—」
 */
export function countText(value, source) {
  if (source === 'purged') return t('dailyReview.count.purged')
  if (value === null || value === undefined) return source ? t('dailyReview.count.purged') : t('dailyReview.count.none')
  if (source === 'partial') return t('dailyReview.count.atLeast', { n: value })
  return String(value)
}

/** 快照（新形或舊形）→ 三項計數與各自來源 */
export function snapshotItems(snapshot) {
  const s = snapshot || {}
  return {
    loginFailures: countText(s.login_failures, s.login_failures_source),
    alerts: countText(s.unreviewed_alerts, s.alerts_source),
    highRiskOps: countText(s.high_risk_ops, s.high_risk_ops_source),
  }
}

export function parseSnapshot(raw) {
  if (!raw) return null
  if (typeof raw === 'object') return raw
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

export const isInferredBasis = (basis) => Boolean(basis) && basis !== 'recorded'

const INFERRED_REASONS = ['presumed_purged', 'presumed_gap', 'presumed_tail']
export const inferredReason = (basis) =>
  INFERRED_REASONS.includes(basis) ? t(`dailyReview.enabledInferred.reason.${basis}`) : ''

/** 簽核或處置告警後通知徽章、清單、統計立刻重算 */
export const DAILY_REVIEWS_CHANGED = 'ot-daily-reviews-changed'
export const notifyDailyReviewsChanged = () => window.dispatchEvent(new Event(DAILY_REVIEWS_CHANGED))
