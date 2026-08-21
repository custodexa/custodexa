/**
 * 全站日期/時長格式化唯一實作（ux-consistency D2＋i18n-foundation D7）。
 * 規則：locale 由 i18n 當前語言驅動（render 期呼叫被依賴追蹤，切語言自動重繪）；
 * hour12 固定 false 不隨語言——審計場景時間必須無歧義（24h 是審計精度決策）。
 * 勿在頁面內重新實作；勿把格式化結果存入 state（會斷 reactivity），
 * state 一律留 raw timestamp、顯示時才格式化。
 */
import { currentLocale, t } from '@/i18n'

// Intl.DateTimeFormat 的**建構**是這裡唯一的重成本（實測容器內約 1.8ms／次，
// 而 cached.format() 約 0.03ms／次，差 50 倍以上）。`toLocaleString(locale, opts)`
// 每呼叫一次就重建一個 formatter，於是「一列一次」的表格在數百列時會卡住主緒
// ——時間軸的 axis mark 是每個事件一次，單日數百事件即秒級。
//
// 以 locale 為鍵快取：同 locale＋同 options 的輸出完全等價，格式化結果不變；
// 切語言時 currentLocale() 變、取到另一顆 formatter，reactivity 與行為都不受影響。
const DATE_TIME_FORMATS = new Map()
const DATE_FORMATS = new Map()

const cachedFormat = (cache, locale, options) => {
  let formatter = cache.get(locale)
  if (!formatter) {
    formatter = new Intl.DateTimeFormat(locale, options)
    cache.set(locale, formatter)
  }
  return formatter
}

const DATE_TIME_OPTIONS = {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
}

const DATE_OPTIONS = {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
}

// 不可解析的輸入：`toLocaleString` 回 "Invalid Date"，而 `formatter.format()`
// 會丟 RangeError——後端若送出壞掉的 ts，快取版就會從「顯示一列怪字串」
// 惡化成「整個 render 炸掉」。故無效日期一律走回原本的 toLocaleString 路徑，
// 輸出與改動前逐字相同（這是錯誤路徑，效能無所謂）
const isValidDate = (date) => Number.isFinite(date.getTime())

export function formatDateTime(datetime) {
  if (!datetime) return '-'
  const date = new Date(datetime)
  if (!isValidDate(date)) return date.toLocaleString(currentLocale(), DATE_TIME_OPTIONS)
  return cachedFormat(DATE_TIME_FORMATS, currentLocale(), DATE_TIME_OPTIONS).format(date)
}

export function formatDate(datetime) {
  if (!datetime) return '-'
  const date = new Date(datetime)
  if (!isValidDate(date)) return date.toLocaleDateString(currentLocale(), DATE_OPTIONS)
  return cachedFormat(DATE_FORMATS, currentLocale(), DATE_OPTIONS).format(date)
}

// 時長：帶 count 的 plural message（en 單複數走 "{n} hour | {n} hours"），
// 不可只翻單位字串後空格 join（codex r1 F9）。
// 分隔符不走訊息（空字串會被 vue-i18n 誤判缺 key 而 fallback）：ja 無空格排版
const DURATION_SEPARATORS = { 'ja-JP': '' }

export function formatDurationSeconds(seconds) {
  if (!seconds) return '-'
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = seconds % 60

  const parts = []
  if (hours > 0) parts.push(t('format.durationHours', hours))
  if (minutes > 0) parts.push(t('format.durationMinutes', minutes))
  if (secs > 0 || parts.length === 0) parts.push(t('format.durationSeconds', secs))

  return parts.join(DURATION_SEPARATORS[currentLocale()] ?? ' ')
}

// 運行時間（SessionStatsPanel 等）：≥1 天顯示「天＋時」、否則「時＋分」；
// 單位訊息與分隔符沿 formatDurationSeconds 同一套（ja 無空格）
export function formatUptimeSeconds(seconds) {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const sep = DURATION_SEPARATORS[currentLocale()] ?? ' '
  if (days > 0) {
    return [t('format.durationDays', days), t('format.durationHours', hours)].join(sep)
  }
  return [t('format.durationHours', hours), t('format.durationMinutes', minutes)].join(sep)
}

// 位元組大小：1024 進位，至 TB，一位小數（B 不帶小數）。
//
// 刻意**不**回收既有兩處手寫格式化（FileManager 的單檔大小、SessionStatsPanel 的
// 流量與速率）：語義不同（單檔／速率），順手統一只會擴大迴歸面而無收益。
// 進位基數取 1024 是與那兩處一致的既有慣例，不是新決定。
const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB']

export function formatBytes(bytes) {
  const n = Number(bytes)
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  let value = n
  let unit = 0
  // 上界停在 TB：再往上（PB）對單一錄影目錄不是可信的量級，
  // 與其顯示一個看起來精確的荒謬數字，不如讓它以 TB 累加下去
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  if (unit === 0) return `${Math.round(value)} B`
  return `${value.toFixed(1)} ${BYTE_UNITS[unit]}`
}

// 相對時間：剛剛/N 分鐘前/N 小時前/月日（Intl 全程隨語言；
// >24h 分支不可手組字串——codex r2 P2：手組 MM-DD 會凍結在單一格式）
export function formatRelativeTime(ts) {
  if (!ts) return ''
  const diff = Date.now() - new Date(ts).getTime()
  const min = Math.floor(diff / 60000)
  if (min < 1) return t('format.justNow')
  const rtf = new Intl.RelativeTimeFormat(currentLocale(), { numeric: 'always' })
  if (min < 60) return rtf.format(-min, 'minute')
  const hr = Math.floor(min / 60)
  if (hr < 24) return rtf.format(-hr, 'hour')
  return new Date(ts).toLocaleDateString(currentLocale(), {
    month: '2-digit',
    day: '2-digit',
  })
}
