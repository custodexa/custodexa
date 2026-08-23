/**
 * 時間軸幾何（auditor-workbench）。
 *
 * 全站無時序元件且**不引入第三方圖表相依**，刻度與跨度條以本模組算出百分比、
 * 由 CSS 定位。純函式無 DOM 依賴，便於單測釘住四種跨度情形（一般／進行中／
 * 跨窗／0 秒）。
 *
 * 裁切不得靜默：窗外的起訖一律回報 clippedStart／clippedEnd，呼叫端必須畫出
 * 裁切標記——否則跨窗會話會被讀成「剛好在窗邊開始或結束」。
 */
import { currentLocale } from '@/i18n'

const MS = 1000

export const toMs = (value) => {
  if (value === null || value === undefined || value === '') return NaN
  const ms = value instanceof Date ? value.getTime() : new Date(value).getTime()
  return Number.isFinite(ms) ? ms : NaN
}

export const clampPercent = (value) => Math.min(100, Math.max(0, value))

/** 時刻在窗內的百分比位置；窗無效或時刻不可解析時回 null（呼叫端不得畫） */
export function timeToPercent(ts, from, to) {
  const f = toMs(from)
  const t = toMs(to)
  const v = toMs(ts)
  if (!Number.isFinite(f) || !Number.isFinite(t) || t <= f) return null
  if (!Number.isFinite(v)) return null
  return clampPercent(((v - f) / (t - f)) * 100)
}

/**
 * 會話跨度的版面幾何。
 * @param {{start:string,end:?string}} span
 * @param {string|number|Date} from 時間窗起
 * @param {string|number|Date} to 時間窗迄
 * @param {number} [now] 現在時刻（測試可注入）
 * @returns {?{left:number,width:number,ongoing:boolean,clippedStart:boolean,
 *             clippedEnd:boolean,durationSeconds:number,visible:boolean}}
 */
export function spanGeometry(span, from, to, now = Date.now()) {
  const f = toMs(from)
  const t = toMs(to)
  const start = toMs(span?.start)
  if (!Number.isFinite(f) || !Number.isFinite(t) || t <= f) return null
  if (!Number.isFinite(start)) return null

  const ongoing = !span.end
  // 進行中會話沒有真實終點：以「現在」當視覺終點，但終點語義仍是開放的，
  // 呼叫端據 ongoing 畫漸層淡出而非硬邊
  const rawEnd = ongoing ? Math.max(now, start) : toMs(span.end)
  if (!Number.isFinite(rawEnd)) return null

  const visibleStart = Math.max(start, f)
  const visibleEnd = Math.min(rawEnd, t)
  const left = clampPercent(((visibleStart - f) / (t - f)) * 100)
  const right = clampPercent(((visibleEnd - f) / (t - f)) * 100)

  return {
    left,
    // 0 秒會話寬度為 0：實際可見寬度由 CSS min-width 保底（dev 庫大量 0-1 秒會話）
    width: Math.max(0, right - left),
    ongoing,
    clippedStart: start < f,
    clippedEnd: !ongoing && rawEnd > t,
    durationSeconds: Math.max(0, Math.round((rawEnd - start) / MS)),
    visible: rawEnd >= f && start <= t,
  }
}

// 刻度候選間隔（秒）：分鐘級到週級，覆蓋「告警前後 30 分鐘」到「查一個月」
const TICK_STEPS = [
  60, 5 * 60, 15 * 60, 30 * 60,
  3600, 3 * 3600, 6 * 3600, 12 * 3600,
  86400, 2 * 86400, 7 * 86400, 30 * 86400,
]
const MAX_TICKS = 40

/**
 * 產生時間刻度。對齊到本地時區的整點／整日邊界（以 epoch 對齊會讓
 * 非整時區偏移的刻度落在半點上）。
 * @returns {Array<{ts:number,percent:number,step:number}>}
 */
export function buildTicks(from, to, target = 8) {
  const f = toMs(from)
  const t = toMs(to)
  if (!Number.isFinite(f) || !Number.isFinite(t) || t <= f) return []

  const totalSec = (t - f) / MS
  const ideal = totalSec / Math.max(1, target)
  const stepSec = TICK_STEPS.find((s) => s >= ideal) ?? TICK_STEPS[TICK_STEPS.length - 1]
  const stepMs = stepSec * MS

  const tzOffset = new Date(f).getTimezoneOffset() * 60 * MS
  let cursor = Math.ceil((f - tzOffset) / stepMs) * stepMs + tzOffset

  const ticks = []
  while (cursor <= t && ticks.length < MAX_TICKS) {
    ticks.push({
      ts: cursor,
      percent: clampPercent(((cursor - f) / (t - f)) * 100),
      step: stepSec,
    })
    cursor += stepMs
  }
  return ticks
}

/**
 * 刻度標籤：跨日以上顯示日期，日內顯示時分。24 小時制固定（審計精度決策，
 * 沿 utils/format.js 同一原則），locale 隨當前語言。
 */
export function formatTickLabel(ts, stepSec) {
  const date = new Date(ts)
  const locale = currentLocale()
  if (stepSec >= 86400) {
    return date.toLocaleDateString(locale, { month: '2-digit', day: '2-digit' })
  }
  const time = date.toLocaleTimeString(locale, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
  // 跨越午夜的刻度補上日期，否則「00:00」在多日窗內無法辨識是哪一天
  if (date.getHours() === 0 && date.getMinutes() === 0) {
    return `${date.toLocaleDateString(locale, {
      month: '2-digit',
      day: '2-digit',
    })} ${time}`
  }
  return time
}
