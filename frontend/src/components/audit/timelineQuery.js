/**
 * 工作台狀態 ↔ query string 的唯一轉換點（auditor-workbench D3）。
 *
 * **全部狀態進 URL**：稽核調查要能把連結貼給同事、要能回上一頁、要能被
 * 六個既有頁面深連結帶入；狀態藏在元件裡三者皆不可得。
 *
 * 時間一律輸出**帶時區偏移的 RFC3339**——後端明文拒收只有日期的參數，
 * 因為沒有偏移量的「今天」會落在伺服器時區上，跨時區調查時那正是爭議點。
 */
import { TIMELINE_TYPES } from './timelineSummary'

const pad = (n) => String(n).padStart(2, '0')

/** Date → `YYYY-MM-DDTHH:mm:ss±HH:mm`（本地時區偏移，與 el-date-picker 的
 *  `value-format="YYYY-MM-DDTHH:mm:ssZ"` 產出同形） */
export function toRfc3339Local(date) {
  const d = date instanceof Date ? date : new Date(date)
  if (Number.isNaN(d.getTime())) return ''
  const offsetMin = -d.getTimezoneOffset()
  const sign = offsetMin >= 0 ? '+' : '-'
  const abs = Math.abs(offsetMin)
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
    `${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
  )
}

const startOfDay = (base) => {
  const d = new Date(base)
  d.setHours(0, 0, 0, 0)
  return d
}

/**
 * 時間窗快捷。
 * @param {'today'|'last24h'|'around30m'} kind
 * @param {Date|number|string} [anchor] around30m 的中心點，預設現在
 * @returns {[string,string]} RFC3339 起訖
 */
export function shortcutRange(kind, anchor = Date.now()) {
  const now = new Date(anchor)
  if (kind === 'today') {
    const from = startOfDay(now)
    const to = new Date(from.getTime() + 24 * 3600 * 1000)
    return [toRfc3339Local(from), toRfc3339Local(to)]
  }
  if (kind === 'around30m') {
    return [
      toRfc3339Local(new Date(now.getTime() - 30 * 60 * 1000)),
      toRfc3339Local(new Date(now.getTime() + 30 * 60 * 1000)),
    ]
  }
  return [
    toRfc3339Local(new Date(now.getTime() - 24 * 3600 * 1000)),
    toRfc3339Local(now),
  ]
}

const isValidTime = (v) => typeof v === 'string' && !Number.isNaN(new Date(v).getTime())

/**
 * URL → 狀態。
 * `types` 三態：**缺席＝全部**、`''`＝一個都沒開（不送查詢）、csv＝子集。
 * 這個區分是必要的——把「全關」和「未指定」壓成同一種，貼上 URL 就會
 * 還原成另一個畫面。
 */
export function parseWorkbenchQuery(query = {}) {
  const subject = query.subject === 'asset' ? 'asset' : 'user'
  const idNum = Number(query.id)
  const rawTypes = query.types
  let types
  if (rawTypes === undefined || rawTypes === null) {
    types = [...TIMELINE_TYPES]
  } else {
    types = String(rawTypes)
      .split(',')
      .map((s) => s.trim())
      .filter((s) => TIMELINE_TYPES.includes(s))
  }
  return {
    subject,
    subjectId: Number.isInteger(idNum) && idNum > 0 ? idNum : null,
    from: isValidTime(query.from) ? query.from : '',
    to: isValidTime(query.to) ? query.to : '',
    types,
    focus: typeof query.focus === 'string' ? query.focus : '',
    view: query.view === 'table' ? 'table' : 'timeline',
  }
}

/** 狀態 → URL（空值一律不寫入，避免 `?focus=` 這種噪音參數污染分享連結） */
export function buildWorkbenchQuery(state) {
  const query = { subject: state.subject }
  if (state.subjectId) query.id = String(state.subjectId)
  if (state.from) query.from = state.from
  if (state.to) query.to = state.to
  const types = state.types || []
  if (types.length !== TIMELINE_TYPES.length) {
    query.types = types.join(',')
  }
  if (state.focus) query.focus = state.focus
  if (state.view === 'table') query.view = 'table'
  return query
}

/**
 * 兩份 query 是否等價（避免 router.replace 自我觸發無窮迴圈）。
 * **缺席與空字串不可視為相同**：`types` 缺席＝全開、`types=''`＝全關，
 * 壓成同一種會讓「全部關閉」寫不進 URL，畫面與網址就此分岔。
 */
export function sameQuery(a = {}, b = {}) {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)])
  for (const k of keys) {
    const av = a[k]
    const bv = b[k]
    if ((av === undefined || av === null) !== (bv === undefined || bv === null)) {
      return false
    }
    if (String(av ?? '') !== String(bv ?? '')) return false
  }
  return true
}
