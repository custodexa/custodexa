/**
 * 工作台狀態 ↔ query string 的唯一轉換點（auditor-workbench）。
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

/** 工作台路徑：外部頁面（告警列表等）組深連結時的唯一來源，勿另行硬寫 */
export const WORKBENCH_PATH = '/audit/workbench'

/** 樞紐值域。**新增樞紐要經規格修訂**（auditor-workbench spec），不得以隱藏參數引入 */
export const WORKBENCH_SUBJECTS = ['user', 'asset', 'ip']

/**
 * 來源位址篩選的保留字：只保留未知來源的列（系統發起、寫入當下無法解析、
 * 所屬連線已不存在三種原因之任一）。它**永遠不是合法位址字串**，故與位址
 * 值域不衝突；後端於正規化之前判定，前端原樣往返即可。
 */
export const UNKNOWN_SOURCE = 'unknown'

const normalizeAddress = (v) => (typeof v === 'string' ? v.trim() : '')

/**
 * URL → 狀態。
 * `types` 三態：**缺席＝全部**、`''`＝一個都沒開（不送查詢）、csv＝子集。
 * 這個區分是必要的——把「全關」和「未指定」壓成同一種，貼上 URL 就會
 * 還原成另一個畫面。
 *
 * `id` 在位址樞紐下**是字串**（位址），不轉整數也不退回人樞紐：`Number('203.0.113.5')`
 * 是 NaN，沿用整數路徑會把一個合法的調查範圍靜默丟成「沒有選對象」。
 */
export function parseWorkbenchQuery(query = {}) {
  const subject = WORKBENCH_SUBJECTS.includes(query.subject) ? query.subject : 'user'
  const isIP = subject === 'ip'
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
    subjectId: !isIP && Number.isInteger(idNum) && idNum > 0 ? idNum : null,
    // 位址樞紐的主體鍵：原樣字串（含 IPv6 縮寫形式），正規化與合法性判定在後端
    subjectIp: isIP ? normalizeAddress(query.id) : '',
    // 位址篩選只存在於人／資產樞紐（位址樞紐下再帶一個位址條件，後端回 400）
    clientIp: isIP ? '' : normalizeAddress(query.ip),
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
  if (state.subject === 'ip') {
    const addr = normalizeAddress(state.subjectIp)
    if (addr) query.id = addr
  } else {
    if (state.subjectId) query.id = String(state.subjectId)
    const clientIp = normalizeAddress(state.clientIp)
    if (clientIp) query.ip = clientIp
  }
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
 * 位址深連結：一鍵以某位址為樞紐開新調查。
 *
 * **保留當前時間窗與類別**——稽核員點下去要接續同一段調查，不是重來一次；
 * 少帶這兩者等於逼他回頭再設一次條件（該連結的存在理由就沒了）。
 * `focus`／`view` 刻意不帶：前者是另一個樞紐下的事件鍵，後者是個人偏好。
 *
 * @param {string} address 位址（原樣，正規化在後端）
 * @param {{from?:string,to?:string,types?:string[]}} [scope] 要保留的調查範圍
 * @returns {{path:string,query:Object}|null} 位址為空時回 null——沒有目的地的連結是假話
 */
export function buildAddressPivotLink(address, scope = {}) {
  const addr = normalizeAddress(address)
  if (!addr) return null
  return {
    path: WORKBENCH_PATH,
    query: buildWorkbenchQuery({
      subject: 'ip',
      subjectIp: addr,
      from: scope.from || '',
      to: scope.to || '',
      types: scope.types || [...TIMELINE_TYPES],
    }),
  }
}

/**
 * 某日的本地整日時間窗（告警列表的位址深連結用：時間窗＝該告警觸發當日）。
 * @param {Date|number|string} anchor 當日任一時刻
 * @returns {[string,string]} RFC3339 起訖（本地時區偏移）
 */
export function localDayRange(anchor) {
  const d = new Date(anchor)
  if (Number.isNaN(d.getTime())) return ['', '']
  const from = startOfDay(d)
  const to = new Date(from.getTime() + 24 * 3600 * 1000)
  return [toRfc3339Local(from), toRfc3339Local(to)]
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
