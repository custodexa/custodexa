/**
 * 日誌去識別。
 *
 * 背景：`console.error('回應錯誤:', error)` 印的是完整 AxiosError，其 `config.data`
 * 即為原始請求本文——帳號 CRUD 會帶明文密碼與私鑰，DevTools 開著就等同外洩，
 * 且 console 內容會被使用者截圖、被錯誤回報工具收集。
 *
 * 設計取捨：以**欄位名比對**而非「特定端點白名單」。端點清單會隨每個 change 漂移，
 * 漏登記一支就破防；欄位名（password／private_key／token…）是跨端點穩定的語彙，
 * 新端點只要沿用同一組命名就自動受保護。誤殺（把非敏感欄位遮掉）只損失除錯資訊，
 * 漏殺則是外洩——刻意偏保守。
 *
 * 邊界（誠實記載）：本模組只保證「不主動把敏感值寫進 console」。它不清除
 * JS 記憶體中既有的字串，也管不到瀏覽器 Network 面板（請求本文本來就看得到）。
 *
 * 分工：`redactAxiosError`／`apiErrorSummary` 皆為**白名單**摘要，
 * 不輸出任何請求本文或後端訊息；`redactSensitive` 是留給「確實需要輸出某個
 * 結構化欄位」時的 opt-in 遮蔽器，呼叫端需自行說明為何這個欄位值得冒險。
 */

export const REDACTED = '[redacted]'

// 敏感欄位名語彙：比對時先移除 `_`/`-` 並轉小寫，故 `private_key`／`privateKey`
// ／`PRIVATE-KEY` 皆命中。`token` 涵蓋 connect_token/refresh_token/change_token；
// `authorization`／`cookie` 擋憑證標頭。刻意不收單獨的 `key`——會誤殺 risk_keys 等
const SENSITIVE_FRAGMENTS = [
  'password',
  'passwd',
  'passphrase',
  'privatekey',
  'secret',
  'token',
  'authorization',
  'cookie',
  'credential',
  'apikey',
  'otp',
]

const normalizeKey = (key) => String(key).replace(/[_-]/g, '').toLowerCase()

/** 欄位名是否屬敏感語彙 */
export function isSensitiveKey(key) {
  const normalized = normalizeKey(key)
  return SENSITIVE_FRAGMENTS.some((fragment) => normalized.includes(fragment))
}

const MAX_DEPTH = 6

/**
 * 深層遮蔽敏感欄位；非物件原樣回傳。
 * JSON 字串（axios 送出後 `config.data` 已被序列化成字串）會先嘗試解析再遮蔽，
 * 解析不了就整串當不可信內容遮掉——寧可少一點除錯資訊
 *
 * 深度上限一律回 placeholder：原本超過
 * MAX_DEPTH 時回傳原值，等於「巢狀夠深就免檢查」——攻擊者或單純的深層 payload
 * （巢狀設定樹、批次匯入）可把 password 藏在第 7 層原封輸出。深度上限的語義
 * 必須是「這裡不再檢查，所以不輸出」，不能是「這裡不再檢查，所以照抄」。
 * @param {*} value
 * @param {number} [depth]
 * @returns {*}
 */
export function redactSensitive(value, depth = 0) {
  if (depth > MAX_DEPTH) return REDACTED
  if (value == null) return value
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return value
    try {
      return redactSensitive(JSON.parse(trimmed), depth + 1)
    } catch {
      return REDACTED
    }
  }
  if (typeof value !== 'object') return value
  // FormData/Blob/File 等非純資料物件不展開（可能含檔案內容）
  if (typeof FormData !== 'undefined' && value instanceof FormData) return '[form-data]'
  if (Array.isArray(value)) return value.map((v) => redactSensitive(v, depth + 1))
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    return '[object]'
  }
  const out = {}
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSensitiveKey(k) ? REDACTED : redactSensitive(v, depth + 1)
  }
  return out
}

/**
 * 元件層日誌用的**最小**錯誤摘要。
 *
 * 與 `redactAxiosError` 的差別是白名單而非黑名單：只輸出機器碼與 HTTP 狀態，
 * 連 url／請求本文／錯誤訊息都不帶。元件處理的是使用者身分類資料（subject、
 * email、claim），這些會出現在請求本文與後端訊息裡，而集中式前端日誌收集器
 * 會把 console 內容整包送走——除錯價值遠低於外洩代價。
 * @param {string} event 固定事件名（機器可讀，勿放使用者資料）
 * @param {*} error
 * @returns {[string, {status: number|undefined, code: string|undefined}]}
 */
export function apiErrorSummary(event, error) {
  return [
    event,
    {
      status: error?.response?.status,
      code: error?.response?.data?.code,
    },
  ]
}

/**
 * 把 AxiosError 壓成可安全寫入 console 的摘要。
 *
 * 白名單而非黑名單：舊版輸出後端 `error` 訊息、
 * axios `message` 與經欄位遮蔽的請求本文。欄位名遮蔽擋得住 password／token，
 * 擋不住**本身就是個資的欄位**——subject、email、username、full_name 全部原樣
 * 落進 console，而後端錯誤訊息常把衝突值回顯（「已綁定至帳號 xxx」）。
 * console 內容會被截圖、被集中式前端日誌收集器整包送走，除錯價值遠低於外洩代價。
 *
 * 保留的四欄都是機器碼或路由層事實：HTTP 方法、**去查詢字串的**路徑、HTTP 狀態、
 * 後端機器碼。要新增診斷欄位一律逐欄 opt-in，不得改回「輸出整個 response／request」。
 * @param {*} error
 * @returns {{method: string|undefined, url: string|undefined, status: number|undefined, code: string|undefined}}
 */
export function redactAxiosError(error) {
  const config = error?.config || {}
  const response = error?.response
  // query string 可能帶 search=<email>／token=<...>，路徑本身才是定位資訊
  const url = typeof config.url === 'string' ? config.url.split(/[?#]/)[0] : undefined
  return {
    method: (config.method || '').toUpperCase() || undefined,
    url,
    status: response?.status,
    code: response?.data?.code,
  }
}
