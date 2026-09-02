// 查詢主控台的 API 面：WebSocket 位址組裝、結果匯出、匯出能力投影。
//
// 兩件事在此收口而不散在元件裡：
//   1. WS 位址只帶一次性連線票——憑證與長效 JWT 一律不進 query string，
//      單元測試據此逐項斷言（同 SSH 分頁的既有契約）。
//   2. 匯出以 `(event_id, set_index)` 定址：同一次送出可能產生多個執行單位
//      （批次終止符切出的批次），每個單位又可能有多個結果集，兩者都要進位址。
import request from './request'
import { getTransferCapabilities } from './files'

export const DB_CONSOLE_WS_PATH = '/api/v1/db-console'

// 能力投影目前只有這一鍵。**它永遠不是授權真相**：匯出端點每次都重驗傳輸政策，
// 畫面只用它決定停用樣式。
export const EXPORT_CAPABILITY = 'file_download'

/**
 * 主控台 WebSocket 位址。
 * scheme 依頁面協定推導（https→wss），使應用置於外部 TLS ingress 後即自動走 wss。
 * @param {string} connectToken 一次性連線票
 * @returns {string}
 */
export function dbConsoleSocketUrl(connectToken) {
  const params = new URLSearchParams({ connect_token: connectToken })
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${window.location.host}${DB_CONSOLE_WS_PATH}?${params.toString()}`
}

/**
 * 結果匯出端點路徑（相對 baseURL）。
 * @param {number|string} sessionId 會話 ID
 * @param {string} eventId 執行單位的事件識別
 * @returns {string}
 */
export function resultExportPath(sessionId, eventId) {
  return (
    `/db-console/sessions/${encodeURIComponent(sessionId)}` +
    `/results/${encodeURIComponent(eventId)}/export`
  )
}

/**
 * 下載某結果集的 CSV（blob；JWT 走 Authorization header）。
 * 伺服端對六種不成立情形一律回同一個 404，前端不據回應反推原因。
 * @param {number|string} sessionId
 * @param {string} eventId
 * @param {number} [setIndex] 結果集索引
 * @returns {Promise<Blob>}
 */
export function downloadResultCsv(sessionId, eventId, setIndex = 0) {
  return request({
    url: resultExportPath(sessionId, eventId),
    method: 'get',
    params: { set: setIndex, format: 'csv' },
    responseType: 'blob',
    // 匯出失敗要就近呈現於結果區（拒絕與找不到都是可預期路徑），不走全域 toast
    skipErrorToast: true,
  })
}

/**
 * 匯出檔名。
 * 回應攔截器只交還 body，讀不到伺服端下的 `Content-Disposition`，故前端自組一份
 * 同構的名字（資產名－序號－結果集－本地時戳），使同一範圍匯出兩次可分辨先後。
 * @param {object} parts
 * @param {string} [parts.assetName]
 * @param {number} [parts.seq] 執行單位序號
 * @param {number} [parts.setIndex]
 * @param {Date} [parts.at]
 * @returns {string}
 */
export function exportFilename({ assetName = '', seq = 0, setIndex = 0, at = new Date() } = {}) {
  const p = (n) => String(n).padStart(2, '0')
  const stamp =
    `${at.getFullYear()}${p(at.getMonth() + 1)}${p(at.getDate())}` +
    `-${p(at.getHours())}${p(at.getMinutes())}${p(at.getSeconds())}`
  // 檔名安全：資產名由管理者自填，空白、路徑分隔與檔名保留字元一律折成底線
  const safeName = String(assetName || 'result').replace(/[\s/\\:*?"<>|]/g, '_')
  return `${safeName}-${seq}-${setIndex}-${stamp}.csv`
}

/**
 * 能力查譯：把伺服端下發的能力集折成畫面要的旗標。
 * 未取得能力集（尚未 ready、或查詢失敗）時視為可用——呈現面 fail-open，
 * 真正的強制點在匯出端點。
 * @param {object|null|undefined} capabilities `ready.capabilities`
 * @returns {boolean} 匯出鈕是否可用
 */
export function allowsExport(capabilities) {
  if (!capabilities) return true
  return capabilities[EXPORT_CAPABILITY] !== false
}

/**
 * 重抓匯出能力投影（政策中途放寬時毋須重連即可解除停用態）。
 * 與匯出端點同一政策事實源；查詢失敗回 null，呼叫端保留上一次已知值。
 * @param {number|string} assetId
 * @returns {Promise<boolean|null>}
 */
export async function fetchExportCapability(assetId) {
  if (!assetId) return null
  try {
    const res = await getTransferCapabilities(assetId)
    const caps = res?.capabilities
    if (!caps) return null
    return caps[EXPORT_CAPABILITY] !== false
  } catch (err) {
    console.error(
      '[dbConsole] 匯出能力查詢失敗:',
      err?.response?.status,
      err?.response?.data?.code
    )
    return null
  }
}
