import request from './request'

/**
 * SFTP 端點的會話帳號參數（asset-multi-account D9）。
 *
 * 帶 `session_id`＝自會話分頁進入檔案管理，後端沿用該會話的帳號快照
 * （終端開 root、旁邊卻以 app 傳檔是審計語義的斷裂）；不帶＝檔案管理獨立入口，
 * 走預設帳號。**授權仍以現行有效帳號集合重判**，舊 session 不是繞道。
 * 空值一律省略此參數，避免送出 `session_id=null` 讓後端當格式錯誤。
 * @param {number|string|null|undefined} sessionId
 * @returns {Object} 可展開進 params 的物件
 */
function sessionParam(sessionId) {
  return sessionId ? { session_id: Number(sessionId) } : {}
}

/**
 * 查詢當前使用者對該資產的資料傳輸有效能力（data-transfer-control 6.2）。
 *
 * **這是呈現用的讀取面，不是強制點**：強制在 SFTP／K8s 端點、tunnel 攔截與
 * guacd 連線參數三處。前端據此把不可用動作先呈現為不可用（而非讓使用者點下去
 * 才吃 403），但即使前端被繞過，伺服端仍會擋。
 * @param {number|string} assetId - 資產 ID
 * @returns {Promise<{capabilities: Object, clipboard_enforced_protocols: string[], clipboard_requires_reconnect: boolean}>}
 */
export function getTransferCapabilities(assetId) {
  return request({
    url: `/assets/${assetId}/transfer-capabilities`,
    method: 'get',
  })
}

/**
 * 列出資產遠端目錄
 * @param {number|string} assetId - 資產 ID
 * @param {string} path - 絕對路徑
 * @param {number|string} [sessionId] - 會話 ID（自會話分頁進入時帶）
 * @returns {Promise}
 */
export function listFiles(assetId, path, sessionId) {
  return request({
    url: `/assets/${assetId}/files`,
    method: 'get',
    params: { path, ...sessionParam(sessionId) },
  })
}

/**
 * 上傳檔案到資產遠端目錄
 * @param {number|string} assetId - 資產 ID
 * @param {string} path - 目的目錄（絕對路徑）
 * @param {File} file - 上傳檔案
 * @param {number|string} [sessionId] - 會話 ID（自會話分頁進入時帶）
 * @returns {Promise}
 */
export function uploadFile(assetId, path, file, sessionId) {
  const form = new FormData()
  form.append('path', path)
  form.append('file', file)
  return request({
    url: `/assets/${assetId}/files/upload`,
    method: 'post',
    data: form,
    // session_id 走 query：後端於 multipart 解析前就要決定帳號（統一 c.Query 取值）
    params: sessionParam(sessionId),
  })
}

/**
 * 下載遠端檔案（blob，token 走 Authorization header）
 * @param {number|string} assetId - 資產 ID
 * @param {string} path - 檔案絕對路徑
 * @param {number|string} [sessionId] - 會話 ID（自會話分頁進入時帶）
 * @returns {Promise<Blob>}
 */
export function downloadFile(assetId, path, sessionId) {
  return request({
    url: `/assets/${assetId}/files/download`,
    method: 'get',
    params: { path, ...sessionParam(sessionId) },
    responseType: 'blob',
  })
}

/**
 * 建立遠端目錄
 * @param {number|string} assetId - 資產 ID
 * @param {string} path - 新目錄絕對路徑
 * @param {number|string} [sessionId] - 會話 ID（自會話分頁進入時帶）
 * @returns {Promise}
 */
export function mkdir(assetId, path, sessionId) {
  return request({
    url: `/assets/${assetId}/files/mkdir`,
    method: 'post',
    data: { path },
    params: sessionParam(sessionId),
  })
}

/**
 * 刪除遠端檔案或空目錄
 * @param {number|string} assetId - 資產 ID
 * @param {string} path - 目標絕對路徑
 * @param {number|string} [sessionId] - 會話 ID（自會話分頁進入時帶）
 * @returns {Promise}
 */
export function deleteFile(assetId, path, sessionId) {
  return request({
    url: `/assets/${assetId}/files`,
    method: 'delete',
    params: { path, ...sessionParam(sessionId) },
  })
}
