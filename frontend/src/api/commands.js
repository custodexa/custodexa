import request from './request'

/**
 * 取得單一會話的指令記錄（依 seq 排序）
 * @param {string|number} sessionId - 會話 ID
 * @returns {Promise} { data: [{ id, session_id, user_id, asset_id, command, seq, executed_at }], total }
 */
export function getSessionCommands(sessionId) {
  return request({
    url: `/sessions/${sessionId}/commands`,
    method: 'get',
  })
}

/**
 * 跨會話指令搜尋（auditor/admin 權限）
 * @param {Object} params - 查詢參數
 * @param {string} params.keyword - 指令關鍵字
 * @param {number} params.user_id - 使用者 ID 過濾
 * @param {number} params.asset_id - 資產 ID 過濾
 * @param {string} params.start_time - 開始時間（RFC3339 格式）
 * @param {string} params.end_time - 結束時間（RFC3339 格式）
 * @param {string} params.source - 來源過濾（console／cli）
 * @param {string} params.target_database - 目標資料庫名
 * @param {string[]} params.result_status - 結果狀態（可多選，聯集）
 * @param {string} params.error_code - 目標端錯誤碼
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @returns {Promise} { data: [...], total, page, page_size }
 */
export function searchCommands(params) {
  return request({
    url: '/commands',
    method: 'get',
    params,
    paramsSerializer: serializeCommandParams,
  })
}

/**
 * 檢索參數序列化。
 * 後端以「重複鍵」讀多選的結果狀態（`?result_status=ok&result_status=partial`），
 * axios 預設會序列化成 `result_status[]=`，那個鍵名後端讀不到——多選會靜默失效
 * 而查詢照樣回全集。空值一律略去，避免把空字串當成過濾條件送出。
 * @param {Object} params
 * @returns {string}
 */
export function serializeCommandParams(params) {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params || {})) {
    const append = (v) => {
      if (v === undefined || v === null || v === '') return
      search.append(key, String(v))
    }
    if (Array.isArray(value)) value.forEach(append)
    else append(value)
  }
  return search.toString()
}
