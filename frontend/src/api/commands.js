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
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @returns {Promise} { data: [...], total, page, page_size }
 */
export function searchCommands(params) {
  return request({
    url: '/commands',
    method: 'get',
    params,
  })
}
