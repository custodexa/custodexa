import request from './request'

/**
 * 取得自己的連線紀錄（my-connections）
 * 僅回呼叫者自己的 session 精簡欄位（資產/協議/連線時間/時長/狀態），
 * 無指令與錄影欄位；owner 由後端自 JWT 取得，不接受 user_id 參數
 * @param {Object} params - 查詢參數
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小（上限 100）
 * @returns {Promise}
 */
export function getMyConnections(params) {
  return request({
    url: '/my/connections',
    method: 'get',
    params,
  })
}

/**
 * 終止自己的進行中連線（owner-scoped）
 * 他人的與不存在的一律 404；非進行中回 400
 * @param {number} id - 連線 ID
 * @returns {Promise}
 */
export function terminateMyConnection(id) {
  return request({
    url: `/my/connections/${id}/terminate`,
    method: 'post',
  })
}
