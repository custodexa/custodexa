import request from './request'

/**
 * 取得審計日誌列表
 * @param {Object} params - 查詢參數
 * @param {number} params.user_id - 使用者 ID 過濾
 * @param {string} params.action - 操作類型過濾 (create/read/update/delete/execute)
 * @param {string} params.resource - 資源類型過濾 (asset/session/user/auth)
 * @param {string} params.status - 狀態過濾 (success/failure/denied)
 * @param {string} params.client_ip - 客戶端 IP 過濾
 * @param {string} params.start_time - 開始時間（RFC3339 格式）
 * @param {string} params.end_time - 結束時間（RFC3339 格式）
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @param {string} params.sort_by - 排序欄位（默認 created_at）
 * @param {string} params.sort_order - 排序方向（asc/desc，默認 desc）
 * @returns {Promise}
 */
export function getAuditLogs(params) {
  return request({
    url: '/audit-logs',
    method: 'get',
    params,
  })
}

/**
 * 取得單條審計日誌詳情
 * @param {number} id - 審計日誌 ID
 * @returns {Promise}
 */
export function getAuditLog(id) {
  return request({
    url: `/audit-logs/${id}`,
    method: 'get',
  })
}

/**
 * 取得特定資源的審計歷史
 * @param {string} resource - 資源類型 (asset/session/user)
 * @param {number} resourceId - 資源 ID
 * @returns {Promise}
 */
export function getResourceAuditHistory(resource, resourceId) {
  return request({
    url: `/audit-logs/resource/${resource}/${resourceId}`,
    method: 'get',
  })
}
