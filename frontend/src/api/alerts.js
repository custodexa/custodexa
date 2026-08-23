import request from './request'

/**
 * 查詢指令告警記錄（audit:view 權限）
 * @param {Object} params - 查詢參數
 * @param {string} params.severity - 嚴重程度過濾（high/medium/low）
 * @param {number} params.user_id - 使用者 ID 過濾
 * @param {number} params.asset_id - 資產 ID 過濾
 * @param {string} params.start_time - 開始時間（RFC3339 格式）
 * @param {string} params.end_time - 結束時間（RFC3339 格式）
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @returns {Promise} { data: [{ id, rule_id, rule_name, session_id, user_id, asset_id, command, severity, triggered_at }], total, page, page_size }
 */
export function searchAlerts(params) {
  return request({
    url: '/command-alerts',
    method: 'get',
    params,
  })
}

/**
 * 審閱處置一筆告警（audit-workflows，alert:manage 權限）
 * @param {number} id - 告警 ID
 * @param {Object} data - { disposition: 'benign'|'escalated', note?: string }
 * @returns {Promise}
 */
export function reviewAlert(id, data) {
  return request({
    url: `/command-alerts/${id}/review`,
    method: 'post',
    data,
  })
}

/**
 * 取得告警規則列表（admin 權限）
 * @returns {Promise} { data: [{ id, name, pattern, severity, enabled }] }
 */
export function getAlertRules() {
  return request({
    url: '/alert-rules',
    method: 'get',
  })
}

/**
 * 建立告警規則（admin 權限；無效 regex 回 400 { error }）
 * @param {Object} data - { name, pattern, severity, enabled }
 * @returns {Promise} { id, name, pattern, severity, enabled }
 */
export function createAlertRule(data) {
  return request({
    url: '/alert-rules',
    method: 'post',
    data,
  })
}

/**
 * 更新告警規則（admin 權限；無效 regex 回 400 { error }）
 * @param {number} id - 規則 ID
 * @param {Object} data - { name, pattern, severity, enabled }
 * @returns {Promise} { id, name, pattern, severity, enabled }
 */
export function updateAlertRule(id, data) {
  return request({
    url: `/alert-rules/${id}`,
    method: 'put',
    data,
  })
}

/**
 * 刪除告警規則（admin 權限）
 * @param {number} id - 規則 ID
 * @returns {Promise}
 */
export function deleteAlertRule(id) {
  return request({
    url: `/alert-rules/${id}`,
    method: 'delete',
  })
}

/**
 * 通知通道列表（admin 權限）
 * @returns {Promise}
 */
export function getChannels() {
  return request({
    url: '/notification-channels',
    method: 'get',
  })
}

/**
 * 新增通知通道（admin 權限）
 * @param {Object} data - {name, type, url, secret, enabled}
 * @returns {Promise}
 */
export function createChannel(data, options = {}) {
  return request({
    url: '/notification-channels',
    method: 'post',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 更新通知通道（admin 權限）
 * @param {number} id - 通道 ID
 * @returns {Promise}
 */
export function updateChannel(id, data, options = {}) {
  return request({
    url: `/notification-channels/${id}`,
    method: 'put',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 刪除通知通道（admin 權限）
 * @param {number} id - 通道 ID
 * @returns {Promise}
 */
export function deleteChannel(id) {
  return request({
    url: `/notification-channels/${id}`,
    method: 'delete',
  })
}

/**
 * 測試發送（admin 權限）；回 {success, status_code 或 error}
 * @param {number} id - 通道 ID
 * @returns {Promise}
 */
export function testChannel(id) {
  return request({
    url: `/notification-channels/${id}/test`,
    method: 'post',
  })
}
