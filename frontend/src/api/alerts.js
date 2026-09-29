import request from './request'

const skipToast = (options) => (options.skipErrorToast === true ? { skipErrorToast: true } : {})

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
 * @param {string} [params.ids] - 指定告警 ID（逗號分隔，上限 50 個）：批次審閱收尾時
 *   查回這幾筆的現況（reviewed_at／reviewed_by／disposition／note）
 * @param {Object} [options] - { skipErrorToast }：呼叫端自行呈現錯誤時關閉全域 toast
 * @returns {Promise} { data: [{ id, rule_id, rule_name, session_id, user_id, asset_id, command, severity, triggered_at }], total, page, page_size }
 */
export function searchAlerts(params, options = {}) {
  return request({
    url: '/command-alerts',
    method: 'get',
    params,
    // 只在呼叫端要求時才帶旗標：既有呼叫的請求設定維持原樣
    ...skipToast(options),
  })
}

/**
 * 審閱處置一筆告警（audit-workflows，alert:manage 權限）
 * 批次審閱逐筆呼叫同一端點：data 多帶 batch_id（UUID v4，同批共用）且 note 必填；
 * 送出時已有審閱結果回 409 CONFLICT_ALERT_ALREADY_REVIEWED、自己連線觸發者回
 * 403 RULE_ALERT_BATCH_SELF_TRIGGERED。
 * @param {number} id - 告警 ID
 * @param {Object} data - { disposition: 'benign'|'escalated', note?: string, batch_id?: string }
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise}
 */
export function reviewAlert(id, data, options = {}) {
  return request({
    url: `/command-alerts/${id}/review`,
    method: 'post',
    data,
    // 只在呼叫端要求時才帶旗標：既有呼叫的請求設定維持原樣
    ...skipToast(options),
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
