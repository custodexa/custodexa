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
 * 帶 batch_id 的逐筆送出（既有 API 呼叫端的路徑，介面已改走 batchReviewAlerts）：note 必填；
 * 送出時已有審閱結果回 409 CONFLICT_ALERT_ALREADY_REVIEWED、本人觸發者回
 * 403 RULE_ALERT_BATCH_SELF_TRIGGERED。不帶 batch_id 時理由選填、可重新審閱。
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
 * 一次請求審閱多筆告警（audit-workflows「告警批次審閱」，alert:manage 權限）。
 * 伺服端在一個交易內逐筆判定、逐筆寫入與留稽核，回逐筆結果；單次上限以回應的 limit 為準。
 * 用戶端逾時長於伺服端交易逾時：伺服端仍在處理時不先放棄（放棄＝待確認，不是失敗）。
 * @param {Object} data - { alert_ids: number[], disposition: 'benign'|'escalated', note: string,
 *   batch_id: string, self_triggered_ack: number }
 * @param {Object} [options] - { skipErrorToast, timeout }
 * @returns {Promise} { batch_id, limit, summary: { reviewed, already_reviewed, not_found, self_triggered },
 *   items: [{ id, result, self_triggered, reviewed_by_you?, existing_disposition? }] }
 */
export function batchReviewAlerts(data, options = {}) {
  return request({
    url: '/command-alerts/batch-review',
    method: 'post',
    data,
    timeout: options.timeout ?? 45_000,
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
 * 測試發送（admin 權限）；回 {success, status_code}，連線層失敗回 502 與錯誤碼。
 * 本文只帶 shape（webhook 的內容格式）；目的地一律是通道已存的設定。
 * 錯誤一律由測試對話框呈現（不跳全域訊息）。
 * @param {number} id - 通道 ID
 * @param {{shape?: string}} [data]
 * @returns {Promise}
 */
export function testChannel(id, data) {
  return request({
    url: `/notification-channels/${id}/test`,
    method: 'post',
    data,
    skipErrorToast: true,
  })
}

/**
 * 通道的投遞紀錄（唯讀、分頁、依排入時間倒序）；回 {data, total}
 * @param {number} id - 通道 ID
 * @param {{page?: number, page_size?: number}} params
 * @returns {Promise}
 */
export function getChannelDeliveries(id, params) {
  return request({
    url: `/notification-channels/${id}/deliveries`,
    method: 'get',
    params,
  })
}
