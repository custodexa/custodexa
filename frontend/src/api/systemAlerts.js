import request from './request'

/**
 * 取得系統告警類型目錄（systemalert:manage）。
 * 具稽核檢視者的回應每列另帶 recent_30d（近 30 天筆數）；沒有稽核檢視時該欄缺席。
 * @returns {Promise} { types: [{ key, group, default_severity, effective_severity, adjusted, recent_30d? }] }
 */
export function getSystemAlertTypes() {
  return request({
    url: '/system-alert-types',
    method: 'get',
  })
}

/**
 * 調整一個系統告警類型的分級（systemalert:manage）。
 * 只接受 severity；系統告警沒有停用或刪除入口。
 * @param {string} key - 類型鍵
 * @param {'high'|'medium'|'low'} severity
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} { key, severity_before, severity_after }
 */
export function updateSystemAlertSeverity(key, severity, options = {}) {
  return request({
    url: `/system-alert-types/${encodeURIComponent(key)}`,
    method: 'put',
    data: { severity },
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 取得一筆系統告警的結構化明細（稽核檢視）。
 * @param {number} alertId - 告警 ID（非系統告警回 404）
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} { alert_id, alert_type, group, severity, triggered_at, actor, target_kind,
 *   target_id, params, correlation_id, audit_log_id, deliveries: [{ dest_type, dest_name, state,
 *   attempts, delivered_at?, next_attempt_at }] }
 */
export function getSystemAlertDetail(alertId, options = {}) {
  return request({
    url: `/command-alerts/${alertId}/system-detail`,
    method: 'get',
    skipErrorToast: options.skipErrorToast === true,
  })
}
