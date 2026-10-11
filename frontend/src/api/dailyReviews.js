import request from './request'

// 呼叫端自行呈現錯誤時才帶旗標：既有呼叫的請求設定維持原樣
const skipToast = (options = {}) => (options.skipErrorToast ? { skipErrorToast: true } : {})

/**
 * 每日簽核摘要（PCI 10.4.1；儀表板卡片、工作區、政策頁時區說明）
 * @returns {Promise} { data: { enabled, timezone_state: { active, today: { date, window_start,
 *   window_end }, pending: null | { value, effective_date, effective_at } }, yesterday: { date,
 *   timezone, window_start, window_end, due_at, signable_at, signable, in_scope, enabled_basis,
 *   signed, review, counts, counts_fixed } | null, pending_count, overdue_count,
 *   earliest_pending_date, pending_dates, stats_30d } }
 */
export function getDailyReviewStatus(options = {}) {
  return request({
    url: '/daily-reviews/status',
    method: 'get',
    ...skipToast(options),
  })
}

/**
 * 待簽日清單（由最早排起，每頁至多 31 天）
 * @param {Object} params - { page, page_size }
 * @returns {Promise} { data: { items: [{ date, timezone, timezone_inferred, window_start,
 *   window_end, due_at, signable_at, signable, overdue, late_days, enabled_basis, counts }],
 *   total, page, page_size } }
 */
export function getDailyReviewPending(params, options = {}) {
  return request({
    url: '/daily-reviews/pending',
    method: 'get',
    params,
    ...skipToast(options),
  })
}

/**
 * 待簽天數與已逾期天數（側欄徽章輪詢；不做計數查詢）
 * @returns {Promise} { data: { count, overdue_count } }
 */
export function getDailyReviewPendingCount(options = {}) {
  return request({
    url: '/daily-reviews/pending/count',
    method: 'get',
    ...skipToast(options),
  })
}

/**
 * 單日明細
 * @param {string} date - 所屬日 YYYY-MM-DD
 * @returns {Promise} { data: { date, status(pending|settling|signed|out_of_scope|not_ended),
 *   timezone, timezone_inferred, window_start, window_end, due_at, signable_at, enabled_basis,
 *   overdue, late_days, sources, counts, unreviewed_alerts, login_failures, high_risk_ops,
 *   review, signed_snapshot, alerts_after_sign } }
 */
export function getDailyReviewDay(date, options = {}) {
  return request({
    url: `/daily-reviews/days/${encodeURIComponent(date)}`,
    method: 'get',
    ...skipToast(options),
  })
}

/**
 * 期間統計（期間、到期與分母的定義全在後端；前端只呈現回應的數字）
 * @param {Object} params - { period: '30d'|'90d' } 或 { from, to }（業務時區日期，含頭尾）
 * @returns {Promise} { data: { from, to, as_of, timezone, required, on_time, late, unsigned,
 *   sign_rate, sign_rate_percent, inferred_days, enabled_since, enabled_days, days } }
 */
export function getDailyReviewStats(params, options = {}) {
  return request({
    url: '/daily-reviews/stats',
    method: 'get',
    params,
    ...skipToast(options),
  })
}

/**
 * 簽核指定所屬日（alert:manage 權限）。簽核時刻由伺服器寫入，請求沒有這個欄位。
 * 409 CONFLICT_DAILY_REVIEW_SIGNED（params：date、signer、signed_at、timezone）；
 * 400 規則錯誤碼見抽屜的處理。
 * @param {Object} data - { review_date, note?, delay_reason? }
 * @returns {Promise} { data: 簽核列 }
 */
export function signDailyReview(data, options = {}) {
  return request({
    url: '/daily-reviews',
    method: 'post',
    data,
    ...skipToast(options),
  })
}

/**
 * 已簽紀錄（新到舊，分頁）
 * @param {Object} params - { page, page_size, late_only? }
 * @returns {Promise} { data: { items: [{ review_date, reviewer_name, signed_at, timezone,
 *   timezone_inferred, window_start, window_end, due_at, late, late_days, delay_reason, note,
 *   coverage, source_status, enabled_basis, snapshot_json }], total } }
 */
export function getDailyReviews(params) {
  return request({
    url: '/daily-reviews',
    method: 'get',
    params,
  })
}
