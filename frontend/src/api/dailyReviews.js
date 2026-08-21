import request from './request'

/**
 * 取得今日審閱簽核狀態（audit-log-compliance，PCI 10.4.1）
 * @returns {Promise} { data: { enabled, signed?, snapshot?: { date, login_failures,
 *   unreviewed_alerts, high_risk_ops }, review?: { review_date, reviewer_name,
 *   created_at, note, snapshot_json } } }；enabled=false 時僅 { enabled: false }
 */
export function getDailyReviewStatus() {
  return request({
    url: '/daily-reviews/status',
    method: 'get',
  })
}

/**
 * 簽核今日審閱（alert:manage 權限，auditor/admin）
 * 409 = 當日已完成簽核（error 帶簽核者與時間）；400 = 功能未啟用
 * @param {Object} data - { note?: string } 簽核備註（選填）
 * @returns {Promise} 簽核列
 */
export function signDailyReview(data) {
  return request({
    url: '/daily-reviews',
    method: 'post',
    data,
  })
}

/**
 * 每日簽核歷史（分頁）
 * @param {Object} params - { page, page_size }
 * @returns {Promise} { data: { items: [{ review_date, reviewer_name, snapshot_json,
 *   note, created_at }], total } }
 */
export function getDailyReviews(params) {
  return request({
    url: '/daily-reviews',
    method: 'get',
    params,
  })
}
