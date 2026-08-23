import request from './request'

/**
 * 存取複審 API（自 authorizations.js 遷出，
 * 職能歸審計區；讀取 audit:view、簽核 admin，全端點無條件守門）
 */

/**
 * 取得當下完整存取矩陣（audit-workflows，audit:view）
 * @returns {Promise} { data: [AccessMatrixEntry], total }
 */
export function getAccessMatrix() {
  return request({
    url: '/access-reviews/matrix',
    method: 'get',
  })
}

/**
 * 取得存取複審歷史與時效（audit:view）
 * @returns {Promise} { data: [{ id, reviewer_name, reviewed_at, note, authorization_count, days_ago }],
 *   last_review_days_ago, review_period_days, overdue }
 *   週期與逾期由伺服端單源回傳，前端不硬編碼
 */
export function getAccessReviews() {
  return request({
    url: '/access-reviews',
    method: 'get',
  })
}

/**
 * 取得單筆複審完整內容（audit:view）：中繼資料＋解析後矩陣陣列
 * @param {number} id
 * @returns {Promise} { id, reviewer_name, reviewed_at, scope, note, authorization_count, matrix: [AccessMatrixEntry] }
 */
export function getAccessReviewDetail(id) {
  return request({
    url: `/access-reviews/${id}`,
    method: 'get',
  })
}

/**
 * 提交一筆存取複審簽核（管理層確認，7.2.4，限 admin）
 * @param {Object} data - { note?: string }
 * @returns {Promise}
 */
export function createAccessReview(data) {
  return request({
    url: '/access-reviews',
    method: 'post',
    data,
  })
}
