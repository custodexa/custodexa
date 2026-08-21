import request from './request'

/** 改密計劃列表 */
export function getChangeSecretPlans() {
  return request({ url: '/change-secret-plans', method: 'get' })
}

/** 建立改密計劃 */
export function createChangeSecretPlan(data) {
  return request({ url: '/change-secret-plans', method: 'post', data })
}

/** 更新改密計劃 */
export function updateChangeSecretPlan(id, data) {
  return request({ url: `/change-secret-plans/${id}`, method: 'put', data })
}

/** 刪除改密計劃 */
export function deleteChangeSecretPlan(id) {
  return request({ url: `/change-secret-plans/${id}`, method: 'delete' })
}

/** 手動觸發改密批次 */
export function runChangeSecretPlan(id) {
  return request({ url: `/change-secret-plans/${id}/run`, method: 'post' })
}

/** 計劃執行記錄 */
export function getChangeSecretRecords(id) {
  return request({ url: `/change-secret-plans/${id}/records`, method: 'get' })
}

/** 未驗證候選憑證清單（不含任何秘密材料） */
export function getChangeSecretCandidates() {
  return request({ url: '/change-secret-candidates', method: 'get' })
}

/** 對單筆候選立即觸發重試 */
export function retryChangeSecretCandidate(id) {
  return request({ url: `/change-secret-candidates/${id}/retry`, method: 'post' })
}

/** 清除候選憑證（破壞性：候選是可能已在遠端生效的秘密的唯一副本） */
export function discardChangeSecretCandidate(id) {
  return request({ url: `/change-secret-candidates/${id}`, method: 'delete' })
}
