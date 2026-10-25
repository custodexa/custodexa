import request from './request'

/** 改密計劃列表 */
export function getChangeSecretPlans() {
  return request({ url: '/change-secret-plans', method: 'get' })
}

/** 建立改密計劃 */
export function createChangeSecretPlan(data, config = {}) {
  return request({ url: '/change-secret-plans', method: 'post', data, ...config })
}

/** 更新改密計劃 */
export function updateChangeSecretPlan(id, data, config = {}) {
  return request({ url: `/change-secret-plans/${id}`, method: 'put', data, ...config })
}

/** 刪除改密計劃 */
export function deleteChangeSecretPlan(id) {
  return request({ url: `/change-secret-plans/${id}`, method: 'delete' })
}

/** 手動觸發改密批次 */
export function runChangeSecretPlan(id) {
  return request({ url: `/change-secret-plans/${id}/run`, method: 'post' })
}

/** 一鍵重新授權：升級後無從歸屬發起者而暫停的排程計畫，改由目前操作者承接 */
export function reauthorizeChangeSecretPlans() {
  return request({ url: '/change-secret-plans/reauthorize', method: 'post' })
}

/** 計劃執行記錄 */
export function getChangeSecretRecords(id) {
  return request({ url: `/change-secret-plans/${id}/records`, method: 'get' })
}

/** 未驗證候選憑證清單（不含任何秘密材料） */
export function getChangeSecretCandidates() {
  return request({ url: '/change-secret-candidates', method: 'get' })
}

/**
 * 確認主機身分後重送若得到 409（身分在確認之後又變更），由呼叫端顯示單一則說明，
 * 這類錯誤不走全域 toast（其餘錯誤照常）。
 */
export const skipHostIdentityMovedToast = (error) =>
  error?.response?.status === 409 && error.response.data?.code === 'CONFLICT_HOST_IDENTITY_MOVED'

/**
 * 對單筆候選立即觸發重試。
 * data 選用：主機身分確認時為 { confirm_host_identity: {...} }；不帶則維持原本的無 body 請求。
 */
export function retryChangeSecretCandidate(id, data) {
  const config = { url: `/change-secret-candidates/${id}/retry`, method: 'post' }
  if (data !== undefined) {
    config.data = data
    config.skipErrorToast = skipHostIdentityMovedToast
  }
  return request(config)
}

/** 清除候選憑證（破壞性：候選是可能已在遠端生效的秘密的唯一副本） */
export function discardChangeSecretCandidate(id) {
  return request({ url: `/change-secret-candidates/${id}`, method: 'delete' })
}
