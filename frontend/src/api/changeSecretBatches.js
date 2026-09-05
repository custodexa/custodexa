import request from './request'

/**
 * 以帳號名為軸的批次改密。
 *
 * 建立為非同步（202）：回應只帶批次本身，逐目標的結果要向單一批次端點查詢。
 * 回應一律不含任何秘密材料，錯誤欄只有系統列舉的機器碼。
 */

/** 登記於系統的帳號名清單（附持有它的資產數） */
export function getChangeSecretBatchUsernames() {
  return request({ url: '/change-secret-batches/usernames', method: 'get' })
}

/** 指定帳號名的全部目標（含執行前即可判定的不可改密原因） */
export function getChangeSecretBatchTargets(username) {
  return request({ url: '/change-secret-batches/targets', method: 'get', params: { username } })
}

/** 建立批次（非同步執行，回應為 202 與批次本身） */
export function createChangeSecretBatch(data) {
  return request({ url: '/change-secret-batches', method: 'post', data })
}

/** 最近批次 */
export function getChangeSecretBatches() {
  return request({ url: '/change-secret-batches', method: 'get' })
}

/** 單一批次與其逐目標記錄 */
export function getChangeSecretBatch(id) {
  return request({ url: `/change-secret-batches/${id}`, method: 'get' })
}
