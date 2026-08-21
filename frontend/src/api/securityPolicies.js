import request from './request'

/**
 * 取得全部安全政策（含 PCI 建議值 metadata 與符合性）
 * @returns {Promise} 回傳 { data: PolicyView[], deviation_count: number }
 */
export function getSecurityPolicies() {
  return request({
    url: '/security-policies',
    method: 'get',
  })
}

/**
 * 批次更新安全政策（僅送有變更的鍵；每項變更後端寫入審計）
 * @param {Object} policies - { [key]: value } 值一律字串
 * @returns {Promise} 回傳更新後的 { data, deviation_count }
 */
export function updateSecurityPolicies(policies) {
  return request({
    url: '/security-policies',
    method: 'put',
    data: { policies },
  })
}
