import request from './request'

/**
 * 審計日誌完整性驗證（PCI 10.3.4；僅 admin）
 * 逐列重算完整性標記並與存檔比對，偵測日誌遭事後竄改
 * @param {Object} params - { from: 'YYYY-MM-DD', to: 'YYYY-MM-DD' }
 * @returns {Promise} { data: { from, to, checked, passed, mismatched,
 *   mismatched_ids, legacy } }；legacy 為功能上線前無完整性標記的歷史列
 */
export function verifyAuditIntegrity(params) {
  return request({
    url: '/audit-integrity/verify',
    method: 'get',
    params,
  })
}
