import request from './request'

/**
 * 取得全部安全政策（含各鍵對生效政策組的判定）
 * @returns {Promise} 回傳 { data: PolicyView[]（每項附 verdicts）, groups: PolicyGroup[] }
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
 * @returns {Promise} 回傳更新後的 { data, groups }（形狀同 GET）
 */
export function updateSecurityPolicies(policies) {
  return request({
    url: '/security-policies',
    method: 'put',
    data: { policies },
  })
}

/**
 * 以尚未儲存的草稿值重算判定（唯讀，不寫入）。
 *
 * 判定由後端算而不是前端自己算：兩套邏輯會漂移，而分歧不會有任何一處報錯。
 *
 * `temp_controls` 讓尚未儲存的條文要求也走同一套比較器：條文編輯器把正在編輯
 * 的那一項送進來，後端以（組代號、設定鍵）覆蓋或新增控制後建構，只影響本次回應。
 *
 * @param {Object} draft - { [key]: value } 值一律字串；只需帶有變更的鍵
 * @param {Array} [tempControls] - [{ group_code, clause_no, policy_key, comparator,
 *   expected_value, reference_only }]；省略即不帶
 * @returns {Promise} 回傳 { data: ComplianceSnapshot }（draft=true）
 */
export function previewCompliance(draft, tempControls) {
  const data = { draft }
  if (tempControls && tempControls.length > 0) data.temp_controls = tempControls
  return request({
    url: '/security-policies/compliance/preview',
    method: 'post',
    data,
  })
}

/**
 * 套用政策建議值的預覽（只算不寫）。
 * @param {Object} payload - { scope: string[], mode: 'group'|'strictest', group_code?, draft? }
 * @returns {Promise} 回傳 { data: { mode, group_code, changes, conflicts, unchanged_count, unmapped_count } }
 */
export function previewApplyPolicies(payload) {
  return request({
    url: '/security-policies/apply-preview',
    method: 'post',
    data: payload,
  })
}
