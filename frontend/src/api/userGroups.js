import request from './request'

/**
 * 使用者群組 API（admin only）
 * 群組是授權主體的分組維度，與 RBAC 角色正交
 */

/**
 * 取得群組列表（含成員）
 * @returns {Promise} { data: [{id, name, description, users: [...]}], total }
 */
export function getUserGroups({ quiet = false } = {}) {
  return request({
    url: '/user-groups',
    method: 'get',
    // 呼叫端自行呈現「沒有權限」時，不再跳全域錯誤訊息
    ...(quiet ? { skipErrorToast: true } : {}),
  })
}

/**
 * 讀取群組目前的角色指派（唯讀）。
 * @returns {Promise} { data: [{role_id, role_name, scope}], total }
 */
export function getUserGroupRoleBindings(id, { quiet = false } = {}) {
  return request({
    url: `/user-groups/${id}/role-bindings`,
    method: 'get',
    ...(quiet ? { skipErrorToast: true } : {}),
  })
}

/**
 * 建立群組
 * @param {Object} data - { name, description }
 */
export function createUserGroup(data) {
  return request({
    url: '/user-groups',
    method: 'post',
    data,
  })
}

/**
 * 更新群組
 * @param {number} id
 * @param {Object} data - { name, description }
 */
export function updateUserGroup(id, data) {
  return request({
    url: `/user-groups/${id}`,
    method: 'put',
    data,
  })
}

/**
 * 刪除群組（連動撤銷掛該群組的授權，回 { revoked_authorizations }）
 * @param {number} id
 */
export function deleteUserGroup(id) {
  return request({
    url: `/user-groups/${id}`,
    method: 'delete',
  })
}

/**
 * 全量替換群組成員（穿梭框語義）
 * @param {number} id
 * @param {number[]} userIds
 */
export function replaceUserGroupMembers(id, manualUserIds) {
  return request({
    url: `/user-groups/${id}/members`,
    method: 'put',
    data: { manual_user_ids: manualUserIds },
  })
}

/**
 * 群組授權筆數（刪除確認「將連動撤銷 N 筆授權」）
 * @param {number} id
 * @returns {Promise} { authorization_count }
 */
export function getUserGroupAuthorizationCount(id) {
  return request({
    url: `/user-groups/${id}/authorization-count`,
    method: 'get',
  })
}

/**
 * 整組替換群組角色指派：本文為 { role_ids }（值含仍保留的受保護角色）。
 * 只有本次改動了節點範圍的角色才帶 role_nodes（鍵為角色編號字串；null 為全系統、陣列為節點）；
 * 沒有任何改動時整個欄位不存在。
 * @param {number} id
 * @param {number[]} roleIds
 * @param {Object} [roleNodes]
 */
export function replaceUserGroupRoleBindings(id, roleIds, roleNodes) {
  const data = { role_ids: roleIds }
  if (roleNodes && Object.keys(roleNodes).length > 0) data.role_nodes = roleNodes
  return request({
    url: `/user-groups/${id}/role-bindings`,
    method: 'put',
    data,
  })
}

/**
 * 依設定映射進這個群組的外部群組（唯讀，只含啟用中的規則）。
 * @returns {Promise} { data: [{rule_id, source_type, source_name, source_enabled, external_group_label}], total }
 */
export function getUserGroupExternalMappings(id, { quiet = true } = {}) {
  return request({
    url: `/user-groups/${id}/external-mappings`,
    method: 'get',
    ...(quiet ? { skipErrorToast: true } : {}),
  })
}
