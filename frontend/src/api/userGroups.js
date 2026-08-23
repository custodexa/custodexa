import request from './request'

/**
 * 使用者群組 API（admin only）
 * 群組是授權主體的分組維度，與 RBAC 角色正交
 */

/**
 * 取得群組列表（含成員）
 * @returns {Promise} { data: [{id, name, description, users: [...]}], total }
 */
export function getUserGroups() {
  return request({
    url: '/user-groups',
    method: 'get',
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
export function replaceUserGroupMembers(id, userIds) {
  return request({
    url: `/user-groups/${id}/members`,
    method: 'put',
    data: { user_ids: userIds },
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
