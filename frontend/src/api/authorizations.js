import request from './request'

/**
 * 取得授權列表（authorization-page-redesign D1：零篩選＝全量分頁；
 * user_id / user_group_id / asset_id 至多一個）
 * @param {Object} params - 查詢參數
 * @param {number} params.user_id - 使用者 ID（選填）
 * @param {number} params.user_group_id - 使用者群組 ID（選填）
 * @param {number} params.asset_id - 資產 ID（選填）
 * @param {number} params.page - 頁碼
 * @param {number} params.page_size - 每頁筆數
 * @param {string} params.validity - 有效性篩選 active/scheduled/expired（選填，伺服端生效）
 * @param {string} params.source - 來源篩選 manual/ticket（選填，伺服端生效）
 * @returns {Promise} data 列含 source/validity_state/date_start/date_expired；
 *   ticket 列另含 request_id/revocable
 */
export function getAuthorizations(params) {
  return request({
    url: '/authorizations',
    method: 'get',
    params,
  })
}

/**
 * 創建授權
 * @param {Object} data - 授權資料
 * @param {number} data.user_id - 使用者 ID
 * @param {number} data.asset_id - 資產 ID
 * @param {string} data.permission - 權限類型 (view/connect)
 * @returns {Promise}
 */
export function createAuthorization(data) {
  return request({
    url: '/authorizations',
    method: 'post',
    data,
  })
}

/**
 * 刪除授權（D4：ticket 來源且有關聯申請單者伺服端 409——走申請單撤銷流）
 * @param {number} id - 授權 ID
 * @returns {Promise}
 */
export function deleteAuthorization(id) {
  return request({
    url: `/authorizations/${id}`,
    method: 'delete',
  })
}

/**
 * 批次創建授權（user-group-authorization：伺服端交易內展開，
 * 主體集 users∪user_groups × 客體集 assets∪asset_groups，既有組合跳過）
 * @param {Object} data - { user_ids, user_group_ids, asset_ids, asset_group_ids, permission }
 * @returns {Promise} { created, skipped }
 */
export function batchCreateAuthorizations(data) {
  return request({
    url: '/authorizations/batch',
    method: 'post',
    data,
  })
}

/**
 * 調整授權列的帳號範圍（asset-multi-account D5，admin only）。
 * 收緊即時生效——兌換點 DB 現查，不受既簽發 token 效期影響。
 * ticket 來源列伺服端回 409 CONFLICT_TICKET_ACCOUNT_SCOPE_IMMUTABLE。
 * @param {number} id - 授權 ID
 * @param {string[]} accounts - `["@ALL"]`＝全部帳號；否則 username 清單
 * @returns {Promise} 更新後的授權列
 */
export function updateAuthorizationAccounts(id, accounts) {
  return request({
    url: `/authorizations/${id}/accounts`,
    method: 'put',
    data: { accounts },
    skipErrorToast: true,
  })
}

/**
 * 主體視角有效權限（authorization-page-redesign D3，admin only）：
 * 四路徑＋approver_scope＋role_override 溯因
 * @param {number} userId
 * @returns {Promise} { user_id, username, role_override, assets: [{ asset_id, asset_name, protocol, permission, paths }] }
 */
export function getEffectiveAssets(userId) {
  return request({
    url: '/authorizations/effective-assets',
    method: 'get',
    params: { user_id: userId },
  })
}

/**
 * 客體視角有效權限（authorization-page-redesign D3，admin only）：
 * 群組展開至成員＋approver_scope＋role_override 摘要
 * @param {number} assetId
 * @returns {Promise} { asset_id, asset_name, role_override_note, users: [{ user_id, username, permission, paths }] }
 */
export function getEffectiveUsers(assetId) {
  return request({
    url: '/authorizations/effective-users',
    method: 'get',
    params: { asset_id: assetId },
  })
}
