import request from './request'

/**
 * 取得授權列表（零篩選＝全量分頁；
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
 * 刪除授權（ticket 來源且有關聯申請單者伺服端 409——走申請單撤銷流）
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
 * 批次創建授權（伺服端交易內展開，
 * 主體集 users∪user_groups × 客體集 assets∪asset_groups，既有組合跳過）
 * @param {Object} data - { user_ids, user_group_ids, asset_ids, asset_group_ids, permission }
 * @returns {Promise} { created, skipped }
 */
export function batchCreateAuthorizations(data) {
  return request({
    url: '/authorizations/batch',
    method: 'post',
    data,
    skipErrorToast: true,
  })
}

/**
 * 調整授權列的帳號範圍（admin only）。
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
 * 本人範圍（任何已登入的人類使用者）：本人、本人直接所屬的群組、本人擁有的 agent，
 * 以及是否適用「不得授權給本人範圍」的限制（超級管理者 applies=false）。
 * 介面據此預先停用不可選的主體；後端守衛照常判定，讀取失敗時不預先停用。
 * @returns {Promise} { applies, user_id, user_group_ids, agent_ids }
 */
export function getSelfSubjects() {
  return request({
    url: '/authorizations/self-subjects',
    method: 'get',
    skipErrorToast: true,
  })
}

/**
 * 主體視角有效權限（admin only）：
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
 * 客體視角有效權限（admin only）：
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

/**
 * 授權畫面的主體選擇器：使用者或使用者群組目錄。
 * 不依節點範圍過濾；只要求操作者至少有一筆有效的授權規則管理指派。
 * 載入失敗由呼叫端就地提示，不走全域錯誤提示。
 * @param {Object} params
 * @param {'user'|'user_group'} params.kind - 必填
 * @param {string} [params.search] - 名稱關鍵字
 * @param {number} [params.page]
 * @param {number} [params.page_size]
 * @returns {Promise} { total, page, page_size, kind, data }；
 *   使用者列 { id, username, display_name, kind, active, roles }，
 *   群組列 { id, name, description, member_count }
 */
export function getAuthorizationSubjectOptions(params) {
  return request({
    url: '/authorizations/subject-options',
    method: 'get',
    params,
    skipErrorToast: true,
  })
}

/**
 * 授權畫面的客體選擇器：資產、節點或標籤候選（已依操作者的授權管理範圍投影）。
 * 節點列的 selectable 為假者只是定位用的祖先，不可授權。
 * @param {Object} params
 * @param {'asset'|'node'|'tag'} params.kind - 必填
 * @param {string} [params.search]
 * @param {number} [params.node_id] - 該節點與其子孫
 * @param {string} [params.tags] - 以逗號分隔，AND
 * @param {number} [params.page]
 * @param {number} [params.page_size]
 * @returns {Promise} { total, page, page_size, kind, data }；
 *   資產列 { id, name, protocol, host, nodes, out_of_scope_node_count? }，
 *   節點列 { id, name, path, selectable }，標籤列 { name, count }
 */
export function getAuthorizationTargetOptions(params) {
  return request({
    url: '/authorizations/target-options',
    method: 'get',
    params,
    skipErrorToast: true,
  })
}
