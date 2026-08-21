import request from './request'

/**
 * 取得用戶列表
 * @param {Object} params - 查詢參數
 * @param {string} params.search - 搜尋關鍵字（用戶名或郵箱）
 * @param {boolean} params.active - 狀態過濾
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @returns {Promise}
 */
export function getUserList(params) {
  return request({
    url: '/users',
    method: 'get',
    params,
  })
}

/**
 * 創建用戶
 * @param {Object} data - 用戶資料
 * @param {string} data.username - 用戶名
 * @param {string} data.password - 密碼
 * @param {string} data.email - 郵箱
 * @param {string} data.full_name - 全名
 * @param {Array<string>} data.roles - 角色列表
 * @returns {Promise}
 */
export function createUser(data) {
  return request({
    url: '/users',
    method: 'post',
    data,
  })
}

/**
 * 取得用戶詳情
 * @param {number} id - 用戶 ID
 * @returns {Promise}
 */
export function getUserDetail(id) {
  return request({
    url: `/users/${id}`,
    method: 'get',
  })
}

/**
 * 更新用戶
 * @param {number} id - 用戶 ID
 * @param {Object} data - 更新資料
 * @param {string} data.email - 郵箱
 * @param {string} data.full_name - 全名
 * @returns {Promise}
 */
export function updateUser(id, data) {
  return request({
    url: `/users/${id}`,
    method: 'put',
    data,
  })
}

/**
 * 刪除用戶
 * @param {number} id - 用戶 ID
 * @returns {Promise}
 */
export function deleteUser(id) {
  return request({
    url: `/users/${id}`,
    method: 'delete',
  })
}

/**
 * 分配角色
 * @param {number} id - 用戶 ID
 * @param {Array<string>} roles - 角色列表
 * @returns {Promise}
 */
export function assignRoles(id, roles) {
  return request({
    url: `/users/${id}/roles`,
    method: 'put',
    data: { roles },
  })
}

/**
 * 冪等追加單一角色（不覆蓋既有角色集，避免快照過期的 lost-update）
 * @param {number} id - 用戶 ID
 * @param {string} role - 角色名稱
 * @returns {Promise}
 */
export function addUserRole(id, role) {
  return request({
    url: `/users/${id}/roles/${role}`,
    method: 'post',
  })
}

/**
 * 更新用戶狀態
 * @param {number} id - 用戶 ID
 * @param {boolean} active - 啟用狀態
 * @returns {Promise}
 */
export function updateUserStatus(id, active) {
  return request({
    url: `/users/${id}/status`,
    method: 'put',
    data: { active },
  })
}

/**
 * 修改密碼
 * @param {number} id - 用戶 ID
 * @param {string} password - 新密碼
 * @returns {Promise}
 */
export function changePassword(id, password) {
  return request({
    url: `/users/${id}/password`,
    method: 'put',
    data: { password },
  })
}

/**
 * 管理員解鎖帳號（清除登入失敗計數與鎖定狀態）
 * @param {number} id - 用戶 ID
 * @returns {Promise}
 */
export function unlockUser(id) {
  return request({
    url: `/users/${id}/unlock`,
    method: 'post',
  })
}

/**
 * 管理員停用指定用戶的 MFA
 * @param {number} id - 用戶 ID
 * @returns {Promise}
 */
export function adminDisableMFA(id) {
  return request({
    url: `/users/${id}/mfa/disable`,
    method: 'post',
  })
}

/**
 * 設定閒置停用豁免（PCI 8.2.6，auth-hardening D8）
 * @param {number} id - 用戶 ID
 * @param {boolean} exempt - 是否豁免自動停用
 * @returns {Promise}
 */
export function setInactivityExempt(id, exempt) {
  return request({
    url: `/users/${id}/inactivity-exempt`,
    method: 'put',
    data: { exempt },
  })
}

/**
 * 列出帳號已綁定的外部身分（idp-oidc-integration 2.8 / UA-1）。
 *
 * 回 { data: ExternalIdentityDTO[], total }；DTO 的 claim_username／claim_email
 * 是**身分提供者自報值**（IdP 端可任意設定），呈現時必須與本地 username 分欄
 * 並標示來源，不得混排或當成操作目標。
 * @param {number} id - 用戶 ID
 * @returns {Promise}
 */
export function getExternalIdentities(id) {
  return request({
    url: `/users/${id}/external-identities`,
    method: 'get',
  })
}

/**
 * admin 為既有帳號綁定外部身分。
 *
 * issuer／client_id 由後端取自 provider 列（身分域的組成不收前端輸入），
 * 故請求只帶 provider_id 與 subject。
 * @param {number} id - 用戶 ID
 * @param {number} providerId - OIDC provider ID
 * @param {string} subject - IdP 的 subject（大小寫敏感，不做正規化）
 * @returns {Promise}
 */
export function bindExternalIdentity(id, providerId, subject) {
  return request({
    url: `/users/${id}/external-identities`,
    method: 'post',
    data: { provider_id: providerId, subject },
  })
}

/**
 * 解除外部身分綁定。
 *
 * **成功即使該使用者的全部既有存取失效**（使用者級粒度的刻意取捨）：刷新憑證、
 * 既簽存取憑證、協議連線、唯讀訂閱與未兌換的能力憑證全數作廢，含經其他 provider
 * 或本地密碼建立者。呼叫端須於確認前明示此後果。
 *
 * 後端會以 RULE_USER_LAST_LOGIN_PATH 拒絕「解綁後無登入途徑」，呼叫端須就近
 * 提供「解綁並停用帳號」出路，故此處關閉全域 toast。
 * @param {number} id - 用戶 ID
 * @param {number} identityId - 外部身分 ID
 * @returns {Promise}
 */
export function unbindExternalIdentity(id, identityId) {
  return request({
    url: `/users/${id}/external-identities/${identityId}`,
    method: 'delete',
    skipErrorToast: true,
  })
}

/**
 * 原子「解除綁定並停用帳號」——「解綁後無登入途徑」時的正當出路。
 * @param {number} id - 用戶 ID
 * @param {number} identityId - 外部身分 ID
 * @returns {Promise}
 */
export function unbindExternalIdentityAndDisable(id, identityId) {
  return request({
    url: `/users/${id}/external-identities/${identityId}/unbind-and-disable`,
    method: 'post',
  })
}

/**
 * 改為僅外部登入：清除本地密碼雜湊、標記憑證外部化並推進憑證世代。
 *
 * **不可逆**（要恢復本地密碼須由管理員另行設定新密碼）：轉換後該帳號只能經
 * 已綁定的外部身分登入，全部既有工作階段與待驗證 MFA 憑證立即失效。
 * 後端前提：帳號至少已有一筆外部身分（RULE_USER_EXTERNAL_IDENTITY_REQUIRED），
 * 且不得因此失去最後一個本地管理員（RULE_USER_LAST_LOCAL_ADMIN）——兩者皆為
 * 「拒絕後要給出路」的規則錯誤，故關閉全域 toast 由呼叫端就近顯示。
 * @param {number} id - 用戶 ID
 * @returns {Promise}
 */
export function convertUserToExternalOnly(id) {
  return request({
    url: `/users/${id}/external-only`,
    method: 'post',
    skipErrorToast: true,
  })
}

/**
 * 現存本地管理員數（admin only，唯讀）。
 *
 * 回 `{ count }`。定義與「本地 admin 不得自一以上降為零」不變式同源
 *（啟用中、具 admin 角色、密碼非空、憑證未由外部提供者託管）。
 * 呼叫端據此條件式警示：`count === 0` 表示系統封印後無人能解封。
 *
 * **讀取失敗不得當成 count ≥ 1**：狀態未知時呼叫端須 fail-safe 顯示通用警語，
 * 故此處關閉全域 toast，由呼叫端就近呈現。
 * @returns {Promise}
 */
export function getLocalAdminCount() {
  return request({
    url: '/users/local-admin-count',
    method: 'get',
    skipErrorToast: true,
  })
}

/**
 * 取得角色列表
 * @returns {Promise}
 */
export function getRoleList() {
  return request({
    url: '/roles',
    method: 'get',
  })
}
