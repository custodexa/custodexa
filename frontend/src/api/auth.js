import request from './request'

/**
 * 使用者登入
 * @param {Object} data - 登入資料
 * @param {string} data.username - 使用者名稱
 * @param {string} data.password - 密碼
 * @returns {Promise}
 */
export function login(data) {
  return request({
    url: '/auth/login',
    method: 'post',
    data,
  })
}

/**
 * 使用者登出：後端自 httpOnly cookie 取得 refresh 憑證並撤銷（會話撤銷），
 * 同時於回應清除該 cookie；本地 access token／使用者快取的清除由呼叫端負責
 * @returns {Promise}
 */
export function logout() {
  return request({
    url: '/auth/logout',
    method: 'post',
    data: {},
  })
}

/**
 * MFA 兩階段登入驗證
 * @param {Object} data - 驗證資料
 * @param {string} data.pending_token - 第一階段登入取得的暫時 token
 * @param {string} data.code - 6 位數 TOTP 驗證碼
 * @returns {Promise} 成功時回傳 { token, user }
 */
export function verifyMFA(data) {
  return request({
    url: '/auth/mfa/verify',
    method: 'post',
    data,
  })
}

/**
 * 產生 MFA 設定資訊（secret 與 otpauth URL）
 * POST：後端會覆寫 pending secret 並重設啟用狀態（有副作用，非冪等讀取）
 * @returns {Promise} 回傳 { secret, otpauth_url }
 */
export function getMFASetup() {
  return request({
    url: '/auth/mfa/setup',
    method: 'post',
  })
}

/**
 * 啟用 MFA
 * @param {Object} data - 啟用資料
 * @param {string} data.code - 6 位數 TOTP 驗證碼
 * @returns {Promise}
 */
export function enableMFA(data) {
  return request({
    url: '/auth/mfa/enable',
    method: 'post',
    data,
  })
}

/**
 * 停用 MFA（需驗證密碼）
 * @param {Object} data - 停用資料
 * @param {string} data.password - 目前密碼
 * @returns {Promise}
 */
export function disableMFA(data) {
  return request({
    url: '/auth/mfa/disable',
    method: 'post',
    data,
  })
}

/**
 * 自助修改密碼
 * 兩種情境：強制改密（傳入 changeToken）或已登入自願改密（走攔截器的正式 token）。
 * 成功時後端直接換發正式 token，回傳 { token, user }
 * @param {Object} data - { old_password, new_password }
 * @param {string} [changeToken] - 登入回應的 change_token（強制改密流程）
 * @returns {Promise}
 */
export function changePassword(data, changeToken) {
  return request({
    url: '/auth/change-password',
    method: 'post',
    data,
    // 改密表單自行呈現錯誤（就近顯示），不走全域 toast
    skipErrorToast: true,
    ...(changeToken
      ? { headers: { Authorization: `Bearer ${changeToken}` } }
      : {}),
  })
}

/**
 * MFA 強制註冊：以 enrollment token 產生 TOTP 設定（回 secret, otpauth_url）
 * @param {string} enrollmentToken - 登入回應的 enrollment_token
 * @returns {Promise}
 */
export function mfaEnrollSetup(enrollmentToken) {
  return request({
    url: '/auth/mfa/enroll/setup',
    method: 'post',
    skipErrorToast: true,
    headers: { Authorization: `Bearer ${enrollmentToken}` },
  })
}

/**
 * MFA 強制註冊：以 enrollment token + TOTP 碼完成綁定
 * 成功時後端直接換發正式 token，回傳 { token, user }（或 password_change_required）
 * @param {string} code - 6 位數 TOTP 驗證碼
 * @param {string} enrollmentToken - 登入回應的 enrollment_token
 * @returns {Promise}
 */
export function mfaEnrollConfirm(code, enrollmentToken) {
  return request({
    url: '/auth/mfa/enroll/confirm',
    method: 'post',
    data: { code },
    skipErrorToast: true,
    headers: { Authorization: `Bearer ${enrollmentToken}` },
  })
}

/**
 * 取得目前使用者資訊
 * @returns {Promise}
 */
export function getCurrentUser() {
  return request({
    url: '/auth/me',
    method: 'get',
  })
}

/**
 * 自助更新個人資料顯示名
 * PATCH /auth/me：僅放行 local_display_name；空字串/null 清除（回退 full_name/username）。
 * 身分綁定 token，target 使用者由後端從 claims 取得。成功回 canonical UserInfo（含 display_name）。
 * 就近顯示錯誤（如格式驗證），不走全域 toast
 * @param {string|null} localDisplayName - 顯示名（空字串清除）
 * @returns {Promise}
 */
export function updateProfileDisplayName(localDisplayName) {
  return request({
    url: '/auth/me',
    method: 'patch',
    data: { local_display_name: localDisplayName },
    skipErrorToast: true,
  })
}

/**
 * 取得使用者列表
 * @returns {Promise}
 */
export function getUsers() {
  return request({
    url: '/users',
    method: 'get',
  })
}
