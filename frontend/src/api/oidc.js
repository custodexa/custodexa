import request from './request'

/**
 * OIDC 身分提供者整合的 API 客戶端。
 *
 * 分兩組：登入流程（未認證可達）與 provider 管理（admin only）。
 */

/**
 * 取得可用登入方法（**未認證可讀**）。
 *
 * 回 { local: true, oidc: [{ id, name }] }。封印期後端回 503——呼叫端 SHALL
 * 降級為只顯示本地表單，故此處不走全域 toast（登入頁不該因清單失敗而彈錯誤）。
 * @returns {Promise}
 */
export function getAuthMethods() {
  return request({
    url: '/auth/methods',
    method: 'get',
    skipErrorToast: true,
  })
}

/**
 * 組出 SSO 發起網址（**整頁導向用，非 XHR**）。
 *
 * 後端回 302 至 IdP，必須由瀏覽器自行跟隨；以 axios 取回只會拿到 IdP 的
 * 授權頁 HTML（且被 CORS 擋），故此函式只回字串，由呼叫端 location.assign。
 * @param {number|string} providerId - provider ID
 * @param {string} bindingHash - 瀏覽器綁定值的 SHA-256（**不是** secret 本身）
 * @param {string} [next] - 登入後導向的站內相對路徑
 * @returns {string}
 */
export function buildOIDCBeginURL(providerId, bindingHash, next) {
  const params = new URLSearchParams({ binding: bindingHash })
  if (next) {
    params.set('next', next)
  }
  return `/api/v1/auth/oidc/${encodeURIComponent(providerId)}/begin?${params.toString()}`
}

/**
 * 以交棒憑證換取正式登入回應（與 /auth/login 同形，含 MFA 分支）。
 *
 * 失敗就近顯示於登入卡片內（不走全域 toast）。
 * @param {string} ticket - fragment 取得的一次性 ticket
 * @param {string} browserSecret - sessionStorage 保存的瀏覽器綁定原值
 * @returns {Promise} { login, redirect_next }
 */
export function exchangeSSOTicket(ticket, browserSecret) {
  return request({
    url: '/auth/oidc/exchange',
    method: 'post',
    data: { ticket, browser_secret: browserSecret },
    skipErrorToast: true,
  })
}

/**
 * 列出全部 OIDC provider（admin only；回應不含 client_secret 的任何形式）
 * @returns {Promise} { data: OIDCProviderDTO[] }
 */
export function getOIDCProviders() {
  return request({
    url: '/oidc-providers',
    method: 'get',
  })
}

/**
 * 建立 OIDC provider
 * @param {Object} data - { name, issuer, client_id, client_secret, scopes,
 *   admission_mode, admission_rules, force_shared, enabled }
 * @returns {Promise}
 */
export function createOIDCProvider(data) {
  return request({
    url: '/oidc-providers',
    method: 'post',
    data,
  })
}

/**
 * 更新 OIDC provider。
 *
 * issuer 與 client_id 建後不可變（後端強制，前端另行停用輸入）；
 * client_secret 留空即沿用既有值。
 * @param {number} id - provider ID
 * @param {Object} data - 同 create
 * @returns {Promise}
 */
export function updateOIDCProvider(id, data) {
  return request({
    url: `/oidc-providers/${id}`,
    method: 'put',
    data,
  })
}

/**
 * 刪除 OIDC provider（仍有外部身分關聯者後端回 409）
 * @param {number} id - provider ID
 * @returns {Promise}
 */
export function deleteOIDCProvider(id) {
  return request({
    url: `/oidc-providers/${id}`,
    method: 'delete',
  })
}
