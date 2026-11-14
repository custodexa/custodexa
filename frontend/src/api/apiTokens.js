import request from './request'

// API token 的端點。回應原樣交給呼叫端：狀態、優先序與角色是否有效一律以後端投影為準。
// 錯誤由各畫面就近呈現，不走全域提示。

// 本人：清單、建立資格與可授權的角色
export const getMyApiTokens = () =>
  request({ url: '/my/api-tokens', method: 'get', skipErrorToast: true })

// 本人建立：回應含一次性明文，只能交給明文顯示元件的區域狀態
export const createMyApiToken = (data) =>
  request({ url: '/my/api-tokens', method: 'post', data, skipErrorToast: true })

export const revokeMyApiToken = (id, note = '') =>
  request({ url: `/my/api-tokens/${id}`, method: 'delete', data: { note }, skipErrorToast: true })

// 管理者：查看與撤銷他人的 API token
export const getUserApiTokens = (userId) =>
  request({ url: `/users/${userId}/api-tokens`, method: 'get', skipErrorToast: true })

export const revokeUserApiToken = (userId, tokenId, note = '') =>
  request({
    url: `/users/${userId}/api-tokens/${tokenId}`,
    method: 'delete',
    data: { note },
    skipErrorToast: true,
  })

export const revokeAllUserApiTokens = (userId, note = '') =>
  request({
    url: `/users/${userId}/api-tokens/revoke-all`,
    method: 'post',
    data: { note },
    skipErrorToast: true,
  })

// 自我查驗端點的路徑（只用來組出給使用者貼到終端機的指令，畫面本身不呼叫）
export const API_TOKEN_VERIFY_PATH = '/api/v1/api-tokens/verify'
