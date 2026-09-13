import request from './request'

// Status is public; unsealing requires an administrator-verified grant.
export function getSealStatus(config = {}) {
  return request({
    url: '/seal/status',
    method: 'get',
    ...config,
  })
}

// 解封流程的第一段：管理員帳號與密碼驗證（封印閘白名單端點）。
// payload 為精確鍵集 `{ username, password }`。
// **回應刻意不可區分**（帳號不存在／密碼錯／非管理者／停用／鎖定同一碼同一形狀），
// 呼叫端 SHALL 直接呈現 resolveApiError 的結果，SHALL NOT 自行推測失敗成因。
// 成功回 `{ grant, expires_at, topology_digest }`；grant 只存在於行程與本頁記憶體，
// 不是業務工作階段憑證，也 SHALL NOT 寫入任何 storage。
export function sealAuthorize(payload, config = {}) {
  return request({
    url: '/seal/authorize',
    method: 'post',
    data: payload,
    ...config,
  })
}

// 送出一次解封嘗試。payload 依分支為精確鍵集（後端以未知欄位拒絕，夾帶多餘鍵即整包被拒）：
//   ui 一般解封：{ kek }
//   ui 初始化：{ kek, kek_confirm, confirm_saved, username, password }
//   env：{}
//   委託解封：該服務商的秘密鍵 ＋ { topology_digest }
//   委託全新安裝：初始管理員兩鍵 ＋ 拓撲欄位 ＋ 該服務商的秘密鍵
// grant 以 `Authorization: SealGrant <grant>` 標頭帶出。**所有模式、所有分支皆必要**，
// 全新安裝亦同（初始管理員由段 1 的種子建立，第一步即可換脈絡）；全新安裝的請求本文
// 仍帶 username／password，那一份在臨界區之內驗證，與脈絡的時點與用途不同。
// **憑證類失敗的細分只在帶有效 grant 時才可能出現**；無 grant 時後端一律收斂為
// 材料無效，呼叫端 SHALL NOT 自行推測成因。
export function unseal(payload, options = {}) {
  const { grant, headers, ...config } = options
  return request({
    url: '/seal/unseal',
    method: 'post',
    data: payload,
    ...config,
    headers: grant ? { ...headers, Authorization: `SealGrant ${grant}` } : headers,
  })
}

// Seal the current generation; completion can include connection and worker cleanup.
export function seal(config = {}) {
  return request({ url: '/seal/seal', method: 'post', data: {}, ...config })
}
