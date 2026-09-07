import request from './request'

/**
 * 列出資產帳號。
 *
 * 後端已依請求者的**有效授權帳號範圍**過濾（admin/auditor 全量），
 * 前端不得再自行推斷可見性——連線選擇器直接用此清單即為有效帳號集合。
 * 回應：{ data: AssetAccount[], total: number }，預設帳號排首。
 * @param {number|string} assetId - 資產 ID
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise}
 */
export function listAssetAccounts(assetId, options = {}) {
  return request({
    url: `/assets/${assetId}/accounts`,
    method: 'get',
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 建立資產帳號。
 *
 * 登入憑證的來源二擇一：`credential_id`（掛既有共用憑證）或這台專用的
 * `username`／`password`／`private_key`。兩者同時給會被伺服端判為意圖不明而整筆拒絕。
 * @param {number|string} assetId - 資產 ID
 * @param {Object} data - { credential_id } 或
 *   { username, password, private_key, auth_method }，另可帶 is_default、privileged、note
 * @returns {Promise} AssetAccount
 */
export function createAssetAccount(assetId, data) {
  return request({
    url: `/assets/${assetId}/accounts`,
    method: 'post',
    data,
  })
}

/**
 * 更新資產帳號（憑證空字串＝沿用既有，比照資產更新語義）。
 *
 * 掛在共用憑證上的帳號帶密碼／私鑰會被拒絕：那組秘密同時掛在別台上，
 * 要改就整組改（憑證庫）或先讓這台脫離共用。回應的部分欄位不完整，存檔後重新取回再渲染。
 * @param {number|string} assetId - 資產 ID
 * @param {number|string} accountId - 帳號 ID
 * @param {Object} data - { username, password, private_key, privileged, note }
 * @returns {Promise} AssetAccount
 */
export function updateAssetAccount(assetId, accountId, data) {
  return request({
    url: `/assets/${assetId}/accounts/${accountId}`,
    method: 'put',
    data,
  })
}

/**
 * 刪除資產帳號（禁刪最後一個預設帳號，後端回 RULE_ACCOUNT_DEFAULT_REQUIRED）。
 * @param {number|string} assetId - 資產 ID
 * @param {number|string} accountId - 帳號 ID
 * @returns {Promise}
 */
export function deleteAssetAccount(assetId, accountId) {
  return request({
    url: `/assets/${assetId}/accounts/${accountId}`,
    method: 'delete',
  })
}

/**
 * 設為預設帳號（交易式切換，每資產至多一個預設）。
 * @param {number|string} assetId - 資產 ID
 * @param {number|string} accountId - 帳號 ID
 * @returns {Promise} AssetAccount
 */
export function setDefaultAssetAccount(assetId, accountId) {
  return request({
    url: `/assets/${assetId}/accounts/${accountId}/set-default`,
    method: 'post',
  })
}
