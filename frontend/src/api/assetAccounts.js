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
 * @param {number|string} assetId - 資產 ID
 * @param {Object} data - { username, password, private_key, is_default,
 *   privileged, note, copy_from_account_id }
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
