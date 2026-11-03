import request from './request'

/**
 * 堡壘機專用帳號 API。
 *
 * 四個函式都收第二個參數 config，與預設 { skipErrorToast: true } 合併後交給 request。
 * 呼叫端不得把 skipErrorToast 覆寫成 false：這一區的錯誤都就地顯示在剛按的按鈕或欄位旁，
 * 全域錯誤提示會在頁頂多跳一則。
 */
function merge(config) {
  return { ...(config || {}), skipErrorToast: true }
}

/**
 * 讀取專用帳號。範圍外與不存在同形（404）。
 * @param {number|string} assetId
 * @param {Object} [config]
 * @returns {Promise} { configured, account_id?, username?, secret_type?, source?, credential?, has_public_key?, fingerprint? }
 */
export function getAssetExecutor(assetId, config) {
  return request({ url: `/assets/${assetId}/executor`, method: 'get', ...merge(config) })
}

/**
 * 設定或更換專用帳號。expected_account_id 必帶：0＝送出者認為目前沒有專用帳號，
 * 其餘為要換掉的那一筆的 account_id（與當下不符回 409）。四種來源的請求形狀：
 *   { source: 'generate', username, expected_account_id }
 *   { source: 'inline', username, password | private_key, expected_account_id }
 *   { source: 'shared', credential_id, acknowledged_host_count, expected_account_id }
 *   { source: 'convert', account_id, expected_account_id }
 * @param {number|string} assetId
 * @param {Object} data
 * @param {Object} [config]
 */
export function putAssetExecutor(assetId, data, config) {
  return request({ url: `/assets/${assetId}/executor`, method: 'put', data, ...merge(config) })
}

/**
 * 清除專用帳號。expectedAccountId 為畫面載入時的 account_id（缺漏＝不比對）。
 * @param {number|string} assetId
 * @param {number} [expectedAccountId]
 * @param {Object} [config]
 */
export function deleteAssetExecutor(assetId, expectedAccountId, config) {
  const params = expectedAccountId === undefined ? {} : { params: { expected_account_id: expectedAccountId } }
  return request({ url: `/assets/${assetId}/executor`, method: 'delete', ...params, ...merge(config) })
}

/**
 * 匯出公鑰（純文字，authorized_keys 單行）。每次取得都留審計，呼叫端不得快取。
 * @param {number|string} assetId
 * @param {Object} [config]
 * @returns {Promise<string>}
 */
export function exportAssetExecutorPublicKey(assetId, config) {
  return request({
    url: `/assets/${assetId}/executor/public-key`,
    method: 'get',
    responseType: 'text',
    ...merge(config),
  })
}

/**
 * 讀取最近一次測試登入的狀態。沒有專用帳號或範圍外為 404。
 * @param {number|string} assetId
 * @param {Object} [config]
 * @returns {Promise} { tested, stale, success, code, method, inventory_read, account_username?, checked_at? }
 */
export function getExecutorLoginCheck(assetId, config) {
  return request({ url: `/assets/${assetId}/executor/login-check`, method: 'get', ...merge(config) })
}

/**
 * 發起一次測試登入，同步等結果（最長約一分鐘）。登入失敗也是 200，結果在 code；
 * 只有被擋（409、422、429）與內部錯誤才是 HTTP 錯誤。
 * @param {number|string} assetId
 * @param {Object} [config]
 * @returns {Promise} { success, code, method, inventory_read, account_username, checked_at, stale }
 */
export function runExecutorLoginCheck(assetId, config) {
  return request({ url: `/assets/${assetId}/executor/login-check`, method: 'post', ...merge(config) })
}
