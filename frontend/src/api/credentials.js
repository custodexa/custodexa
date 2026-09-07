import request from './request'

/**
 * 帳號憑證庫。
 *
 * 全部端點需 admin ＋ credential:manage；密文永不出站，回應只帶
 * has_password／has_private_key 兩個布林。
 *
 * 兩件事在呼叫端必須分清楚：
 *   - 卸載（unbindCredential）只移除掛載列，**不動主機上的密碼**；
 *   - 脫離（detachCredentialBinding）會登入該台改密，驗證通過才脫離。
 *
 * 改密是非同步的（回 202），進度由 getCredentialRotation 輪詢；
 * 單台補跑與單台脫離是同步的，可能耗時數十秒。
 */

/**
 * 憑證列表。
 *
 * `page`／`page_size` 為選用：不帶即回全部。`search` 同時比對共用名稱、帳號名
 * 與專用憑證的顯示名（資產名）。
 * @param {Object} [params] - { scope: 'dedicated'|'shared', secret_type,
 *   rotation_state, username, search, page, page_size }
 * @returns {Promise} { data: CredentialDTO[], total }
 */
export function listCredentials(params) {
  return request({ url: '/credentials', method: 'get', params })
}

/**
 * 憑證詳情（含掛載清單與逐台就位版本）。
 * @param {number|string} id - 憑證 ID
 * @returns {Promise} { data: CredentialDetailDTO, aggregate_state?: string }
 */
export function getCredential(id) {
  return request({ url: `/credentials/${id}`, method: 'get' })
}

/**
 * 建立共用憑證。
 * @param {Object} data - { name, username, secret_type, auth_method,
 *   protocol_family, note, password, private_key }
 * @returns {Promise} CredentialDTO
 */
export function createCredential(data) {
  return request({ url: '/credentials', method: 'post', data })
}

/**
 * 更新憑證（三欄皆為「省略＝不動」語義；共用憑證的帳號名不可改）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { name?, note?, username? }
 * @returns {Promise} CredentialDTO
 */
export function updateCredential(id, data) {
  return request({ url: `/credentials/${id}`, method: 'put', data })
}

/**
 * 刪除憑證。仍有掛載時回 409 RULE_CREDENTIAL_IN_USE，body 另帶 assets 名單。
 * @param {number|string} id - 憑證 ID
 * @returns {Promise}
 */
export function deleteCredential(id) {
  return request({ url: `/credentials/${id}`, method: 'delete' })
}

/**
 * 掛到資產（**對目標主機零寫入**）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { asset_id, is_default, privileged, note }
 * @returns {Promise} AssetAccountDTO
 */
export function bindCredential(id, data) {
  return request({ url: `/credentials/${id}/bindings`, method: 'post', data })
}

/**
 * 卸載（只移除掛載列，主機上的密碼不動）。
 * @param {number|string} id - 憑證 ID
 * @param {number|string} accountId - 掛載列（資產帳號）ID
 * @returns {Promise}
 */
export function unbindCredential(id, accountId) {
  return request({ url: `/credentials/${id}/bindings/${accountId}`, method: 'delete' })
}

/**
 * 單台脫離共用＋改密（同步；失敗回 409 並帶 state／reason 機器碼）。
 *
 * 編輯資產與憑證庫掛載列都打這一支——單台脫離只有這一個端點。
 * @param {number|string} id - 憑證 ID
 * @param {number|string} accountId - 掛載列（資產帳號）ID
 * @param {Object} data - { source: 'random'|'custom', policy?, password?, private_key? }
 * @returns {Promise} { data: RotationDTO }
 */
export function detachCredentialBinding(id, accountId, data) {
  return request({
    url: `/credentials/${id}/bindings/${accountId}/detach`,
    method: 'post',
    data,
  })
}

/**
 * 範圍轉換（轉共用時 name 必填）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { scope: 'dedicated'|'shared', name }
 * @returns {Promise} CredentialDTO
 */
export function convertCredentialScope(id, data) {
  return request({ url: `/credentials/${id}/scope`, method: 'post', data })
}

/**
 * 直接寫入新密文（建新版本並立即生效，**不觸碰遠端**；供補登既有密碼）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { password, private_key }
 * @returns {Promise} CredentialDTO
 */
export function setCredentialSecret(id, data) {
  return request({ url: `/credentials/${id}/secret`, method: 'post', data })
}

/**
 * 發起改密（非同步，回 202）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { mode: 'group'|'split', policy: { length,
 *   include_symbol, exclude_ambiguous } }
 * @returns {Promise} { data: RotationDTO }
 */
export function startCredentialRotation(id, data) {
  return request({ url: `/credentials/${id}/rotations`, method: 'post', data })
}

/**
 * 改密進度（聚合態＋成員逐列）。
 * @param {number|string} id - 憑證 ID
 * @param {number|string} rotationId - 輪替 ID
 * @returns {Promise} { data: RotationDTO }
 */
export function getCredentialRotation(id, rotationId) {
  return request({ url: `/credentials/${id}/rotations/${rotationId}`, method: 'get' })
}

/**
 * 逐台補跑（同步，可能耗時數十秒）。
 * @param {number|string} id - 憑證 ID
 * @param {number|string} rotationId - 輪替 ID
 * @param {number|string} memberId - 成員 ID
 * @returns {Promise} { data: RotationDTO }
 */
export function retryCredentialRotationMember(id, rotationId, memberId) {
  return request({
    url: `/credentials/${id}/rotations/${rotationId}/members/${memberId}/retry`,
    method: 'post',
  })
}

/**
 * 放棄本輪（已就位的主機不會被改回舊密碼）。
 * @param {number|string} id - 憑證 ID
 * @param {number|string} rotationId - 輪替 ID
 * @returns {Promise} { data: RotationDTO }
 */
export function abandonCredentialRotation(id, rotationId) {
  return request({
    url: `/credentials/${id}/rotations/${rotationId}/abandon`,
    method: 'post',
  })
}

/**
 * 更換此掛載使用的憑證（主體是資產，故掛在資產帳號路徑下）。
 *
 * **只能改到共用憑證**，且原本的專用憑證會在同一交易內被回收——這個動作沒有
 * 「復原」可言，介面不得提供改回專用的入口（要回專用走單台脫離：那會改遠端）。
 * @param {number|string} assetId - 資產 ID
 * @param {number|string} accountId - 掛載列（資產帳號）ID
 * @param {number|string} credentialId - 新憑證 ID
 * @returns {Promise} AssetAccountDTO
 */
export function rebindAccountCredential(assetId, accountId, credentialId) {
  return request({
    url: `/assets/${assetId}/accounts/${accountId}/credential`,
    method: 'put',
    data: { credential_id: credentialId },
  })
}
