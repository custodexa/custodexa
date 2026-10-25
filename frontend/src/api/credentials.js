import request from './request'
import { skipHostIdentityMovedToast } from './changeSecret'

/**
 * 帳號憑證庫。
 *
 * 讀取端點需憑證檢視能力；寫入端點在路由層只需任一憑證語義管理能力（補跑與放棄需遠端輪替能力），
 * 各動作所需的能力由伺服器逐項裁決。密文永不出站，回應只帶 has_password／has_private_key 兩個布林。
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
 * `ownership`（global｜asset｜node）與 `owner_node_id` 為歸屬篩選。範圍化檢視者的列另帶
 * `actions` 與 `out_of_scope_asset_count`，由伺服器標示，前端不自行計算。
 * @param {Object} [params] - { scope: 'dedicated'|'shared', secret_type,
 *   rotation_state, username, search, ownership, owner_node_id, page, page_size }
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
 *   protocol_family, note, password, private_key, ownership?: { kind, node_id? } }
 * @returns {Promise} CredentialDTO
 */
export function createCredential(data) {
  return request({ url: '/credentials', method: 'post', data })
}

/**
 * 更新憑證（三欄皆為「省略＝不動」語義；共用憑證的帳號名不可改）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { name?, note?, username?, ownership?: { kind, node_id? } }
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
 * @param {Object} data - { scope: 'dedicated'|'shared', name, ownership?: { kind, node_id? } }
 * @returns {Promise} CredentialDTO
 */
export function convertCredentialScope(id, data) {
  return request({ url: `/credentials/${id}/scope`, method: 'post', data })
}

/**
 * 直接寫入新密文（建新版本並立即生效，**不觸碰遠端**；供更正登記錯的秘密）。
 *
 * 全部掛載的就位版本在同一交易內一併指向新版本；未帶的那一欄自現行版本原樣帶過。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { password } 或 { private_key }；另可帶 impact_confirmation_id
 * @param {Object} [config] - 額外 axios 設定（例如 skipErrorToast）
 * @returns {Promise} CredentialDTO
 */
export function setCredentialSecret(id, data, config = {}) {
  return request({ url: `/credentials/${id}/secret`, method: 'post', data, ...config })
}

/**
 * 發起改密（非同步，回 202）。
 * @param {number|string} id - 憑證 ID
 * @param {Object} data - { mode: 'group'|'split', policy: { length,
 *   include_symbol, exclude_ambiguous }, impact_confirmation_id? }
 * @param {Object} [config] - 額外 axios 設定（例如 skipErrorToast）
 * @returns {Promise} { data: RotationDTO }
 */
export function startCredentialRotation(id, data, config = {}) {
  return request({ url: `/credentials/${id}/rotations`, method: 'post', data, ...config })
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
 * @param {Object} [data] - 選用 body：{ confirm_host_identity }；省略則不帶 body
 * @returns {Promise} { data: RotationDTO }
 */
export function retryCredentialRotationMember(id, rotationId, memberId, data) {
  return request({
    url: `/credentials/${id}/rotations/${rotationId}/members/${memberId}/retry`,
    method: 'post',
    ...(data === undefined ? {} : { data, skipErrorToast: skipHostIdentityMovedToast }),
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

/**
 * 取得共用憑證修改的範圍外影響確認。
 *
 * 更正登記值（set_secret）與改密（rotate）送出前呼叫。回應 `required: false` 時直接送出、
 * 請求不帶確認欄；`required: true` 時帶回不透明的 `confirmation_id`、範圍內台數
 * `in_scope_count` 與範圍外台數 `out_of_scope_asset_count`，使用者勾選知情後把
 * `confirmation_id` 以 `impact_confirmation_id` 帶進提交。回應不含任何範圍外資產識別。
 * @param {number|string} id - 憑證 ID
 * @param {'set_secret'|'rotate'} operation
 * @returns {Promise} { required, confirmation_id?, in_scope_count, out_of_scope_asset_count? }
 */
export function confirmCredentialImpact(id, operation) {
  return request({
    url: `/credentials/${id}/impact-confirmations`,
    method: 'post',
    data: { operation },
  })
}

/**
 * 批次改歸共用憑證的管理歸屬（整批原子；任一筆不可操作即整批拒絕）。
 * @param {Object} data - { credential_ids: number[], ownership: { kind: 'global'|'node', node_id? } }
 * @returns {Promise} { changed: number }
 */
export function reassignCredentialOwnership(data) {
  return request({ url: '/credentials/ownership', method: 'post', data })
}
