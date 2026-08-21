import request from './request'

/**
 * LDAP 目錄設定（ldap-settings-migration 3.1／4.x）的 API 客戶端。
 *
 * **singleton 資源**：無集合端點、無資源 id——`/ldap-directory` 一條路徑同時是
 * 讀、upsert 與軟刪的對象。全部 admin only（後端 RequireRole 才是強制點）。
 *
 * bind 密碼為 write-only：讀取回應永不含密碼，僅以 `has_bind_password` 表達有無。
 */

/**
 * 讀取現行設定。**未設定時回 `{ configured: false }` 而非 404**——
 * 「還沒設定」是 singleton 資源的正常狀態，呼叫端不可把它當錯誤處理。
 * @returns {Promise} { configured, name, url, bind_dn, has_bind_password, base_dn,
 *   user_filter, attr_email, attr_fullname, skip_tls_verify, enabled }
 */
export function getLDAPDirectory() {
  return request({
    url: '/ldap-directory',
    method: 'get',
  })
}

/**
 * upsert 設定（PUT：無列即建、有列即改）。
 *
 * 密碼三規則（後端為權威，前端只提前提示）：空值＝沿用既存；
 * `clear_bind_password: true`＝顯式清除；兩者同時給＝400。
 * URL 的 canonical origin 改變且既存有密碼時，必須同時給新密碼或顯式清除。
 *
 * 存檔閘沿三通道共用契約：warn 檔缺 `risk_acknowledged` 回 400＋
 * `VALIDATION_TRANSMISSION_ACK_REQUIRED`（確認後重送即可）、strict 檔位直接拒存
 * （`VALIDATION_TRANSMISSION_STRICT_REJECT`，重送無用）。
 * @param {Object} data - 見 API_SPEC「LDAP 目錄設定」
 * @param {Object} [options] - { skipErrorToast } 由呼叫端自行呈現錯誤時開啟
 * @returns {Promise} 與 GET 同形狀的 view
 */
export function updateLDAPDirectory(data, options = {}) {
  return request({
    url: '/ldap-directory',
    method: 'put',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 軟刪設定（同一事務抹除密文）；無列時後端回 404
 * @returns {Promise}
 */
export function deleteLDAPDirectory() {
  return request({
    url: '/ldap-directory',
    method: 'delete',
  })
}

/**
 * 以**表單當下未儲存的值**執行分階段連線測試（先測後存）。
 *
 * 回傳語義是契約的一部分，呼叫端兩種失敗不可混為一談：
 *   - reject ＝ 測試**未執行**（驗證／傳輸閘 400、限流 429、既存密文不可讀 500）；
 *   - resolve ＝ 階梯已跑完（**含失敗**），失敗資訊在 `stages[]`／`failed_stage`／
 *     `code`／`diagnostic_id`，HTTP 恆為 200。
 *
 * **timeout 顯式放大到 20s**：實例預設 10s，而後端階梯（dial/bind/search 各 5s）
 * 最壞約 15s——沿用預設會讓「慢但成功」的目錄固定表現為前端逾時，且使用者看到的
 * 是網路錯誤而非階梯結果。此處不宣稱 15s 為硬上限（後端未以 context 封頂），
 * 20s 只是留出餘裕的客戶端界線。
 * @param {Object} data - 同 update 的 body（不含 name）
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} LDAPDirectoryTestResult
 */
export function testLDAPDirectory(data, options = {}) {
  return request({
    url: '/ldap-directory/test',
    method: 'post',
    data,
    timeout: 20000,
    skipErrorToast: options.skipErrorToast === true,
  })
}
