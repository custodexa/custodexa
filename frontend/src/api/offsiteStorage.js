import request from './request'

/**
 * 離機儲存（evidence-offsite-storage）的 API 客戶端。全部 admin only
 * （後端 `RequireRole("admin")` 才是強制點）。
 *
 * # 憑證是 write-only
 *
 * 讀取端點（`getOffsiteSettings`／`listOffsiteProfiles`／`getOffsiteStatus`）
 * **永不回傳憑證，也不回傳遮罩值**——遮罩仍會洩漏長度與前綴。有無憑證只由
 * `credential_mode`（`stored`／`default_chain`／`revoked`）與 `has_credentials`
 * 表達。寫入端的三種意圖：填值＝新憑證；`clear_credentials: true`＝改走
 * SDK 預設鏈；兩者皆無＝沿用既存（僅在落點未變時成立，否則後端以
 * `RULE_OFFSITE_CREDENTIAL_REUSE_ON_MOVE` 拒絕）。
 *
 * # 兩種失敗語義不可混為一談（連線測試）
 *
 *   - reject ＝ 測試**未能執行**（欄位驗證 400、限流 429、既存密文不可解 500）；
 *   - resolve ＝ 階梯已跑完（**含失敗**），失敗資訊在 `stages[]`，HTTP 恆為 200。
 */

/**
 * 總覽：設定摘要（write-only 投影）＋憑證三態＋各態計數＋最老待上傳年齡
 * ＋bucket 治理現況揭露。
 *
 * **注意**：本端點會對現行世代發 `ProbeBucket` 遠端探測，屬「使用者按下重新整理
 * 才該付的成本」，不要掛在別頁的載入路徑上（要判斷是否已設定請用
 * `getOffsiteSettings`，那是單列讀取）。
 *
 * timeout 顯式放大到 30s（同 `testOffsiteConnection` 的理由）：該遠端探測的實測
 * 秒數會壓過實例預設，沿用預設會讓「慢但成功」的讀取表現為前端逾時；本端點又常
 * 掛在破壞性動作後的自動重讀上，逾時的紅字會被讀成那個動作失敗。
 * @returns {Promise} { configured, disabled, generation_id, profile_fingerprint,
 *   provider, endpoint_origin, bucket, prefix, region, path_style,
 *   credential_mode, has_credentials, credentials_cleared_at, created_at,
 *   activated_at, retired_at, object_count, credential_state, counts,
 *   total_objects, oldest_pending_age_seconds, governance? }
 */
export function getOffsiteStatus() {
  return request({
    url: '/offsite-storage/status',
    method: 'get',
    timeout: 30000,
  })
}

/**
 * 失敗清單（分頁；距保留到期近者在前）。
 *
 * **排序只在頁內成立**（後端註解明載）：`retention_deadline` 屬擁有者模組的事實，
 * 跨頁全域排序需把全部失敗列取出逐列點查。故「距到期天數」欄在每一頁都要看得見。
 * @param {Object} params - { page, size }
 * @returns {Promise} { data, total, page, page_size }
 */
export function getOffsiteFailures(params) {
  return request({
    url: '/offsite-storage/failures',
    method: 'get',
    params,
  })
}

/**
 * 以**表單當下未儲存的值**執行分階段連線測試（test-then-save）。
 *
 * timeout 顯式放大到 30s：後端階梯是探測＋寫＋讀＋刪四趟遠端往返，
 * 逐呼叫各有自己的 context 期限，沿用實例預設會讓「慢但成功」的 bucket
 * 固定表現為前端逾時，而使用者看到的是網路錯誤而非階梯結果。
 * 此處不宣稱 30s 是後端硬上限，只是留出餘裕的客戶端界線。
 * @param {Object} data - 同 saveOffsiteSettings 的 body
 * @param {Object} [options] - { skipErrorToast } 由呼叫端自行呈現錯誤時開啟
 * @returns {Promise} { passed, stages: [{ step, outcome, code, detail }] }
 */
export function testOffsiteConnection(data, options = {}) {
  return request({
    url: '/offsite-storage/test',
    method: 'post',
    data,
    timeout: 30000,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 批次重試全部 failed 件（把它們放回 pending，由 worker 依序取件）
 * @returns {Promise} { retried }
 */
export function retryOffsiteFailed() {
  return request({
    url: '/offsite-storage/retry-failed',
    method: 'post',
  })
}

/**
 * 單筆重試。查無此列與「非本功能可重試列」後端收斂同一 404
 * @param {number|string} objectId
 * @returns {Promise} { retried }
 */
export function retryOffsiteObject(objectId) {
  return request({
    url: `/offsite-storage/objects/${objectId}/retry`,
    method: 'post',
  })
}

/**
 * 讀取現行設定（write-only DTO）。
 *
 * **未設定時回 `configured: false` 而非 404**——「還沒設定」是本資源的正常狀態，
 * 呼叫端不可把它當錯誤處理。`configured: true` 且 `disabled: true`＝停用態
 * （有歷史世代、零現行世代），與「從未設定」分立。
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} 同 getOffsiteStatus 的設定投影（不含計數與治理欄）
 */
export function getOffsiteSettings(options = {}) {
  return request({
    url: '/offsite-storage/settings',
    method: 'get',
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 儲存設定。
 *
 * 新指紋 ≠ 現行且帳冊有存量物件時**不逕行儲存**，回
 * `{ needs_confirmation: true, object_count, expected_current_generation_id,
 * settings_digest }`——呼叫端須開確認框，並把後兩個值**原樣**帶進
 * `confirmOffsiteGenerationSwitch`。
 * @param {Object} data - { provider, endpoint, bucket, prefix, region, path_style,
 *   access_key_id?, secret_access_key?, service_account_json?, clear_credentials? }
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise}
 */
export function saveOffsiteSettings(data, options = {}) {
  return request({
    url: '/offsite-storage/settings',
    method: 'put',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 確認世代切換（鎖內 CAS ＋ digest 比對 ＋ 同一驗證核心重驗）。
 *
 * `expectedCurrentGenerationID` 與 `settingsDigest` **一律由「需確認」回應原樣攜回，
 * 前端不得自行計算或補值**：那兩個值綁的是「管理員按下確認時所見的狀態」，
 * 前端自算等於把 CAS 變成橡皮圖章。`0` 是合法的期望值（＝預期目前無現行世代），
 * 故不可用「falsy 就省略」的寫法。
 * @param {Object} data - 同 saveOffsiteSettings 的 body
 * @param {number} expectedCurrentGenerationID
 * @param {string} settingsDigest
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} 切換後的設定投影
 */
export function confirmOffsiteGenerationSwitch(
  data,
  expectedCurrentGenerationID,
  settingsDigest,
  options = {}
) {
  return request({
    url: '/offsite-storage/settings/confirm',
    method: 'post',
    data: {
      ...data,
      expected_current_generation_id: expectedCurrentGenerationID,
      settings_digest: settingsDigest,
    },
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 停止離機：退役現行世代而**不建新列**。
 * 憑證不隨停用撤銷（歷史取回要用），遠端物件不被刪除。
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} 停用後的設定投影（configured: true、disabled: true）
 */
export function disableOffsiteStorage(options = {}) {
  return request({
    url: '/offsite-storage/settings/disable',
    method: 'post',
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 歷史世代列表（新到舊，含物件數與憑證模式）
 * @returns {Promise} { data, total }
 */
export function listOffsiteProfiles() {
  return request({
    url: '/offsite-storage/profiles',
    method: 'get',
  })
}

/**
 * 撤銷某世代的憑證（不可逆）。撤銷後該世代的物件取回一律以
 * `CONFLICT_OFFSITE_FOREIGN_CREDENTIALS_MISSING` 失敗，
 * 且**不會回退到雲端預設憑證鏈**。查無世代收斂同一 404。
 * @param {number|string} generationId
 * @param {Object} [options] - { skipErrorToast }
 * @returns {Promise} 204 無內容
 */
export function revokeOffsiteProfileCredentials(generationId, options = {}) {
  return request({
    url: `/offsite-storage/profiles/${generationId}/revoke-credentials`,
    method: 'post',
    skipErrorToast: options.skipErrorToast === true,
  })
}
