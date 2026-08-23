import request from './request'

/**
 * 稽核證據匯出打包（audit-workflows，audit:view）。
 * 回傳 ZIP blob——用 responseType blob 讓瀏覽器可另存；篩選隨目前查詢範圍。
 *
 * 兩種包，由 subject 決定（同一端點、同一包結構）：
 *   - 不帶 subject：既有證據包（操作日誌＋指令流＋錄影檔本體）。
 *   - 帶 subject：**事件報告**——六來源的事件事實，不含剪貼簿內容、
 *     檔案本體與錄影檔；內容本體改由介面上的個別下載取得。
 *     此模式下 start_time／end_time 為必填（報告得說得出自己涵蓋哪一段），
 *     樞紐 id 沿用 user_id／asset_id。
 *
 * @param {Object} params - {
 *   user_id?, asset_id?, session_id?, start_time?, end_time?,
 *   subject?: 'user'|'asset',
 *   types?: 'session,command,audit_log,file_transfer,clipboard,alert' 的子集（csv，空＝六類全收）
 * }（至少一項）
 * @returns {Promise<Blob>}
 */
export function exportAuditEvidence(params) {
  return request({
    url: '/audit-export',
    method: 'get',
    params,
    responseType: 'blob',
    // 匯出可能較大（含錄影），放寬逾時
    timeout: 120000,
  })
}

/**
 * 匯出簽章的驗證金鑰（Ed25519，base64）。
 *
 * 介面用它回答一個下載**之前**就該講清楚的問題：這份包會不會附簽章檔。
 * 取得到金鑰＝本系統已啟用簽章；端點不存在（404）＝未啟用。其餘錯誤
 * （斷線、逾時）**不可**推論成「未啟用」——分不出來時就說分不出來。
 *
 * @returns {Promise<{data:{algorithm:string, public_key:string}}>}
 */
export function getExportSigningPublicKey() {
  // skipErrorToast：這是介面自己去問的一個問題，使用者沒按任何東西；
  // 失敗時由對話框內的「無法確認簽章狀態」承接，不該再彈一則全域錯誤
  return request({
    url: '/audit-export/public-key',
    method: 'get',
    skipErrorToast: true,
  })
}
