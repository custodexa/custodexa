import request from './request'

/**
 * 稽核證據匯出打包（audit-workflows，audit:view）。
 * 回傳 ZIP blob——用 responseType blob 讓瀏覽器可另存；篩選隨目前查詢範圍。
 *
 * 兩種包（同一端點、同一包結構），由 `pack` 明示；缺席時沿舊推斷
 *（帶 subject 或 types＝事件報告，否則證據包）：
 *   - `pack=evidence_bundle`：證據包（操作日誌＋指令流＋剪貼簿明文＋錄影檔本體）。
 *   - `pack=event_report`：**事件報告**——六來源的事件事實，不含剪貼簿內容、
 *     檔案本體與錄影檔；內容本體改由介面上的個別下載取得。
 *     此模式下 subject 與 start_time／end_time 為必填（報告得說得出自己涵蓋哪一段），
 *     樞紐 id 沿用 user_id／asset_id。
 *
 * @param {Object} params - {
 *   user_id?, asset_id?, session_id?, start_time?, end_time?,
 *   pack?: 'event_report'|'evidence_bundle',
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

// —— 證據包的非同步交付 ——
//
// 證據包（含錄影檔本體與剪貼簿明文）體積不可控，改走 job：發起→背景打包→
// 限時下載。事件報告（帶 subject 的模式）維持上方 exportAuditEvidence 的同步直下。
//
// **參數形態的硬事實**（後端 `parseExportFilter`／`parseExportPack`／
// `parseExportBundleScope`，2026-08-25 起）：job 只受理證據包，而包型的判別
// **以 `pack` 為準**。`pack` 缺席時沿舊推斷（帶 subject 或 types＝事件報告），
// 故只帶 subject／types 而不帶 `pack` 會被判成報告並以 CodeExportJobBundleOnly
// 拒絕——發起證據包時 `pack=evidence_bundle` 是必填，不是裝飾。
// 帶了 `pack` 之後，證據包**也套用類別篩選**（未勾選的類別整段不入包），
// 樞紐與時間窗選填；但選了 alert／file_transfer 就必須同時給樞紐與正向時間窗
//（那兩類走事件事實寫入器，缺樞紐即無從取數），否則 400。

/**
 * 發起證據包打包（POST /audit-export/jobs，audit:view）。
 *
 * @param {Object} params - { pack: 'evidence_bundle'（必填）,
 *   user_id?|asset_id?|session_id?, subject?, types?, start_time?, end_time? }
 *   （範圍條件至少一項）
 * @returns {Promise<{data:Object, deduplicated:boolean}>} 202 Accepted；
 *   deduplicated=true 代表同範圍已有 pending/running 的 job，回的是既有那一份
 */
export function createAuditExportJob(params) {
  return request({
    url: '/audit-export/jobs',
    method: 'post',
    params,
  })
}

/**
 * 匯出 job 清單（GET /audit-export/jobs）。
 *
 * `kind` **缺省為 `evidence_bundle`**：證據包的清單範圍與下載授權同判準
 * ——只列本人，後端沒有跨帳號的檢視面，前端也不該演一個「全部使用者」的篩選出來。
 *
 * `kind=rotation_report` 是顯式例外且**只適用於該種類**：輪替證據報告不含錄影、
 * 剪貼簿內容或任何秘密材料，故對所有具稽核檢視權限者是同一份清單，不綁申請者。
 * 種類閉集外的值由後端回 400。
 *
 * @param {Object} params - { kind?: 'evidence_bundle'|'rotation_report', page?, page_size? }
 * @returns {Promise<{data:Array, total:number, page:number, page_size:number}>}
 */
export function listAuditExportJobs(params) {
  return request({
    url: '/audit-export/jobs',
    method: 'get',
    params,
  })
}

/**
 * 下載產物（GET /audit-export/jobs/:id/download）。
 *
 * 走 axios 而非開新分頁：授權綁申請者本人且需 Authorization 標頭，
 * 下載位址本身不含任何憑證（連結貼給別人不會生效，也不該生效）。
 *
 * @param {number|string} jobId
 * @returns {Promise<Blob>}
 */
export function downloadAuditExportJob(jobId) {
  return request({
    url: `/audit-export/jobs/${jobId}/download`,
    method: 'get',
    responseType: 'blob',
    // 產物含錄影檔本體，放寬逾時（與同步匯出同一口徑）
    timeout: 120000,
  })
}
