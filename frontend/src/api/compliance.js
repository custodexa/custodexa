import request from './request'

/**
 * 合規判定結果（唯讀）。
 *
 * 一次呼叫回齊四塊：判定本體（data）、政策組、逐組摘要、條文卡片。
 * **不拆成四支端點**：判定有建構時點，分四次讀等於四個時點，
 * 摘要與逐條結果會在管理者剛好改值的那一瞬間對不起來。
 *
 * @param {Object} [params]
 * @param {string} [params.group] 政策組代號；省略＝全部組
 * @returns {Promise} { data, groups, summaries, clauses }
 */
export function getComplianceSnapshot(params) {
  return request({
    url: '/compliance/snapshot',
    method: 'get',
    params,
  })
}

/**
 * 發起合規報告產出（POST /compliance/report-jobs，admin 與 auditor）。
 *
 * 非同步：受理即回 202，產物由背景產出後掛在下載中心的報告清單
 *（`listAuditExportJobs({ kind: 'compliance_report' })`），下載走共用的
 * job 下載端點。報告內容是產出當下的設定狀態，沒有區間參數。
 *
 * @param {Object} payload
 * @param {string} payload.group 政策組代號（必填，須為生效中的組）
 * @param {'zh-TW'|'en-US'|'ja-JP'} payload.language 報告語言
 * @param {number} payload.retention_days 產物在下載中心的保留天數（1–3650）
 * @returns {Promise<{data:{id:number, status:string}}>}
 */
export function createReportJob({ group, language, retention_days }) {
  return request({
    url: '/compliance/report-jobs',
    method: 'post',
    data: { group, language, retention_days },
  })
}
