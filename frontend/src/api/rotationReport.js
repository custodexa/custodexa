import request from './request'

// 輪替證據報告。
//
// 資料集端點一次算完整個範圍（上限 20,000 列）並回摘要與帳號列，
// **記錄明細不在其中**（恆為 null），要另打 records 端點分頁取得。
// 因此畫面的狀態桶篩選一律在已取得的資料上做，不逐次重打——
// 摘要與表格出自同一次建構才會是同一組數字。

/**
 * 報告資料集（GET /rotation-report，audit:view）。
 *
 * @param {Object} params - {
 *   scope_kind?: 'all'|'node'|'plan'（缺省 all）,
 *   scope_id?: number（all 時須為 0）,
 *   as_of?: RFC3339（缺省＝現在）,
 *   language?: 'zh-TW'|'en-US'|'ja-JP'
 * }
 * @returns {Promise<{data:{meta:Object, summary:Object, rows:Array, truncation:Object}}>}
 */
export function getRotationReport(params) {
  return request({ url: '/rotation-report', method: 'get', params })
}

/**
 * 區間記錄明細（GET /rotation-report/records，audit:view）。
 *
 * period_start／period_end 為必填：記錄明細必須說得出自己涵蓋哪一段。
 *
 * @param {Object} params - { scope_kind?, scope_id?, period_start, period_end, page?, page_size? }
 * @returns {Promise<{data:Array, total:number, page:number, page_size:number, truncated:boolean}>}
 */
export function getRotationReportRecords(params) {
  return request({ url: '/rotation-report/records', method: 'get', params })
}

/**
 * 手動產出報告（POST /rotation-report/jobs，audit:view）。
 *
 * 回應是工作單而非檔案——產出是非同步的，取件在下載中心的報告分頁。
 *
 * @param {Object} data - { scope_kind, scope_id, period_start, period_end, language }
 * @returns {Promise<{data:{id:number, status:string}}>} 202 Accepted
 */
export function createRotationReportJob(data) {
  return request({ url: '/rotation-report/jobs', method: 'post', data })
}

/** 排程列表（GET /rotation-report/schedules，admin） */
export function listRotationReportSchedules() {
  return request({ url: '/rotation-report/schedules', method: 'get' })
}

/**
 * 建立排程（POST /rotation-report/schedules，admin）。
 *
 * period_anchor 唯讀（送上來也不採用）：它由後端在建立、成功建單與 cron 變更時
 * 各自推進，前端只呈現不寫入。
 *
 * @param {Object} data - { name, cron, enabled, scope_kind, scope_id, retention_days, language }
 */
export function createRotationReportSchedule(data) {
  return request({ url: '/rotation-report/schedules', method: 'post', data })
}

/** 修改排程（PUT /rotation-report/schedules/:id，admin） */
export function updateRotationReportSchedule(id, data) {
  return request({ url: `/rotation-report/schedules/${id}`, method: 'put', data })
}

/** 刪除排程（DELETE /rotation-report/schedules/:id，admin） */
export function deleteRotationReportSchedule(id) {
  return request({ url: `/rotation-report/schedules/${id}`, method: 'delete' })
}

/**
 * 依排程規則立即產出一份（POST /rotation-report/schedules/:id/run，admin）。
 *
 * 這會**推進區間錨點**——它產的是提前的一期，不是額外的一份副本。
 * 同一排程已有進行中的工作單時回 409。
 */
export function runRotationReportSchedule(id) {
  return request({ url: `/rotation-report/schedules/${id}/run`, method: 'post' })
}
