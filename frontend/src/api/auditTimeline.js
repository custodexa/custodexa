import request from './request'

/**
 * 稽核調查工作台的兩支唯讀端點（auditor-workbench D7）。
 * 本模組**只有 GET**：工作台零寫入是規格要求，不得在此新增任何寫方法。
 */

/**
 * 取得六類稽核紀錄的合併時間軸
 * @param {Object} params
 * @param {string} params.subject - user | asset（必填）
 * @param {number} params.subject_id - 主體 ID（必填）
 * @param {string} params.from - RFC3339 且**必須帶時區偏移**（只給日期後端回 400）
 * @param {string} params.to - 同上
 * @param {string} [params.types] - csv；省略＝全部類別
 * @param {string} [params.cursor] - 複合游標（後端產生，前端不自拼）
 * @param {number} [params.limit] - 預設 200，上限 500
 * @returns {Promise<{events:Array, spans:Array, coverage:Array, counts:Object,
 *                    next_cursor?:string, truncated:boolean}>}
 */
export function getAuditTimeline(params) {
  return request({
    url: '/audit/timeline',
    method: 'get',
    params,
  })
}

/**
 * 主體目錄（搜尋下拉用）。
 * 已停用（active=false）與已軟刪（deleted=true）的主體**仍會回**——
 * 調查對象常已離職或資產已下架，濾掉等於把證據藏起來，UI 須標記而非隱藏。
 * @param {Object} params
 * @param {string} params.type - user | asset
 * @param {string} [params.q] - 關鍵字
 * @param {number} [params.limit]
 * @returns {Promise<{data:Array<{id:number,name:string,display_name:string,
 *                    active:boolean,deleted:boolean}>, total:number}>}
 */
export function getAuditSubjects(params) {
  return request({
    url: '/audit/subjects',
    method: 'get',
    params,
  })
}
