import request from './request'

/**
 * 稽核調查工作台的兩支唯讀端點（auditor-workbench）。
 * 本模組**只有 GET**：工作台零寫入是規格要求，不得在此新增任何寫方法。
 */

/**
 * 取得六類稽核紀錄的合併時間軸
 * 事件與會話跨度各帶 `client_ip`：有位址時為正規化字串，**無位址時是顯式 `null`**
 * （不是缺欄、也不是空字串），另帶 `client_ip_reason`（`system`／`unresolvable`／
 * `session_missing`）。介面據此把「未知來源」與「有位址」分開呈現。
 * @param {Object} params
 * @param {string} params.subject - user | asset | ip（必填）
 * @param {number} [params.subject_id] - 主體 ID（user／asset 樞紐必填；對 ip 樞紐被忽略）
 * @param {string} [params.subject_ip] - 來源位址（ip 樞紐必填）；無法解析為位址時回 400
 * @param {string} [params.client_ip] - 來源位址篩選（僅人／資產樞紐）；保留字 `unknown`
 *   表示只保留未知來源的列。**位址樞紐下再帶本參數後端回 400**
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
 * **ip 型是另一種形狀**（`{ip, last_seen_at}`，無 id／active／deleted）：候選取自帳號
 * 已見位址基準，只含成功登入或建線過的位址。候選是便利不是範圍限制——只出現在
 * 拒絕紀錄裡的位址查不到候選，但仍可直接輸入為樞紐。
 * @param {Object} params
 * @param {string} params.type - user | asset | ip
 * @param {string} [params.q] - 關鍵字（ip 型為位址前綴）
 * @param {number} [params.limit]
 * @returns {Promise<{data:Array<{id:number,name:string,display_name:string,
 *                    active:boolean,deleted:boolean}|{ip:string,last_seen_at:string}>,
 *                    total:number}>}
 */
export function getAuditSubjects(params) {
  return request({
    url: '/audit/subjects',
    method: 'get',
    params,
  })
}
