import request from './request'

// 政策組的讀寫端。**寫入只有這一組端點**——判定結果那一頁是唯讀的，
// 條文改在這裡、設定值改在安全政策頁，兩者各自留下自己的記錄。
//
// 條號含括號與中文（如 `4-7(五)`），一律 encodeURIComponent 後才進路徑：
// 不編碼時 `/` 之外的字元多半僥倖可用，但條號的字元集由規範決定而不由我們決定，
// 哪天出現一個帶斜線的條號就會靜默打到別的路由。
const clausePath = (code, clauseNo) =>
  `/policy-groups/${encodeURIComponent(code)}/clauses/${encodeURIComponent(clauseNo)}`

/**
 * 政策組清單（admin 與 auditor）。
 * @returns {Promise} { data: PolicyGroup[] }
 */
export function getPolicyGroups() {
  return request({
    url: '/policy-groups',
    method: 'get',
  })
}

/**
 * 單一政策組與其條文（admin 與 auditor）。
 * @param {string} code 組代號
 * @returns {Promise} { data: { group, clauses } }
 */
export function getPolicyGroup(code) {
  return request({
    url: `/policy-groups/${encodeURIComponent(code)}`,
    method: 'get',
  })
}

/**
 * 建立自建政策組。
 * @param {Object} payload { code, name, locale }
 * @param {Object} [options] { skipErrorToast } 對話框自行就近顯示拒因時關掉全域 toast
 */
export function createPolicyGroup(payload, options = {}) {
  return request({
    url: '/policy-groups',
    method: 'post',
    data: payload,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 自建政策組改名。
 * @param {Object} [options] { skipErrorToast }
 */
export function renamePolicyGroup(code, name, options = {}) {
  return request({
    url: `/policy-groups/${encodeURIComponent(code)}`,
    method: 'put',
    data: { name },
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 切換生效開關（內建組亦可切——生效與否由機構決定）。
 */
export function setPolicyGroupEnabled(code, enabled) {
  return request({
    url: `/policy-groups/${encodeURIComponent(code)}/enabled`,
    method: 'put',
    data: { enabled },
  })
}

/**
 * 刪除自建政策組（連帶清除其條文、要求與備註）。
 */
export function deletePolicyGroup(code) {
  return request({
    url: `/policy-groups/${encodeURIComponent(code)}`,
    method: 'delete',
  })
}

/**
 * 新增或改寫一條條文。
 * @param {Object} payload { title, summary, kind, controls }
 *   controls 為**整批取代**：送進去的就是這條條文的全部要求
 */
export function upsertPolicyClause(code, clauseNo, payload, options = {}) {
  return request({
    url: clausePath(code, clauseNo),
    method: 'put',
    data: payload,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 刪除一條條文（掛在它上面的備註與確認記錄不刪）。
 */
export function deletePolicyClause(code, clauseNo) {
  return request({
    url: clausePath(code, clauseNo),
    method: 'delete',
  })
}

/**
 * 寫入機構備註（備註不影響判定）。
 */
export function upsertClauseAnnotation(code, clauseNo, note) {
  return request({
    url: `${clausePath(code, clauseNo)}/annotation`,
    method: 'put',
    data: { note },
  })
}

/**
 * 人工確認一條待確認的條文；再次確認覆蓋前次，歷史留在操作日誌。
 */
export function confirmClause(code, clauseNo, note) {
  return request({
    url: `${clausePath(code, clauseNo)}/confirm`,
    method: 'post',
    data: { note },
  })
}

/**
 * 單一設定鍵的定義與現值：型別、可用的比較方式、值域、目前值。
 * 條文表單選鍵之後才問——55 個鍵的完整定義沒有一次全取的必要。
 * @param {string} key 設定鍵
 */
export function getPolicyKeyDef(key) {
  return request({
    url: `/security-policies/defs/${encodeURIComponent(key)}`,
    method: 'get',
  })
}
