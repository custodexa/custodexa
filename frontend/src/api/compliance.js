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
