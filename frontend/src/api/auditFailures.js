import request from './request'

/**
 * 審計機制失效事件列表（PCI 10.7.3；分頁）
 * @param {Object} params - { page, page_size }
 * @returns {Promise} { data: { items: [{ mechanism, started_at, ended_at, cause,
 *   details }], total } }；ended_at 為 null 表示失效進行中
 */
export function getAuditFailures(params) {
  return request({
    url: '/audit-failures',
    method: 'get',
    params,
  })
}

/**
 * 超管確認權限狀態「無來源變動」並接受風險：以目前狀態為新基準，審計留痕。
 * @param {Object} data - { reason }（1 至 500 字）
 * @returns {Promise} { data: { op_id, event_seq, missing_count, extra_count } }
 */
export function acceptPermissionState(data) {
  return request({
    url: '/audit-failures/permission-state/accept',
    method: 'post',
    data,
  })
}
