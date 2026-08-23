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
