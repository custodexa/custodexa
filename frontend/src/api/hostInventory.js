import request from './request'

// 主機帳號盤點 API（路徑與形狀見 docs/API_SPEC.md「主機帳號盤點 API」）。
// 錯誤由畫面就地呈現，一律 skipErrorToast；呼叫端自行決定要不要 toast。

/** 發起一次盤點，202 回盤點紀錄 */
export function startInventoryScan(assetId) {
  return request({
    url: `/assets/${assetId}/account-inventory/scans`,
    method: 'post',
    skipErrorToast: true,
  })
}

/**
 * 讀取單台最近一次盤點與結果。
 * @param {number|string} assetId
 * @param {{privileged?: boolean, managed?: boolean, present?: boolean, status?: string, page?: number, page_size?: number}} params
 * @returns {Promise<{scan: object|null, coverage: object[], fixed_notes: string[], findings: object[], total: number, page: number, page_size: number}>}
 */
export function getAssetInventory(assetId, params = {}) {
  return request({
    url: `/assets/${assetId}/account-inventory`,
    method: 'get',
    params,
    skipErrorToast: true,
  })
}

/** 忽略一筆結果（理由去除首尾空白後 1 至 500 字元） */
export function ignoreInventoryFinding(assetId, findingId, reason) {
  return request({
    url: `/assets/${assetId}/account-inventory/findings/${findingId}/ignore`,
    method: 'post',
    data: { reason },
    skipErrorToast: true,
  })
}

/** 重新開啟已忽略的結果 */
export function reopenInventoryFinding(assetId, findingId) {
  return request({
    url: `/assets/${assetId}/account-inventory/findings/${findingId}/reopen`,
    method: 'post',
    skipErrorToast: true,
  })
}

/** 全域清單：開啟中、特權、仍在主機上、未納管（依呼叫者的資產檢視範圍過濾） */
export function listGlobalInventoryFindings(params = {}) {
  return request({
    url: '/account-inventory/findings',
    method: 'get',
    params,
    skipErrorToast: true,
  })
}
