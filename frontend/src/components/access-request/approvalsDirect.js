// 審核中心被直達時的網址參數（通知連結 /approvals?tab=…&request=…）。
//
// 兩個參數各自判斷，不合格的單獨忽略、另一個合格的照用；同名參數出現多次時取第一個
// （與 URLSearchParams.get 相同）。只用網址上的值，不另外查詢那張單。
export const DIRECT_TABS = Object.freeze(['pending', 'history', 'tickets', 'reviews'])

// 1 到 10 位、不以 0 開頭的十進位數字
const REQUEST_ID_RE = /^[1-9][0-9]{0,9}$/

/**
 * @param {string} search 網址查詢字串（含或不含開頭的 ?）
 * @returns {{ tab: string|null, request: number|null }}
 */
export function parseApprovalsDirect(search) {
  const params = new URLSearchParams(search || '')
  const tab = params.get('tab')
  const request = params.get('request')
  return {
    tab: DIRECT_TABS.includes(tab) ? tab : null,
    request: typeof request === 'string' && REQUEST_ID_RE.test(request) ? Number(request) : null,
  }
}

/**
 * 依參數與檢視者決定開啟的頁籤。
 * - 只有歷史讀取資格者只有歷史頁籤，其他頁籤參數忽略。
 * - 頁籤缺席或被忽略：有合格的單號照既有行為落在歷史頁籤，沒有就用預設頁籤。
 * @returns {string} 頁籤名稱
 */
export function directInitialTab({ tab, request }, { historyOnly }) {
  if (historyOnly) return 'history'
  if (tab) return tab
  if (request) return 'history'
  return 'pending'
}
