import request from './request'

/**
 * 儀表板逐卡資料。每次只取一張卡，卡與卡之間互不牽連：
 * 一張失敗由呼叫端在該卡內呈現，不影響其他卡。
 *
 * 回應 { key, value, unit, filters, count?, review_count?, overdue?, review_period_days? }。
 * `filters` 是對應列表 API 的查詢參數（含日界線字串，微秒完整），
 * 導覽時必須原樣放進 route query，不經任何時間型別轉換。
 * 錯誤由卡片自行處理，不走全域 toast。
 */
export function getDashboardCard(key) {
  return request({
    url: `/dashboard/cards/${encodeURIComponent(key)}`,
    method: 'get',
    skipErrorToast: true,
  })
}
