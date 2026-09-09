import request from './request'

// 排程時刻的共用查詢。
//
// 下次執行時刻一律問後端：時區、日曆邊界（每月 31 日、閏年）與排程器實際採用的
// 解析規則只有後端說得準，前端自己算會與真正的執行時刻分岔。

/**
 * 接下來的執行時刻（POST /schedules/next-runs）。
 *
 * @param {Object} data - { cron: 五欄字串, count: 1–10（缺省 3） }
 * @param {Object} [options] - { skipErrorToast } 呼叫端自行就近呈現錯誤時開啟
 * @returns {Promise<{runs: string[], timezone: string}>} runs 為含時區位移的
 *   RFC3339 字串，時區即排程器採用的時區——呼叫端只顯示，不再換算。
 */
export function getScheduleNextRuns(data, options = {}) {
  return request({
    url: '/schedules/next-runs',
    method: 'post',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}
