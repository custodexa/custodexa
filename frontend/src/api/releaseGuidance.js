import request from './request'

/**
 * 版本說明的 API 客戶端。
 *
 * - 關閉狀態是本人偏好（owner/self）：路徑上沒有使用者識別，伺服器只認認證主體。
 * - 保留調整告知需要安全政策讀取能力；失敗由呼叫端在卡片內呈現並提供重試，
 *   不走全域 toast，也不把失敗當成「沒有調整」。
 */

/** 讀取本人對某說明版本的關閉狀態，回 { notice_version, dismissed }。 */
export function getReleaseGuidanceState(version) {
  return request({
    url: `/auth/me/release-guidance/${encodeURIComponent(version)}`,
    method: 'get',
    skipErrorToast: true,
  })
}

/** 關閉某說明版本（冪等）；本文固定為 { dismissed: true }。 */
export function dismissReleaseGuidance(version) {
  return request({
    url: `/auth/me/release-guidance/${encodeURIComponent(version)}`,
    method: 'put',
    data: { dismissed: true },
    skipErrorToast: true,
  })
}

/** 讀取升級時的保留天數調整與目前未被檢查點涵蓋的關係。 */
export function getRetentionAdjustments() {
  return request({
    url: '/dashboard/retention-adjustments',
    method: 'get',
    skipErrorToast: true,
  })
}
