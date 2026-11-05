import request from './request'

/**
 * 取得連線的鍵盤紀錄中繼資料（keystroke:view；不解密、不需理由）。
 * state ∈ { pre_feature, not_covered, record_missing, recording, complete, incomplete, failed, purged }；
 * viewable 為後端判定「是否有可查看的內容」，前端只看它決定開理由對話框或直接顯示狀態說明。
 * 會話不存在回既有的 NOTFOUND_SESSION。
 * @param {string|number} sessionId
 * @returns {Promise} { data: { state, viewable, feature_since?, coverage_reason?, failure_cause?, event_count?, ... } }
 */
export function getKeystrokeMeta(sessionId) {
  return request({ url: `/sessions/${sessionId}/keystrokes`, method: 'get', skipErrorToast: true })
}

/**
 * 帶理由查看鍵盤紀錄內容（keystroke:view）。理由只放在請求本文，不放網址或查詢字串。
 * 每一頁都是一次帶理由的請求，各自留痕；呼叫端不得把回應寫入瀏覽器儲存或 console。
 * @param {string|number} sessionId
 * @param {{ reason: string, from_event?: number, limit?: number }} body
 * @returns {Promise} { data: { events, integrity, record_status, last_event_ms, next_event?, failed_segment? } }
 */
export function viewKeystrokes(sessionId, body) {
  // 錯誤由呼叫端在對話框內就地呈現，不走全域 toast
  return request({ url: `/sessions/${sessionId}/keystrokes/view`, method: 'post', data: body, skipErrorToast: true })
}
