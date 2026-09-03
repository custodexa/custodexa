import request from './request'

/**
 * 取得 Session 列表
 * @param {Object} params - 查詢參數
 * @param {number} params.user_id - 使用者 ID 過濾
 * @param {number} params.asset_id - 資產 ID 過濾
 * @param {string} params.protocol - 協議過濾 (ssh/rdp/vnc)
 * @param {string} params.status - 狀態過濾 (active/disconnected/closed)
 * @param {string} params.start_time - 開始時間過濾（RFC3339 格式）
 * @param {string} params.end_time - 結束時間過濾（RFC3339 格式）
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @returns {Promise}
 */
export function getSessionList(params) {
  return request({
    url: '/sessions',
    method: 'get',
    params,
  })
}

/**
 * 取得 Session 詳情
 * @param {number} id - Session ID
 * @returns {Promise}
 */
export function getSession(id) {
  return request({
    url: `/sessions/${id}`,
    method: 'get',
  })
}

/**
 * 取得活動 Session
 * @returns {Promise}
 */
export function getActiveSessions() {
  return request({
    url: '/sessions/active',
    method: 'get',
  })
}

/**
 * 取得 Session 統計資訊
 * @returns {Promise}
 */
export function getSessionStatistics() {
  return request({
    url: '/sessions/statistics',
    method: 'get',
  })
}

/**
 * 強制終止 Session
 * @param {number} id - Session ID
 * @returns {Promise}
 */
export function terminateSession(id) {
  return request({
    url: `/sessions/${id}/terminate`,
    method: 'post',
  })
}

/**
 * 取得 Session 錄製檔案 URL
 * @param {number} id - Session ID
 * @returns {string} 錄製檔案串流 URL
 */
export function getRecordingUrl(id) {
  return `/api/v1/sessions/${id}/recording/stream`
}

/**
 * 取得一次性錄影存取 token（避免把長效 JWT 放進播放 URL）
 * @param {number} id - Session ID
 * @returns {Promise<{token: string}>}
 */
export function getRecordingToken(id) {
  return request({ url: `/sessions/${id}/recording/token`, method: 'post' })
}

/**
 * 以錄影 token 組裝串流 URL（播放器用，URL 不含 JWT）
 * @param {string} rtoken - 一次性錄影 token
 * @returns {string}
 */
export function recordingStreamUrlByToken(rtoken) {
  return `/api/v1/recordings/stream?rtoken=${encodeURIComponent(rtoken)}`
}

/**
 * 錄影目錄的目前佔用統計（需 audit:view）。
 * 值取自錄影目錄的實際檔案大小加總，非資料庫的每會話 recording_size 欄位。
 * @returns {Promise<{total_size: number, count: number, oldest_date: string, newest_date: string}>}
 */
export function getRecordingStats() {
  return request({ url: '/recordings/stats', method: 'get' })
}

/**
 * 下載 Session 錄製檔案
 * @param {number} id - Session ID
 * @returns {Promise}
 */
export function downloadRecording(id) {
  return request({
    url: `/sessions/${id}/recording/download`,
    method: 'get',
    responseType: 'blob',
  })
}

/** SSH 會話即時指標（session-stats） */
export function getSessionStats(sessionId) {
  return request({
    url: `/ssh/sessions/${sessionId}/stats`,
    method: 'get',
    skipErrorToast: true,
  })
}

/** 建立會話分享（session-share） */
export function createSessionShare(sessionId, data) {
  return request({ url: `/sessions/${sessionId}/share`, method: 'post', data })
}

/** 撤銷會話分享 */
export function revokeSessionShare(sessionId) {
  return request({ url: `/sessions/${sessionId}/share`, method: 'delete' })
}

/**
 * 簽發即時監看的一次性觀看票（限 admin／auditor）。
 * WebSocket 只收這張票，登入憑證不進 URL
 */
export function createMonitorTicket(sessionId) {
  return request({
    url: `/sessions/${sessionId}/monitor-token`,
    method: 'post',
    skipErrorToast: true,
  })
}

/**
 * 簽發分享觀看的一次性觀看票（任何已登入者）。
 * 分享碼走請求本體：本端點的請求路徑會進入操作日誌，碼是短期憑證，不該留在那裡
 */
export function createShareTicket(code) {
  return request({
    url: '/sessions/share/token',
    method: 'post',
    data: { code },
    skipErrorToast: true,
  })
}
