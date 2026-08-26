import request from './request'

/**
 * 取得單一會話的剪貼簿事件事實列表（時間序；不含內容）
 * content_status ∈ { available, failed }——failed＝內容留存失敗的缺口紀錄，
 * 事實仍在、內容缺席，呈現端不得以長度或空值推斷。
 * @param {string|number} sessionId - 會話 ID
 * @returns {Promise} { data: [{ id, session_id, direction, content_length, content_status, created_at }], total }
 */
export function getSessionClipboardEvents(sessionId) {
  return request({
    url: `/sessions/${sessionId}/clipboard-events`,
    method: 'get',
  })
}

/**
 * 取得單筆剪貼簿事件的解密內容（audit:view；伺服器端逐筆留痕，
 * 留痕成功是交付前置——fail-close，審計不可用時後端收斂拒絕）。
 * 缺口紀錄（content_status=failed）回 200 事實且 content 鍵缺席，
 * 不以空字串冒充內容。跨會話／不存在收斂為 NOTFOUND_CLIPBOARD_EVENT。
 * @param {string|number} sessionId - 會話 ID
 * @param {string|number} eventId - 剪貼簿事件 ID
 * @returns {Promise} { data: { id, session_id, direction, content_length, content_status, created_at, content? } }
 */
export function getClipboardEventContent(sessionId, eventId) {
  return request({
    url: `/sessions/${sessionId}/clipboard-events/${eventId}/content`,
    method: 'get',
  })
}
