// 執行單位的資料形狀與更新規則。
//
// 與通道狀態機分開，是因為這裡的規則與「連線好不好」無關：一個單位從哪裡來
// （unit_started、未經 unit_started 的未送出批次、重連時的佔位列）、
// 怎麼被回填、什麼時候算「不知道」，是同一組不變式。

/**
 * 一個尚未回填的執行單位。
 * @param {string} eventId 事件識別
 * @param {number} submission 送出批號（匯出只有最近一批可用）
 */
export function emptyUnit(eventId, submission = 0) {
  return {
    eventId,
    seq: 0,
    sql: '',
    batchIndex: 0,
    batchCount: 1,
    submission,
    status: 'running',
    reason: '',
    sets: [],
    rowsAffected: 0,
    durationMs: 0,
    truncated: false,
    txState: '',
    dbError: null,
    // 伺服端沒回終態就斷線：這一筆的效果未知，畫面須明說而不是留白
    resultUnknown: false,
  }
}

/**
 * 未收束的佔位列（重連自報用）。
 * @param {string} eventId
 * @param {string} sql 該單位的原文（重送前比對用）
 */
export function pendingUnit(eventId, sql) {
  return { ...emptyUnit(eventId), sql, resultUnknown: true }
}

/**
 * 依事件識別更新或新增一個單位，回傳新陣列（不就地改）。
 * 未經 `unit_started` 就直接回終態的單位（前一批次失敗而未送出者）也走這裡。
 * @param {object[]} list 現有單位
 * @param {string} eventId
 * @param {object} patch 要套用的欄位
 * @param {object} [seed] 新建時的補充欄位
 * @returns {object[]}
 */
export function upsertUnit(list, eventId, patch, seed = {}) {
  const index = list.findIndex((u) => u.eventId === eventId)
  if (index === -1) {
    return [...list, { ...emptyUnit(eventId), ...seed, ...patch }]
  }
  const next = list.slice()
  next[index] = { ...next[index], ...patch }
  return next
}

/**
 * 斷線時把仍在進行中的單位標成「結果未知」。
 * @param {object[]} list
 * @returns {{units: object[], pending: object|null}} 新陣列與第一筆未收束的單位
 */
export function markRunningUnknown(list) {
  const pending = list.find((u) => u.status === 'running') || null
  if (!pending) return { units: list, pending: null }
  return {
    units: list.map((u) => (u.status === 'running' ? { ...u, resultUnknown: true } : u)),
    pending,
  }
}
