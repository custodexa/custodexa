// 伺服端訊息 → 畫面狀態的映射（純函式）。
//
// 與通道分開的理由：訊息形狀由伺服端的協議決定，而它會隨後端演進；把「欄位怎麼
// 讀」集中在一處，通道那邊只剩「讀出來之後要做什麼」。缺欄位一律折成安全預設，
// 不讓 undefined 流進畫面。

/**
 * `ready` 的會話事實。
 * @param {object} msg
 */
export function sessionFacts(msg) {
  return {
    sessionId: msg.session_id ?? null,
    dialect: msg.dialect || '',
    database: msg.database || '',
    databaseAllowed: msg.database_allowed !== false,
    databases: Array.isArray(msg.databases) ? msg.databases : [],
    capabilities: msg.capabilities || null,
    txState: msg.tx_state || '',
    limits: msg.limits || {},
  }
}

/**
 * `result` 對應執行單位的欄位。
 * @param {object} msg
 */
export function resultPatch(msg) {
  return {
    seq: msg.seq ?? 0,
    status: msg.status || '',
    reason: msg.result_reason || '',
    sets: Array.isArray(msg.sets) ? msg.sets : [],
    rowsAffected: msg.rows_affected ?? 0,
    durationMs: msg.duration_ms ?? 0,
    truncated: msg.truncated === true,
    txState: msg.tx_state || '',
    dbError: msg.db_error || null,
    resultUnknown: false,
  }
}

/**
 * `ready.pending_result` 的回填。只有狀態與原因碼，沒有結果資料——
 * 結果快取隨舊會話釋放，而把「未知」更新成真相不需要資料本身。
 * @param {object} msg
 * @returns {{eventId: string, patch: object}|null}
 */
export function pendingResultPatch(msg) {
  const pending = msg.pending_result
  if (!pending?.event_id) return null
  return {
    eventId: pending.event_id,
    patch: {
      status: pending.status || 'running',
      reason: pending.result_reason || '',
      resultUnknown: false,
    },
  }
}

/**
 * `notice` 對目標庫的效果。回 null＝這則通知不影響目標狀態。
 * @param {object} msg
 * @returns {{database: string, allowed: boolean, code: string}|null}
 */
export function noticeEffect(msg) {
  const database = msg.params?.database || ''
  if (msg.code === 'database_switched') {
    return { database, allowed: true, code: '' }
  }
  if (msg.code === 'database_not_allowed' || msg.code === 'database_drift_denied') {
    return { database, allowed: false, code: msg.code }
  }
  return null
}
