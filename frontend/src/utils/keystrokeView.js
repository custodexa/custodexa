// 鍵盤紀錄查看的前端共用邏輯：記憶體交接、錯誤分類、狀態說明對照。
//
// 查看內容與理由只存在於記憶體：不寫 localStorage、sessionStorage、IndexedDB、路由參數或 console。
// 交接用模組變數，且取走即清空；重新整理或開新分頁後交接物不存在，頁面要求重新填理由。

export const REASON_MAX = 1000

// 後端標記事件（kind 0x10）的機器碼；碼值是儲存格式的一部分，與後端 marker.go 對照
export const MARKER_CODES = Object.freeze([
  'end_user_closed', 'end_client_lost', 'end_target_closed', 'end_idle_timeout',
  'end_max_duration', 'end_block_clear_failed', 'end_terminated', 'writer_stalled',
])

// 失敗原因碼（後端 audit_failure cause）
export const FAILURE_CAUSES = Object.freeze([
  'KEYSTROKE_DIR_UNWRITABLE', 'KEYSTROKE_KEY_SEAL_FAILED', 'KEYSTROKE_FILE_CREATE_FAILED',
  'KEYSTROKE_WRITE_FAILED', 'KEYSTROKE_WRITER_STALLED',
])

let held = null

/** 對話框成功取得第一頁後，把理由與第一頁內容交給檢視頁。 */
export function holdKeystrokeView(sessionId, reason, firstPage) {
  held = { sessionId: String(sessionId), reason, firstPage }
}

/** 檢視頁掛載時取走；取走即清空。對不上連線編號時回 null 並一併清空。 */
export function takeKeystrokeView(sessionId) {
  const out = held && held.sessionId === String(sessionId) ? held : null
  held = null
  return out
}

export function clearKeystrokeView() {
  held = null
}

/** 以字元（code point）計；前後空白不計。 */
export function reasonLength(reason) {
  return Array.from(String(reason ?? '').trim()).length
}

/**
 * 錯誤分類。只看後端錯誤碼與狀態碼，不讀任何回應內容。
 * retryable：會好轉的錯誤（未解封、暫時寫不進查看紀錄、其他暫時性失敗）。
 */
export function classifyKeystrokeError(err) {
  const status = err?.response?.status
  const code = err?.response?.data?.code
  const base = (kind, retryable) => ({ kind, retryable, code: code || '', status: status || 0 })
  switch (code) {
    case 'RULE_KEYSTROKE_VAULT_SEALED': return base('sealed', true)
    case 'RULE_KEYSTROKE_RECORD_REJECTED': return base('rejected', false)
    case 'INTERNAL_KEYSTROKE_VIEW': return base('audit', true)
    case 'RESOURCE_KEYSTROKE_NOT_VIEWABLE': return base('notViewable', false)
    case 'VALIDATION_KEYSTROKE_REASON_REQUIRED': return base('reasonRequired', false)
    case 'VALIDATION_KEYSTROKE_REASON_TOO_LONG': return base('reasonTooLong', false)
    default:
  }
  if (status === 401 || status === 403) return base('noPermission', false)
  return base('other', true)
}

/**
 * 沒有可查看內容時的狀態說明對照（i18n 鍵都在 keystrokeView.noContent 之下）。
 * @returns {{ tone: 'info'|'warn'|'error', key: string, params?: object, hint?: string }}
 */
export function describeNoContent(meta) {
  const m = meta || {}
  switch (m.state) {
    case 'pre_feature':
      return { tone: 'info', key: 'preFeature', hint: 'preFeatureHint', time: m.feature_since }
    case 'not_covered': {
      const reason = ['k8s_logs_readonly', 'db_console', 'graphics_pending', 'file_transfer'].includes(m.coverage_reason)
        ? m.coverage_reason : 'generic'
      return { tone: 'info', key: `notCovered.${reason}` }
    }
    case 'record_missing':
      return { tone: 'error', key: 'recordMissing', hint: 'recordMissingHint' }
    case 'failed':
      return { tone: 'error', key: 'failedNoFile', cause: FAILURE_CAUSES.includes(m.failure_cause) ? m.failure_cause : '' }
    case 'purged':
      return { tone: 'warn', key: 'purged', hint: 'purgedHint', time: m.purged_at }
    default:
      return { tone: 'info', key: 'generic' }
  }
}

/**
 * 檢視頁紀錄狀態：integrity 是讀取器的完整性判定，recordStatus 是紀錄列的狀態。
 * 優先序：檔案缺失 > 疑似竄改 > 紀錄中 > 中途失敗 > 未正常結束 > 不完整 > 完整。
 */
export function describeIntegrity(integrity, recordStatus) {
  if (integrity === 'file_missing') return { kind: 'fileMissing', tag: 'danger' }
  if (integrity === 'tampered') return { kind: 'tampered', tag: 'danger' }
  if (recordStatus === 'recording') return { kind: 'recording', tag: 'primary' }
  if (recordStatus === 'failed') return { kind: 'failed', tag: 'danger' }
  if (recordStatus === 'incomplete') return { kind: 'incomplete', tag: 'warning' }
  if (integrity === 'truncated') return { kind: 'truncated', tag: 'warning' }
  return { kind: 'complete', tag: 'success' }
}

const pad = (n, w = 2) => String(n).padStart(w, '0')

/** 連線後的相對時間 hh:mm:ss.d。 */
export function formatOffsetMs(ms) {
  const total = Math.max(0, Math.floor(Number(ms) || 0))
  const h = Math.floor(total / 3600000)
  const m = Math.floor((total % 3600000) / 60000)
  const s = Math.floor((total % 60000) / 1000)
  const d = Math.floor((total % 1000) / 100)
  return `${pad(h)}:${pad(m)}:${pad(s)}.${d}`
}

/** 事件絕對時間的時分秒（本地時區）。 */
export function formatClock(iso) {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '-'
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}
