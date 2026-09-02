/**
 * 查詢主控台的枚舉顯示中繼資料唯一事實源。
 *
 * 值域硬拷後端：
 *   result_status  ＝ backend/internal/model/session_command.go:142-164
 *   result_reason  ＝ backend/internal/model/session_command.go:168-190
 *   tx_state       ＝ backend/internal/model/session_command.go:196-203
 *   closed.reason  ＝ backend/internal/sshproxy/dbconsole_message.go:52-58
 *   notice.code    ＝ backend/internal/sshproxy/dbconsole_message.go:45-48
 * 譯文住 locale 檔，以 getter 回 t()；後端新增值時此處補一筆＋三語補 key，
 * 完備性單測（db-console-enums.spec.js）對每值 × 每 locale 斷言非空，缺漏即紅燈。
 *
 * 空字串不在任何值域內：那是「這不是主控台列」的判別鍵，屬命令列會話。
 */
import { t } from '@/i18n'

// 八值狀態的色彩語義。**`partial` 與 `effect_unknown` 不得呈現為成功或失敗**：
// 前者是「已完成的部分不可假設沒有生效」，後者是「伺服器確知自己不知道」，
// 兩者都是要人去查的狀態，故一律警示色
const RESULT_STATUS_TAG_TYPES = {
  running: 'primary',
  ok: 'success',
  error: 'danger',
  partial: 'warning',
  blocked: 'danger',
  cancelled: 'info',
  timeout: 'warning',
  effect_unknown: 'warning',
}

export const RESULT_STATUS_VALUES = Object.keys(RESULT_STATUS_TAG_TYPES)

// 要人去查的狀態：畫面另加警示橫幅，不只換個顏色
export const RESULT_STATUS_ALERT_VALUES = ['partial', 'effect_unknown']

export const RESULT_REASON_VALUES = [
  'matcher_hit',
  'matcher_unavailable',
  'error_after_results',
  'cancel_confirmed',
  'batch_stopped',
  'timeout_confirmed',
  'cancel_unconfirmed',
  'timeout_unconfirmed',
  'connection_lost',
  'cell_truncated',
]

export const TX_STATE_VALUES = ['none', 'active', 'failed', 'unknown']

export const CLOSED_REASON_VALUES = [
  'target_closed',
  'slow_consumer',
  'idle_timeout',
  'max_duration',
  'terminated',
  'client_gone',
]

// 目標受限的兩個成因（notice）。`database_switched` 不在此列——那是成功事件
export const RESTRICTED_NOTICE_VALUES = ['database_not_allowed', 'database_drift_denied']

const labelMap = (values, prefix) => {
  const out = {}
  for (const value of values) {
    Object.defineProperty(out, value, {
      enumerable: true,
      get: () => t(`${prefix}.${value}`),
    })
  }
  return out
}

export const RESULT_STATUS_LABELS = labelMap(RESULT_STATUS_VALUES, 'enum.resultStatus')
export const RESULT_REASON_LABELS = labelMap(RESULT_REASON_VALUES, 'enum.resultReason')
export const TX_STATE_LABELS = labelMap(TX_STATE_VALUES, 'enum.txState')
export const CLOSED_REASON_LABELS = labelMap(CLOSED_REASON_VALUES, 'dbConsole.closed')

export const resultStatusLabel = (v) => RESULT_STATUS_LABELS[v] || v || ''
export const resultStatusTagType = (v) => RESULT_STATUS_TAG_TYPES[v] || 'info'
export const resultReasonLabel = (v) => RESULT_REASON_LABELS[v] || v || ''
export const txStateLabel = (v) => TX_STATE_LABELS[v] || v || ''
export const closedReasonLabel = (v) => CLOSED_REASON_LABELS[v] || v || ''

// 需要人去查的狀態（警示橫幅的判準）
export const isAlertStatus = (v) => RESULT_STATUS_ALERT_VALUES.includes(v)
// 交易未收束：畫面常駐提示，關分頁前要確認
export const isTxUnsettled = (v) => v === 'active' || v === 'failed'
