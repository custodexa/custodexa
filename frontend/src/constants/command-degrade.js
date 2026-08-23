/**
 * 指令審計「降級／限定」原因碼的顯示中繼資料。
 *
 * 值域硬拷後端：`backend/internal/model/session_command.go` 的 `Degrade*`／`Qualify*`
 * 常數區（碼是權威表述，散文由此處按碼查譯）。**兩個值域刻意不合併**：
 *   - `Degraded=true`  → 該輪沒有可信的指令文字，`command` 必為空（DB CHECK 釘死）。
 *   - `Degraded=false` 且 `degrade_reason` 非空 → 文字已入庫、但可能不等於實際執行。
 *
 * **UI 紅線**：沒有降級標記 SHALL NOT 被呈現為「內容已驗證」——
 * 偵測判準是充分條件而非必要條件，故本模組只為「有標記」的列提供文案，
 * 一般列不加任何「已驗證」字樣。
 *
 * 後端新增碼時：本檔值域補一筆 ＋ 三語 locale 補 `enum.commandDegrade.<碼>`；
 * `command-degrade.spec.js` 直讀後端原始碼雙向比對，任一方向缺漏即紅燈。
 * 未知碼仍有 default 分支（`reasonUnknown`），不致白屏或顯示裸碼。
 */
import { t } from '@/i18n'

// Degrade*：該輪沒有可信文字（`degraded=true`）
export const DEGRADE_REASON_VALUES = [
  'altscreen_round',
  'redraw_unanchored',
  'fullscreen_input',
  'queue_discarded',
  'queue_discarded_at_close',
  'queue_uncounted',
  'queue_overflow',
  'input_without_echo',
]

// Qualify*：文字已入庫但受限定（`degraded=false` 且原因碼非空）
export const QUALIFY_REASON_VALUES = ['replay_input_bytes']

export const COMMAND_REASON_VALUES = [...DEGRADE_REASON_VALUES, ...QUALIFY_REASON_VALUES]

// 回顯被關閉的那一類**連錄影都救不回**（asciicast 只有輸出方向的 "o" 事件）。
// 對這些碼不得沿用「錄影可能保留該時段畫面」的下一步文案。
const REASONS_WITHOUT_RECORDING_HOPE = new Set(['input_without_echo'])

/**
 * 原因碼查譯。未知碼走 default 分支（帶出原碼供回報），不顯示裸鍵、不白屏。
 * @param {string|undefined} code 機器碼
 * @returns {string}
 */
export const degradeReasonLabel = (code) => {
  if (!code) return t('commands.degrade.reasonMissing')
  if (COMMAND_REASON_VALUES.includes(code)) return t(`enum.commandDegrade.${code}`)
  return t('commands.degrade.reasonUnknown', { code })
}

/**
 * 降級列的「下一步」文案。三種錄影狀態各有其誠實邊界：
 *   unavailable → 本連線沒有錄影，不得暗示去看回放；
 *   回顯關閉類 → 錄影同樣不會有畫面（design：`"o"` 事件不含按鍵）；
 *   其餘        → 「**可能**保留」，不宣稱一定有。
 * @param {string|undefined} code 機器碼
 * @param {'available'|'unavailable'|'unknown'} recordingState
 */
export const degradeRecordingHint = (code, recordingState = 'unknown') => {
  if (recordingState === 'unavailable') return t('commands.degrade.recordingUnavailable')
  if (REASONS_WITHOUT_RECORDING_HOPE.has(code)) return t('commands.degrade.recordingNoEcho')
  return t('commands.degrade.recordingMaybe')
}

// ---------------------------------------------------------------------------
// 降級告警（command_alerts.kind = audit_degraded）
//
// 告警走**獨立的**機器碼值域（`model.AlertReason*`），不與上面的 Degrade* 共用：
// 那邊描述的是「某一輪為何沒有文字」，這邊描述的是「一段降級區間開始」。
// 值域刻意不做後端原始碼雙向守衛——它由另一條線在演進中，
// 未知碼有 default 分支承接，介面不會白屏也不會顯示裸鍵。
// ---------------------------------------------------------------------------
export const ALERT_KIND_AUDIT_DEGRADED = 'audit_degraded'

export const COMMAND_ALERT_REASON_VALUES = ['audit_degraded_span']

/** 該筆告警是否為指令審計降級告警（非規則比對） */
export const isDegradedAlert = (row) => row?.kind === ALERT_KIND_AUDIT_DEGRADED

/** 降級告警的原因碼查譯；未知碼帶出原碼 */
export const commandAlertReasonLabel = (code) => {
  if (!code) return t('commands.degrade.reasonMissing')
  if (COMMAND_ALERT_REASON_VALUES.includes(code)) return t(`enum.commandAlertReason.${code}`)
  return t('commands.degrade.reasonUnknown', { code })
}

/** 該列是否為「沒有可信文字」的降級列 */
export const isDegradedRow = (row) => row?.degraded === true

/** 該列是否為「文字已入庫但受限定」（Qualify*）。降級列不算在內——兩者不同型 */
export const isQualifiedRow = (row) => row?.degraded !== true && Boolean(row?.degrade_reason)
