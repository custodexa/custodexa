// 錄影可讀性：詳情回應的 recording_state 與錄影端點錯誤碼，對到同一套白話文案。
//
// 兩個入口共用這裡的對照：
//   - 頁面載入時：GET /sessions/:id 帶 recording_state（available／missing／unreadable），
//     缺席＝舊後端或探測無法下結論，維持現行行為（被動呈現兜底）
//   - 載入之後才失敗：播放器與下載依回應的機器碼呈現同一組文字
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

export const RECORDING_UNREADABLE_CODE = 'INTERNAL_RECORDING_FILE_UNREADABLE'
export const RECORDING_MISSING_CODE = 'NOTFOUND_RECORDING_FILE'

const STATE_TO_CODE = {
  unreadable: RECORDING_UNREADABLE_CODE,
  missing: RECORDING_MISSING_CODE,
}

// 錄影檔讀不到的兩種狀態；其餘（available、缺席）回 null
export function blockedRecordingState(session) {
  const state = session?.has_recording ? session.recording_state : undefined
  return state === 'unreadable' || state === 'missing' ? state : null
}

// 可讀但來源為離機：播放與下載前要先取回
export function isOffsiteRecording(session) {
  return Boolean(session?.has_recording) &&
    session.recording_state === 'available' &&
    session.recording_source === 'offsite'
}

export function codeForState(state) {
  return STATE_TO_CODE[state] || ''
}

// 機器碼 → 讀不到的種類；其他碼回 null
export function problemFromCode(code) {
  if (code === RECORDING_UNREADABLE_CODE) return 'unreadable'
  if (code === RECORDING_MISSING_CODE) return 'missing'
  return null
}

// 自錯誤回應本體取出錯誤信封（{code, error, params}）。
// 本體可能是 Blob（responseType: 'blob'）、fetch Response 或已解析的物件；
// 解析不了回 null，呼叫端退回通用文案，不顯示 HTTP 狀態列原文
export async function readErrorEnvelope(body) {
  try {
    if (!body) return null
    if (typeof Response !== 'undefined' && body instanceof Response) {
      return JSON.parse(await body.text())
    }
    if (typeof Blob !== 'undefined' && body instanceof Blob) {
      return JSON.parse(await body.text())
    }
    if (typeof body === 'string') return JSON.parse(body)
    return typeof body === 'object' ? body : null
  } catch {
    return null
  }
}

// 播放中斷覆蓋層的文案：讀不到的兩種各有專屬說法，其餘依機器碼查譯文
export function playbackFailure(envelope, status) {
  const problem = problemFromCode(envelope?.code)
  if (problem) {
    return {
      problem,
      title: t(`recordingReadability.playback.${problem}.title`),
      detail: t(`recordingReadability.playback.${problem}.detail`),
    }
  }
  return {
    problem: null,
    title: t('player.loadFailedTitle'),
    detail: envelope ? resolveApiError(envelope, status) : t('player.initFailed'),
  }
}

// 下載失敗的提示文字
export function downloadFailureMessage(envelope, status) {
  const problem = problemFromCode(envelope?.code)
  if (problem) return t(`recordingReadability.download.${problem}`)
  const reason = envelope ? resolveApiError(envelope, status) : t('api.requestFailed')
  return t('recordingReadability.download.failed', { reason })
}
