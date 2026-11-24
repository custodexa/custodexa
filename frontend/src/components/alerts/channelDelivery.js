/**
 * 通知通道的送達狀況與投遞紀錄：狀態推導、原因句子、重送推算、短時間格式。
 * 通道列表、投遞紀錄抽屜與系統告警明細共用。
 *
 * 後端回的是原因代碼（`last_failure_code`、`reason_code`）與已遮蔽的原文；畫面一律以代碼選句子，
 * 不直接顯示對方回傳的字串（「Slack 回報錯誤：{code}」例外，代碼本身已經過字元與長度限制）。
 */
import { t, te } from '@/i18n'
import {
  DELIVERY_MAX_ATTEMPTS,
  DELIVERY_BACKOFF_BASE_MS,
  DELIVERY_BACKOFF_MAX_MS,
} from '@/constants/notification-channels'

/** 沒有語意顏色的狀態（尚未投遞、已停用、等待中、已取消）用產品的中性標籤 */
export const NEUTRAL_TAG_CLASS = 'ot-tag-neutral'
export const NEUTRAL_HEALTH = ['none', 'disabled']
export const NEUTRAL_DELIVERY_STATES = ['pending', 'canceled']

/** 送達狀況標籤 → el-tag 型別 */
export const HEALTH_TAG_TYPES = {
  ok: 'success',
  failing: 'danger',
  abandoned: 'warning',
  none: 'info',
  disabled: 'info',
}

const ts = (v) => (v ? new Date(v).getTime() : NaN)

/**
 * 通道列的送達狀況：停用 → disabled；三個值都沒有 → none；最近失敗晚於最近送達 → failing；
 * 近 7 天有放棄 → abandoned；其餘 → ok。
 */
export function healthStatus(row) {
  if (!row || !row.enabled) return 'disabled'
  const h = row.health
  if (!h) return 'none'
  const ok = ts(h.last_delivered_at)
  const fail = ts(h.last_failed_at)
  const abandoned = Number(h.abandoned_7d) || 0
  if (Number.isNaN(ok) && Number.isNaN(fail) && abandoned === 0) return 'none'
  if (!Number.isNaN(fail) && (Number.isNaN(ok) || fail > ok)) return 'failing'
  if (abandoned > 0) return 'abandoned'
  return 'ok'
}

/** 最近失敗晚於最近送達（列表以紅字與淡紅列底標示） */
export const isFailing = (row) => healthStatus(row) === 'failing'

// 原因代碼 → 句子鍵（delivery.reason.*）。http 類需要狀態碼，從已遮蔽的原文取出
const REASON_KEYS = {
  http_404: 'http404',
  http_401: 'http401',
  http_5xx: 'http5xx',
  http_other: 'httpOther',
  timeout: 'timeout',
  connect: 'connect',
  slack_channel: 'slackChannel',
  slack_not_in: 'slackNotIn',
  slack_auth: 'slackAuth',
  slack_scope: 'slackScope',
  slack_rate: 'slackRate',
  slack_other: 'slackOther',
  snapshot_unreadable: 'unreadable',
  channel_unreadable: 'channelUnreadable',
  policy: 'policy',
  redirect_not_followed: 'http3xx',
  redirect_policy: 'redirectPolicy',
  redirect_too_many: 'redirectTooMany',
  rate_limited: 'slackRate',
  type_unregistered: 'typeUnregistered',
  render_failed: 'renderFailed',
}

const httpStatusOf = (raw) => {
  const m = /HTTP\s+(\d{3})/.exec(raw || '')
  return m ? m[1] : ''
}

const platformCodeOf = (raw) => {
  const m = /platform error:\s*([a-z0-9_]{1,64})/i.exec(raw || '')
  return m ? m[1] : ''
}

/**
 * 原因句子。`code` 為原因代碼，`raw` 為已遮蔽的原文（只用來取 HTTP 狀態碼與平台錯誤碼）。
 * 未知代碼退回「收端回應錯誤」的一般句子，不顯示原文。
 */
export function reasonText(code, raw = '') {
  const key = REASON_KEYS[code]
  const status = httpStatusOf(raw)
  if (!key) return status ? t('alerts.deliveryReason.httpOther', { status }) : t('alerts.deliveryReason.unknown')
  if (key === 'slackOther') return t('alerts.deliveryReason.slackOther', { code: platformCodeOf(raw) || '-' })
  if (key === 'http3xx' && !status) return t('alerts.deliveryReason.http3xxNoStatus')
  return t(`alerts.deliveryReason.${key}`, { status: status || '-' })
}

/** 第 attempts 次失敗後到下一次嘗試的間隔（與後端投遞程序的退避相同） */
export function backoffAfter(attempts) {
  let d = DELIVERY_BACKOFF_BASE_MS
  for (let i = 1; i < attempts && d < DELIVERY_BACKOFF_MAX_MS; i += 1) d *= 2
  return Math.min(d, DELIVERY_BACKOFF_MAX_MS)
}

/** 最多再試幾次（含下一次） */
export const remainingAttempts = (attempts) => Math.max(DELIVERY_MAX_ATTEMPTS - (Number(attempts) || 0), 0)

/**
 * 一直失敗的話約何時放棄：從下一次嘗試起，把之後每次失敗的間隔加上去，直到用完次數上限。
 * 回傳時間戳（毫秒）；沒有下一次嘗試時間時回 null。
 */
export function estimateGiveUpAt(attempts, nextAttemptAt) {
  const next = ts(nextAttemptAt)
  if (Number.isNaN(next)) return null
  const done = Number(attempts) || 0
  let at = next
  for (let k = done + 1; k < DELIVERY_MAX_ATTEMPTS; k += 1) at += backoffAfter(k)
  return at
}

const pad = (n) => String(n).padStart(2, '0')

/** 列表用的時間：`YYYY/MM/DD HH:mm`（欄標題另寫時區） */
export function formatListTime(v) {
  const d = new Date(v)
  if (!v || Number.isNaN(d.getTime())) return '-'
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** 抽屜用的短時間：`MM/DD HH:mm`（抽屜另寫時區） */
export function formatLogTime(v) {
  const d = new Date(v)
  if (!v || Number.isNaN(d.getTime())) return '-'
  return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** 瀏覽器時區的偏移字樣，三語相同（`UTC+8`、`UTC-5:30`、`UTC`） */
export function utcOffsetText(date = new Date()) {
  const minutes = -date.getTimezoneOffset()
  if (minutes === 0) return 'UTC'
  const sign = minutes > 0 ? '+' : '-'
  const abs = Math.abs(minutes)
  const rest = abs % 60
  return `UTC${sign}${Math.floor(abs / 60)}${rest ? `:${pad(rest)}` : ''}`
}

/** 投遞紀錄篩選 → 包含的狀態 */
export const LOG_FILTERS = {
  all: null,
  undelivered: ['pending', 'retrying'],
  abandoned: ['abandoned'],
  canceled: ['canceled'],
  delivered: ['delivered'],
}

const DELIVERY_STATES = ['pending', 'retrying', 'delivered', 'abandoned', 'canceled']
export const deliveryStateLabel = (state) =>
  DELIVERY_STATES.includes(state) ? t(`alerts.log.status.${state}`) : state

export const DELIVERY_STATE_TAG_TYPES = {
  pending: 'info',
  retrying: 'warning',
  delivered: 'success',
  abandoned: 'danger',
  canceled: 'info',
}

const CATEGORIES = ['command_alert', 'system_security_alert', 'system_event']
export const categoryLabel = (c) => (CATEGORIES.includes(c) ? t(`alerts.log.category.${c}`) : c)

/**
 * 事件名稱：系統安全告警用告警類型的名稱，系統事件用投遞紀錄的事件名稱表，
 * 指令告警不顯示事件名稱（類別已說明）。查無名稱的系統事件顯示「無法顯示的通知」。
 */
export function eventName(row) {
  const key = row?.event_key || ''
  if (row?.category === 'command_alert') return ''
  if (row?.category === 'system_security_alert' && key && te(`systemAlerts.types.${key}.name`)) {
    return t(`systemAlerts.types.${key}.name`)
  }
  const logKey = `alerts.log.event.${key.replace(/\./g, '_')}`
  if (key && te(logKey)) return t(logKey)
  return t('alerts.log.eventUnknown')
}

const SEVERITIES = ['high', 'medium', 'low']
export const severityLabel = (s) => (SEVERITIES.includes(s) ? t(`enum.alertLevel.${s}`) : s)
export const SEVERITY_TAG_TYPES = { high: 'danger', medium: 'warning', low: 'info' }

/**
 * 個人訊息（對個人派送）特有的終態原因。以原因代碼選句子（alerts.log.endReason.*），
 * 句子不含電子郵件。前三個是放棄（立即放棄、不重試），後三個是取消（送出前重驗不成立或開關關閉）。
 */
export const TARGETED_END_REASONS = [
  'no_email',
  'email_ambiguous',
  'recipient_not_found',
  'request_resolved',
  'recipient_ineligible',
  'direct_message_disabled',
]
const isTargetedEndReason = (r) => TARGETED_END_REASONS.includes(r)

/**
 * 投遞紀錄每一列的說明句。
 * - 等待中：帶 throttled_since（因限流或送出節流延後）才寫延後句；剛排入的不加句子。
 * - 重送中：已試次數、最近原因、下次時間、最多再試、約何時放棄；通道設定讀不到時改用專屬句。
 * - 已送達：第幾次送到。
 * - 已放棄：依結束原因。
 * - 已取消：依結束原因（停用或刪除）。
 */
export function deliveryDescription(row) {
  const reason = () => reasonText(row.reason_code, row.last_error)
  switch (row.state) {
    case 'pending': {
      // 因限流或送出節流延後的紀錄帶 throttled_since；剛排入、還沒輪到的不加句子
      if (row.throttled_since) {
        return t('alerts.log.desc.pending', { until: formatLogTime(row.next_attempt_at) })
      }
      return ''
    }
    case 'retrying': {
      const params = {
        attempts: row.attempts,
        last_at: formatLogTime(row.last_failed_at),
        next_at: formatLogTime(row.next_attempt_at),
        remaining: remainingAttempts(row.attempts),
      }
      if (row.reason_code === 'channel_unreadable') return t('alerts.log.desc.retryingUnreadable', params)
      const giveUp = estimateGiveUpAt(row.attempts, row.next_attempt_at)
      return t('alerts.log.desc.retrying', {
        ...params,
        reason: reason(),
        give_up_at: giveUp ? formatLogTime(giveUp) : '-',
      })
    }
    case 'delivered': {
      const at = formatLogTime(row.delivered_at)
      return Number(row.attempts) > 1
        ? t('alerts.log.desc.deliveredNth', { at, n: row.attempts })
        : t('alerts.log.desc.deliveredFirst', { at })
    }
    case 'abandoned': {
      const at = formatLogTime(row.ended_at)
      if (isTargetedEndReason(row.end_reason)) return t(`alerts.log.endReason.${row.end_reason}`)
      switch (row.end_reason) {
        case 'snapshot_unreadable':
          return t('alerts.log.desc.abandonedUnreadable')
        case 'type_unregistered':
          return t('alerts.log.desc.abandonedType')
        case 'render_failed':
          return t('alerts.log.desc.abandonedRender')
        case 'rate_limited':
          return t('alerts.log.desc.abandonedRateLimited', { at })
        case 'channel_deleted':
          return t('alerts.log.desc.abandonedDeleted', { at })
        default:
          return t('alerts.log.desc.abandonedMax', { at, max: DELIVERY_MAX_ATTEMPTS, reason: reason() })
      }
    }
    case 'canceled': {
      const at = formatLogTime(row.ended_at)
      if (row.end_reason === 'channel_deleted') return t('alerts.log.desc.canceledDeleted', { at })
      if (row.end_reason === 'channel_disabled') return t('alerts.log.desc.canceledDisabled', { at })
      if (isTargetedEndReason(row.end_reason)) {
        // 取消前已試過的（例如第一次遇到平台錯誤、重送前就被取消）照實寫出次數與最近原因
        const lead = Number(row.attempts) > 0 && row.last_failed_at
          ? t('alerts.log.desc.canceledTried', {
            attempts: row.attempts,
            last_at: formatLogTime(row.last_failed_at),
            reason: reasonText(row.reason_code, row.last_error),
            at,
          })
          : t('alerts.log.desc.canceledAt', { at })
        return `${lead}${t(`alerts.log.endReason.${row.end_reason}`)}`
      }
      return t('alerts.log.desc.canceled')
    }
    default:
      return ''
  }
}
