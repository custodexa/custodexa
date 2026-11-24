import { describe, it, expect } from 'vitest'
import { t } from '@/i18n'
import {
  healthStatus,
  backoffAfter,
  remainingAttempts,
  estimateGiveUpAt,
  reasonText,
  deliveryDescription,
  eventName,
  formatLogTime,
} from '../channelDelivery'
import { maskChannelUrl, isSlackDefaultMasked, SLACK_APP_DEFAULT_URL, SLACK_APP_LEGACY_DEFAULT_URL } from '@/constants/notification-channels'

const h = (health, extra = {}) => ({ enabled: true, health, ...extra })

describe('送達狀況標籤', () => {
  it('停用、尚未投遞、送不出去、有放棄、正常', () => {
    expect(healthStatus(h({ last_delivered_at: '2026-11-20T09:00:00Z' }, { enabled: false }))).toBe('disabled')
    expect(healthStatus(h({ abandoned_7d: 0 }))).toBe('none')
    expect(healthStatus(h(null))).toBe('none')
    expect(healthStatus(h({ last_delivered_at: '2026-11-16T01:00:00Z', last_failed_at: '2026-11-20T09:05:00Z', abandoned_7d: 12 }))).toBe('failing')
    expect(healthStatus(h({ last_failed_at: '2026-11-20T09:05:00Z' }))).toBe('failing')
    expect(healthStatus(h({ last_delivered_at: '2026-11-20T09:12:00Z', last_failed_at: '2026-11-19T14:03:00Z', abandoned_7d: 1 }))).toBe('abandoned')
    expect(healthStatus(h({ last_delivered_at: '2026-11-20T09:12:00Z', last_failed_at: '2026-11-17T02:41:00Z', abandoned_7d: 0 }))).toBe('ok')
  })
})

describe('重送推算（與後端退避相同）', () => {
  it('間隔逐次加倍、最長 2 小時；最多再試 = 48 − 已試', () => {
    expect(backoffAfter(1)).toBe(1000)
    expect(backoffAfter(2)).toBe(2000)
    expect(backoffAfter(13)).toBe(4096 * 1000)
    expect(backoffAfter(14)).toBe(2 * 3600 * 1000)
    expect(backoffAfter(40)).toBe(2 * 3600 * 1000)
    expect(remainingAttempts(17)).toBe(31)
    expect(remainingAttempts(60)).toBe(0)
  })

  it('約何時放棄：從下一次嘗試起加上之後每次失敗的間隔', () => {
    const next = Date.parse('2026-11-20T11:05:00Z')
    // 已試 17 次：第 18 到 47 次失敗後各再等 2 小時，共 30 段 = 60 小時
    expect(estimateGiveUpAt(17, '2026-11-20T11:05:00Z')).toBe(next + 60 * 3600 * 1000)
    expect(estimateGiveUpAt(47, '2026-11-20T11:05:00Z')).toBe(next)
    expect(estimateGiveUpAt(3, null)).toBeNull()
  })
})

describe('原因句子', () => {
  it('依代碼選句子，HTTP 狀態碼與平台錯誤碼取自已遮蔽的原文', () => {
    expect(reasonText('http_404', 'HTTP 404')).toBe(t('alerts.deliveryReason.http404'))
    expect(reasonText('http_5xx', 'HTTP 503 Service Unavailable')).toBe(t('alerts.deliveryReason.http5xx', { status: '503' }))
    expect(reasonText('slack_other', 'platform error: weird_code')).toBe(t('alerts.deliveryReason.slackOther', { code: 'weird_code' }))
    expect(reasonText('', '')).toBe(t('alerts.deliveryReason.unknown'))
    // 未知代碼不顯示原文
    expect(reasonText('mystery', 'secret-ish text')).not.toContain('secret-ish')
  })
})

describe('投遞紀錄說明句', () => {
  it('等待中只有延後時才寫句子；已送達分第一次與第 n 次；已取消依原因', () => {
    // 延後句只看 throttled_since，不以下次嘗試時間推定
    expect(deliveryDescription({ state: 'pending', next_attempt_at: '2026-11-20T10:04:00Z', throttled_since: null })).toBe('')
    expect(deliveryDescription({ state: 'pending', next_attempt_at: '2026-11-20T09:29:00Z', throttled_since: '2026-11-20T09:20:00Z' }))
      .toBe(t('alerts.log.desc.pending', { until: formatLogTime('2026-11-20T09:29:00Z') }))
    expect(deliveryDescription({ state: 'delivered', attempts: 1, delivered_at: '2026-11-20T09:12:00Z' })).toBe(t('alerts.log.desc.deliveredFirst', { at: formatLogTime('2026-11-20T09:12:00Z') }))
    expect(deliveryDescription({ state: 'canceled', end_reason: 'channel_disabled', ended_at: '2026-11-20T09:32:00Z' })).toBe(t('alerts.log.desc.canceledDisabled', { at: formatLogTime('2026-11-20T09:32:00Z') }))
    expect(deliveryDescription({ state: 'abandoned', end_reason: 'snapshot_unreadable' })).toBe(t('alerts.log.desc.abandonedUnreadable'))
    expect(deliveryDescription({ state: 'retrying', attempts: 12, reason_code: 'channel_unreadable', next_attempt_at: '2026-11-20T09:48:00Z', last_failed_at: '2026-11-20T09:14:00Z' })).toContain('36')
  })

  it('事件名稱：系統安全告警用告警類型名稱、系統事件用名稱表、指令告警不顯示、查無時標示無法顯示', () => {
    expect(eventName({ category: 'system_security_alert', event_key: 'notification_channel_changed' })).toBe(t('systemAlerts.types.notification_channel_changed.name'))
    expect(eventName({ category: 'system_event', event_key: 'daily_review_overdue' })).toBe(t('alerts.log.event.daily_review_overdue'))
    expect(eventName({ category: 'command_alert', event_key: '' })).toBe('')
    expect(eventName({ category: 'system_event', event_key: 'no_such_event' })).toBe(t('alerts.log.eventUnknown'))
  })
})

describe('網址遮罩（與後端列表相同的規則）', () => {
  it('官方位址的遮罩值可辨認：基底與舊的完整方法網址都算', () => {
    expect(SLACK_APP_DEFAULT_URL).toBe('https://slack.com/api')
    expect(maskChannelUrl(SLACK_APP_DEFAULT_URL)).toBe('https://slack.com/****/api')
    expect(maskChannelUrl(SLACK_APP_LEGACY_DEFAULT_URL)).toBe('https://slack.com/****sage')
    expect(isSlackDefaultMasked('https://slack.com/****sage')).toBe(true)
    expect(maskChannelUrl('https://example.com/')).toBe('https://example.com')
    expect(maskChannelUrl('not a url')).toBe('****')
    expect(isSlackDefaultMasked(maskChannelUrl(SLACK_APP_DEFAULT_URL))).toBe(true)
    expect(isSlackDefaultMasked('https://relay.example.com/****/api')).toBe(false)
  })
})
