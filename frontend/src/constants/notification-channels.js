/**
 * 通知通道枚舉。
 * 值域硬拷後端 model/notification_channel.go 的 NotificationChannelLanguage* 常數，
 * 由 notification-channels.spec.js 直讀 Go 原始碼雙向斷言（audit-enums 金標準模式）。
 *
 * 語系選單標籤刻意不查譯：沿用 i18n 的 LOCALE_LABELS（各語言自身文字），
 * 與右上角語言切換選單同一慣例——「這則 Slack 訊息要用哪種語言」的選項
 * 應以該語言自身呈現，不隨介面語言變動。
 */
import { LOCALE_LABELS } from '@/i18n'

/**
 * 通道型別。值域＝後端 audit 模組的通道型別登錄，由後端守衛
 * TestChannelTypeRegistryMatchesConstraintsAndForm 直讀本檔雙向比對（兩條資料庫型別約束一併核對）。
 * 通道表單的型別選項以本陣列產生；標籤鍵見 CHANNEL_TYPE_LABEL_KEYS。
 */
export const CHANNEL_TYPE_VALUES = ['webhook', 'slack', 'slack_app']

export const CHANNEL_TYPE_LABEL_KEYS = {
  webhook: 'alerts.channelTypeWebhook',
  slack: 'alerts.channelTypeSlack',
  slack_app: 'alerts.channelTypeSlackApp',
}

/** 型別選單每一項的第二行說明（與後端型別描述的 HelpKey 同名） */
export const CHANNEL_TYPE_HELP_KEYS = {
  webhook: 'alerts.channelTypeWebhookHelp',
  slack: 'alerts.channelTypeSlackHelp',
  slack_app: 'alerts.channelTypeSlackAppHelp',
}

/** 通道列表「類型」欄的短名 */
export const CHANNEL_TYPE_SHORT_KEYS = {
  webhook: 'alerts.channelTypeWebhookShort',
  slack: 'alerts.channelTypeSlackShort',
  slack_app: 'alerts.channelTypeSlackAppShort',
}

/** slack_app 的預設網址（Slack API 基底；送出時由後端接上方法名），與後端型別描述的 DefaultURL 相同 */
export const SLACK_APP_DEFAULT_URL = 'https://slack.com/api'

/**
 * 宣告能以個人為對象的型別（可開啟「對個人派送審核類通知」）。與後端型別描述的 can_target_user 相同，
 * 本版只有 Slack 應用程式；資料庫另有 CHECK 只允許此型別開啟。
 */
export const CHANNEL_TYPES_TARGET_USER = ['slack_app']

/**
 * 對個人派送允許清單的預設主機（Slack 官方 API 主機，比對完整主機名）。部署者另外加入的主機
 * 畫面無從得知：已保存的網址由伺服端回傳 direct_message_url_allowed，表單上改了網址時只有這個
 * 主機能確定仍在清單內。
 */
export const SLACK_DM_DEFAULT_HOST = 'slack.com'

/** 網址的主機名稱（小寫）；解析不了回空字串 */
export const urlHostOf = (raw) => {
  try {
    return new URL(raw).hostname.toLowerCase()
  } catch {
    return ''
  }
}

/** 早期以完整方法網址建立的 slack_app 通道保存的值；同樣視為官方位址 */
export const SLACK_APP_LEGACY_DEFAULT_URL = 'https://slack.com/api/chat.postMessage'

/** 通道網址解不開時，列表回應的遮罩值 */
export const CHANNEL_URL_UNREADABLE = '****'

/**
 * 以與後端列表相同的規則遮罩網址（保留協定、主機與路徑最後 4 字）。
 * 只用來判斷列表上的遮罩值是否等於預設網址的遮罩值，不用來顯示。
 */
export const maskChannelUrl = (plain) => {
  let parsed
  try {
    parsed = new URL(plain)
  } catch {
    return CHANNEL_URL_UNREADABLE
  }
  if (!parsed.host) return CHANNEL_URL_UNREADABLE
  const rest = plain.slice(parsed.protocol.length + 2 + parsed.host.length)
  if (rest === '' || rest === '/') return `${parsed.protocol}//${parsed.host}`
  return `${parsed.protocol}//${parsed.host}/****${rest.slice(-4)}`
}

/** 列表上的遮罩網址是否就是 Slack 官方位址（基底與舊的完整方法網址都算） */
export const isSlackDefaultMasked = (masked) =>
  masked === maskChannelUrl(SLACK_APP_DEFAULT_URL) || masked === maskChannelUrl(SLACK_APP_LEGACY_DEFAULT_URL)

/** 機器人 token 的格式（前端就近提示；後端另有相同規則） */
export const SLACK_BOT_TOKEN_PATTERN = /^xoxb-\S*$/

/** 頻道 ID 的格式與長度上限（與後端相同） */
export const SLACK_TARGET_PATTERN = /^[A-Za-z0-9]+$/
export const SLACK_TARGET_MAX_LEN = 64

/** 每則通知的嘗試次數上限與退避參數（與後端投遞程序相同，用於推算「最多再試」與「約何時放棄」） */
export const DELIVERY_MAX_ATTEMPTS = 48
export const DELIVERY_BACKOFF_BASE_MS = 1000
export const DELIVERY_BACKOFF_MAX_MS = 2 * 60 * 60 * 1000

export const CHANNEL_LANGUAGE_VALUES = ['zh-TW', 'en-US', 'ja-JP']

export const CHANNEL_LANGUAGE_DEFAULT = 'zh-TW'

/** 通道語系原生名；未知值原樣回傳（後端加值而前端未跟上時不吞資訊） */
export const channelLanguageLabel = (v) => LOCALE_LABELS[v] || v

/**
 * 通道推送門檻（最低推送等級），由低到高：low＝全部告警（預設）、medium＝中、高等級、
 * high＝只有高等級。值域＝後端告警等級三值，由 notification-channels.spec.js 直讀
 * model/alert_rule.go 雙向斷言。只作用於告警推送；系統事件與測試發送不受影響。
 */
export const CHANNEL_MIN_SEVERITY_VALUES = ['low', 'medium', 'high']

export const CHANNEL_MIN_SEVERITY_DEFAULT = 'low'
