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

export const CHANNEL_LANGUAGE_VALUES = ['zh-TW', 'en-US', 'ja-JP']

export const CHANNEL_LANGUAGE_DEFAULT = 'zh-TW'

/** 通道語系原生名；未知值原樣回傳（後端加值而前端未跟上時不吞資訊） */
export const channelLanguageLabel = (v) => LOCALE_LABELS[v] || v
