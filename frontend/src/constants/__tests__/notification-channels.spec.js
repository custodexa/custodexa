// 通道語系值域前後端雙向完備性。
// 沿用 audit-enums.spec.js 的金標準模式：硬拷對照組＋直讀後端 Go 原始碼雙向斷言。
// docker-compose.dev.yml 已為 frontend 掛載 ./backend/internal/model（唯讀），
// 無掛載的環境該案例 skip（測試清單可見 skipped，非靜默通過）。
import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  CHANNEL_LANGUAGE_VALUES,
  CHANNEL_LANGUAGE_DEFAULT,
  channelLanguageLabel,
} from '../notification-channels'
import { SUPPORTED_LOCALES } from '@/i18n'

// model.ValidNotificationChannelLanguage 的三值（嚴格匹配，DB 另有 CHECK）
const BACKEND_LANGUAGES = ['zh-TW', 'en-US', 'ja-JP']

const BACKEND_SOURCE_PATHS = [
  join(process.cwd(), '../backend/internal/model/notification_channel.go'),
  join(process.cwd(), '../../backend/internal/model/notification_channel.go'),
  '/repo/backend/internal/model/notification_channel.go',
]
const backendSourcePath = BACKEND_SOURCE_PATHS.find((p) => existsSync(p))

// 抽 `NotificationChannelLanguageXxx = "zh-TW"` 的值；Default 是別名（指向
// 既有常數而非字面量），不會被本正則收進來，故不需排除
const parseBackendLanguages = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*NotificationChannelLanguage\w+\s*=\s*"([\w-]+)"/gm)].map((m) => m[1])
  ),
]

// 抽 `NotificationChannelLanguageDefault = NotificationChannelLanguageZhTW` 的別名尾碼
const parseBackendDefaultAlias = (src) =>
  src.match(/NotificationChannelLanguageDefault\s*=\s*NotificationChannelLanguage(\w+)/)?.[1]

describe('通知通道語系值域（前後端一致）', () => {
  it('CHANNEL_LANGUAGE_VALUES 與後端三值互為全集', () => {
    expect([...CHANNEL_LANGUAGE_VALUES].sort()).toEqual([...BACKEND_LANGUAGES].sort())
  })

  it('預設值為 zh-TW，且在值域內', () => {
    expect(CHANNEL_LANGUAGE_DEFAULT).toBe('zh-TW')
    expect(CHANNEL_LANGUAGE_VALUES).toContain(CHANNEL_LANGUAGE_DEFAULT)
  })

  it('每個值都有原生名標籤，未知值原樣回傳', () => {
    for (const v of CHANNEL_LANGUAGE_VALUES) {
      expect(channelLanguageLabel(v), `${v} 缺標籤`).toBeTruthy()
      expect(channelLanguageLabel(v)).not.toBe(v)
    }
    expect(channelLanguageLabel('fr-FR')).toBe('fr-FR')
    expect(channelLanguageLabel(undefined)).toBe(undefined)
  })

  it('與 UI 支援語系集合一致（三語齊備的前提）', () => {
    expect([...CHANNEL_LANGUAGE_VALUES].sort()).toEqual([...SUPPORTED_LOCALES].sort())
  })

  it.skipIf(!backendSourcePath)(
    '值域與後端原始碼常數雙向等同（直讀 notification_channel.go）',
    () => {
      const src = readFileSync(backendSourcePath, 'utf8')
      const parsed = parseBackendLanguages(src)
      // 正則失效（後端改寫法）時集合會空掉而「意外全綠」——先鎖下界
      expect(parsed.length, '未從後端原始碼抽到語系常數（正則失效？）').toBeGreaterThanOrEqual(3)
      expect(parsed.sort()).toEqual([...CHANNEL_LANGUAGE_VALUES].sort())
      expect(parsed.sort()).toEqual([...BACKEND_LANGUAGES].sort())
      // 後端預設值改別名（例：改指 EnUS）時，前端預設必須跟著改
      expect(parseBackendDefaultAlias(src)).toBe('ZhTW')
    }
  )
})
