import { describe, it, expect, afterEach } from 'vitest'
import { resolveApiError } from '../error'
import { setLanguage } from '@/i18n'

// 後端拒絕形狀收斂後，前端只依狀態與碼顯示通用譯文。

const RETIRED_CODES = [
  'AUTH_ROLE_REQUIRED',
  'AUTH_TAG_LIST_PRIVILEGED_ONLY',
  'AUTH_TAG_GOVERNANCE_ADMIN_ONLY',
  'AUTH_SESSION_TERMINATE_ADMIN_ONLY',
  'AUTH_MONITOR_ROLE_REQUIRED',
  'AUTH_APPROVER_REQUIRED',
  'AUTH_ROLE_ASSIGNMENT_FORBIDDEN',
]

const GENERIC = {
  'zh-TW': '權限不足',
  'en-US': 'Insufficient permission',
  'ja-JP': '権限が不足しています',
}

const BATCH = {
  'zh-TW': '3 筆項目無法操作',
  'en-US': '3 items cannot be operated on',
  'ja-JP': '3 件の項目を操作できません',
}

afterEach(() => setLanguage('zh-TW'))

describe('403 單一拒絕形狀', () => {
  for (const [lang, text] of Object.entries(GENERIC)) {
    it(`AUTH_PERMISSION_DENIED 在 ${lang} 顯示通用譯文`, () => {
      setLanguage(lang)
      expect(resolveApiError({ code: 'AUTH_PERMISSION_DENIED', error: 'x' }, 403)).toBe(text)
    })
  }
})

describe('批次不可操作碼', () => {
  for (const [lang, text] of Object.entries(BATCH)) {
    it(`NOTFOUND_BATCH_ITEMS_UNAVAILABLE count=3 在 ${lang} 插值`, () => {
      setLanguage(lang)
      expect(
        resolveApiError({ code: 'NOTFOUND_BATCH_ITEMS_UNAVAILABLE', params: { count: 3 } }, 404)
      ).toBe(text)
    })
  }
})

describe('原始碼不依賴被收斂的欄位與碼', () => {
  const sources = import.meta.glob(
    [
      '/src/**/*.{js,vue}',
      '!/src/**/__tests__/**',
      '!/src/**/*.spec.js',
      '!/src/i18n/locales/**',
    ],
    { query: '?raw', import: 'default', eager: true }
  )

  it('掃描到足量的原始檔', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50)
  })

  it('不含 required_permission', () => {
    const hits = Object.entries(sources)
      .filter(([, src]) => src.includes('required_permission'))
      .map(([f]) => f)
    expect(hits).toEqual([])
  })

  it('不含 7 個退役碼', () => {
    const hits = []
    for (const [f, src] of Object.entries(sources)) {
      for (const code of RETIRED_CODES) if (src.includes(code)) hits.push(`${f}:${code}`)
    }
    expect(hits).toEqual([])
  })
})
