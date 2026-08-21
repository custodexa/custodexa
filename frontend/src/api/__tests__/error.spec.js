import { describe, it, expect } from 'vitest'
import { resolveApiError } from '../error'

// i18n 由 setupFiles 全域注入並在每測前重設 zh-TW（見 test setup）。

describe('resolveApiError — 三層降級', () => {
  it('第一層：合法 code 有譯文 → 顯示當前語言譯文', () => {
    expect(resolveApiError({ code: 'AUTH_UNAUTHENTICATED' }, 401)).toBe('未認證')
  })

  it('第一層：帶 params 的 code → 語義 ID 經 enum 查譯後插值', () => {
    expect(
      resolveApiError({ code: 'VALIDATION_INVALID_ID', params: { resource: 'asset' } }, 400)
    ).toBe('無效的資產 ID')
  })

  it('第二層：code 不符 grammar → 退回後端 error', () => {
    expect(resolveApiError({ code: 'bad.code', error: '後端訊息' }, 400)).toBe('後端訊息')
  })

  it('第二層：code 合法但無譯文（未登記）→ 退回後端 error', () => {
    expect(
      resolveApiError({ code: 'TOTALLY_UNKNOWN_CODE', error: '後端訊息' }, 400)
    ).toBe('後端訊息')
  })

  it('第二層：無 code → 退回後端 error', () => {
    expect(resolveApiError({ error: '純後端訊息' }, 409)).toBe('純後端訊息')
  })

  it('第三層：非字串 error（物件）→ 不外洩、走通用語', () => {
    const msg = resolveApiError({ error: { nested: 'x' } }, 500)
    expect(msg).toBe('請求失敗 (500)')
    expect(msg).not.toContain('nested')
  })

  it('第三層：空白字串 error → 通用語（不顯示空白）', () => {
    expect(resolveApiError({ error: '   ' }, 502)).toBe('請求失敗 (502)')
  })

  it('第三層：呼叫端專屬 fallback 優先於通用語', () => {
    expect(resolveApiError({}, 400, '登入失敗，請稍後再試')).toBe('登入失敗，請稍後再試')
  })

  it('code 命中時無視 fallback（第一層優先）', () => {
    expect(
      resolveApiError({ code: 'AUTH_UNAUTHENTICATED' }, 401, '不該出現的 fallback')
    ).toBe('未認證')
  })
})
