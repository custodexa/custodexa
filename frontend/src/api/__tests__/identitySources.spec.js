import { describe, it, expect } from 'vitest'
import {
  isNotImplemented,
  errorCode,
  CODE_LDAP_DIRECTORY_NOT_FOUND,
} from '../identitySources'

/**
 * 降級判定的分界。
 *
 * 這一支的失敗方向是**靜默的**：把「路由存在且回答了資源不存在」誤判成
 * 「後端尚未提供」，畫面會告訴管理者系統還沒做這塊功能，而實際上只是還沒設定。
 * 兩者的可操作結論相反，故以測試釘住分界。
 */
const axiosError = (status, data) => ({ response: { status, data } })

describe('isNotImplemented', () => {
  it('路由不存在（框架回純文字、無機器碼）視為端點尚未提供', () => {
    expect(isNotImplemented(axiosError(404, '404 page not found'))).toBe(true)
    expect(isNotImplemented(axiosError(405, ''))).toBe(true)
  })

  it('帶機器碼的 404 是答案而非缺席', () => {
    expect(
      isNotImplemented(axiosError(404, { code: CODE_LDAP_DIRECTORY_NOT_FOUND, error: '不存在' }))
    ).toBe(false)
  })

  it('機器碼包在 error 物件內時同樣認得', () => {
    expect(isNotImplemented(axiosError(404, { error: { code: 'NOTFOUND_X' } }))).toBe(false)
  })

  it('其餘狀態一律是真的錯誤', () => {
    for (const status of [401, 403, 422, 500, 503]) {
      expect(isNotImplemented(axiosError(status, { code: 'ANY' }))).toBe(false)
    }
    expect(isNotImplemented({})).toBe(false)
  })
})

describe('errorCode', () => {
  it('取得頂層與巢狀兩種外框的機器碼', () => {
    expect(errorCode(axiosError(409, { code: 'A' }))).toBe('A')
    expect(errorCode(axiosError(409, { error: { code: 'B' } }))).toBe('B')
  })

  it('沒有機器碼時回空字串，不回 undefined', () => {
    expect(errorCode(axiosError(404, '404 page not found'))).toBe('')
    expect(errorCode(axiosError(404, { error: '純文字訊息' }))).toBe('')
    expect(errorCode({})).toBe('')
  })
})
