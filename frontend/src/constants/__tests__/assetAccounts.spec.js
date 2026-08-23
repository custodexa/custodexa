// 資產帳號值域與導出：
// 值域硬拷後端（`@ALL` 對應 model.AccountScopeAll）；憑證型別為前端導出枚舉，
// 必須窮盡 has_password × has_private_key 四種組合。
import { describe, it, expect } from 'vitest'
import {
  ACCOUNT_SCOPE_ALL,
  ACCOUNT_CREDENTIAL_VALUES,
  ACCOUNT_CREDENTIAL_META,
  isAllAccountScope,
  accountCredentialType,
  accountCredentialLabel,
  accountCredentialTagType,
} from '../assetAccounts'

describe('帳號範圍值域', () => {
  it('全帳號別名與後端 model.AccountScopeAll 一致', () => {
    expect(ACCOUNT_SCOPE_ALL).toBe('@ALL')
  })

  it('缺欄／空陣列／含 @ALL 皆視為全部帳號（與 AccountScope.IsAll 同語義）', () => {
    expect(isAllAccountScope(undefined)).toBe(true)
    expect(isAllAccountScope(null)).toBe(true)
    expect(isAllAccountScope([])).toBe(true)
    expect(isAllAccountScope(['@ALL'])).toBe(true)
    expect(isAllAccountScope(['app', '@ALL'])).toBe(true)
  })

  it('具名清單不是全部帳號', () => {
    expect(isAllAccountScope(['app'])).toBe(false)
    expect(isAllAccountScope(['app', 'root'])).toBe(false)
  })
})

describe('憑證型別導出', () => {
  it('值域窮盡兩布林的四種組合且每值皆有 META', () => {
    expect(ACCOUNT_CREDENTIAL_VALUES).toEqual(['password', 'private_key', 'both', 'none'])
    for (const v of ACCOUNT_CREDENTIAL_VALUES) {
      expect(ACCOUNT_CREDENTIAL_META[v]).toBeTruthy()
      expect(typeof ACCOUNT_CREDENTIAL_META[v].tagType).toBe('string')
    }
  })

  it.each([
    [{ has_password: true, has_private_key: true }, 'both'],
    [{ has_password: false, has_private_key: true }, 'private_key'],
    [{ has_password: true, has_private_key: false }, 'password'],
    [{ has_password: false, has_private_key: false }, 'none'],
    [{}, 'none'],
    [undefined, 'none'],
  ])('%o 導出 %s', (account, expected) => {
    expect(accountCredentialType(account)).toBe(expected)
  })

  it('label 走 locale（zh-TW 為源）而非硬編碼', () => {
    expect(accountCredentialLabel({ has_password: true })).toBe('密碼')
    expect(accountCredentialLabel({ has_private_key: true })).toBe('私鑰')
    expect(accountCredentialLabel({ has_password: true, has_private_key: true })).toBe('密碼＋私鑰')
    expect(accountCredentialLabel({})).toBe('未設定')
  })

  it('零憑證帳號用 info 而非 danger（合法狀態非錯誤）', () => {
    expect(accountCredentialTagType({})).toBe('info')
  })
})
