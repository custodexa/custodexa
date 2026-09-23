import { describe, it, expect } from 'vitest'
import { isEntraIssuer } from '../entraIssuer'

describe('isEntraIssuer', () => {
  it.each([
    ['租戶專屬 v2.0 端點', 'https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0', true],
    ['多租戶 common 端點', 'https://login.microsoftonline.com/common/v2.0', true],
    ['主機大寫', 'https://LOGIN.MicrosoftOnline.COM/tenant-a/v2.0', true],
    ['前後空白', '  https://login.microsoftonline.com/tenant-a/v2.0  ', true],
    ['非 Entra 主機', 'https://idp.example.com', false],
    ['主機只是前綴相同', 'https://login.microsoftonline.com.evil.example/tenant/v2.0', false],
    ['路徑含 Entra 主機字樣', 'https://idp.example.com/login.microsoftonline.com', false],
    ['無法解析的字串', 'https://[::1', false],
    ['空值', '', false],
    ['undefined', undefined, false],
  ])('%s', (_name, issuer, want) => {
    expect(isEntraIssuer(issuer)).toBe(want)
  })
})
