import { describe, test, it, expect } from 'vitest'
import {
  isTextTerminal,
  isDatabaseProtocol,
  isPasswordOnlyProtocol,
  PROTOCOL_DEFAULT_PORTS,
  protocolTagType,
} from '../protocol'

describe('protocol 分類（與後端 model.ProtocolType 對齊）', () => {
  test.each(['ssh', 'mysql', 'postgres', 'redis', 'mssql', 'k8s'])(
    '%s 屬文字終端類（走審計鏈）',
    (p) => {
      expect(isTextTerminal(p)).toBe(true)
    }
  )

  test.each(['rdp', 'vnc'])('%s 非文字終端類（走 guacd）', (p) => {
    expect(isTextTerminal(p)).toBe(false)
  })

  test('未知協議不屬文字終端類', () => {
    expect(isTextTerminal('telnet')).toBe(false)
    expect(isTextTerminal(undefined)).toBe(false)
  })

  test.each(['mysql', 'postgres', 'redis', 'mssql'])('%s 屬資料庫 CLI 協議', (p) => {
    expect(isDatabaseProtocol(p)).toBe(true)
  })

  test.each(['ssh', 'rdp', 'vnc', 'k8s'])('%s 非資料庫 CLI 協議', (p) => {
    expect(isDatabaseProtocol(p)).toBe(false)
  })

  test.each(['vnc', 'redis', 'k8s'])('%s 免使用者名稱', (p) => {
    expect(isPasswordOnlyProtocol(p)).toBe(true)
  })

  test.each(['ssh', 'rdp', 'mysql', 'postgres', 'mssql'])('%s 需使用者名稱', (p) => {
    expect(isPasswordOnlyProtocol(p)).toBe(false)
  })

  // 反面守衛（刻意）：mssql 若被歸為「僅密碼」，表單會藏掉使用者名稱欄位，
  // sqlcmd 缺 -U 就不索取密碼，後端 PTY 密碼注入永不觸發、連線無聲斷掉
  test('mssql 絕不可歸類為僅密碼協議', () => {
    expect(isPasswordOnlyProtocol('mssql')).toBe(false)
  })

  test('八協議皆有預設埠', () => {
    expect(PROTOCOL_DEFAULT_PORTS).toEqual({
      ssh: 22,
      rdp: 3389,
      vnc: 5900,
      mysql: 3306,
      postgres: 5432,
      redis: 6379,
      mssql: 1433,
      k8s: 6443,
    })
  })
})

describe('protocolTagType（ux-consistency 全站唯一色映射）', () => {
  it('maps each protocol to its tag type', () => {
    expect(protocolTagType('ssh')).toBe('success')
    expect(protocolTagType('rdp')).toBe('primary')
    expect(protocolTagType('vnc')).toBe('warning')
    expect(protocolTagType('mysql')).toBe('info')
    expect(protocolTagType('postgres')).toBe('info')
    expect(protocolTagType('redis')).toBe('info')
    expect(protocolTagType('mssql')).toBe('info')
    expect(protocolTagType('k8s')).toBe('info')
  })

  it('is case-insensitive and falls back to info', () => {
    expect(protocolTagType('SSH')).toBe('success')
    expect(protocolTagType('telnet')).toBe('info')
    expect(protocolTagType('')).toBe('info')
    expect(protocolTagType(undefined)).toBe('info')
  })
})
