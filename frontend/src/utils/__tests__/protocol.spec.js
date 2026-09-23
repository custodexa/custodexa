import { describe, test, it, expect } from 'vitest'
import {
  isTextTerminal,
  isDatabaseProtocol,
  isDBConsoleProtocol,
  isPasswordOnlyProtocol,
  PROTOCOL_DEFAULT_PORTS,
  protocolKind,
  protocolKindText,
  protocolKindShortText,
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

describe('isDBConsoleProtocol（查詢主控台的協議閘）', () => {
  test.each(['mysql', 'postgres', 'mssql'])('%s 支援主控台', (p) => {
    expect(isDBConsoleProtocol(p)).toBe(true)
  })

  test.each(['redis', 'ssh', 'rdp', 'vnc', 'k8s', '', undefined])(
    '%s 不支援主控台',
    (p) => {
      expect(isDBConsoleProtocol(p)).toBe(false)
    }
  )

  it('是 isDatabaseProtocol 的真子集（redis 為差集）', () => {
    const dbOnly = ['mysql', 'postgres', 'redis', 'mssql'].filter(
      (p) => isDatabaseProtocol(p) && !isDBConsoleProtocol(p)
    )
    expect(dbOnly).toEqual(['redis'])
  })
})

describe('共用協議人話映射', () => {
  it.each([['ssh', 'terminal', '終端'], ['postgres', 'database', '資料庫'], ['rdp', 'desktop', '遠端桌面']])('%s → %s', (code, kind, text) => {
    expect(protocolKind(code)).toBe(kind)
    expect(protocolKindShortText(code)).toBe(text)
    expect(protocolKindText(code)).toBe(`${text}（${code.toUpperCase()}）`)
  })
  it('大小寫分類一致，未知碼維持原樣、空值安全', () => {
    expect(protocolKind('SSH')).toBe('terminal')
    expect(protocolKind('telnet')).toBeNull()
    expect(protocolKind('__proto__')).toBeNull()
    expect(protocolKindText('telnet')).toBe('telnet')
    expect(protocolKindShortText('telnet')).toBe('telnet')
    expect(protocolKindText(undefined)).toBe('')
  })
})
