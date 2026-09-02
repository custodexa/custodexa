import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))
const capabilitiesMock = vi.fn()

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))
vi.mock('../files', () => ({
  getTransferCapabilities: (...args) => capabilitiesMock(...args),
}))

import {
  DB_CONSOLE_WS_PATH,
  EXPORT_CAPABILITY,
  dbConsoleSocketUrl,
  resultExportPath,
  downloadResultCsv,
  exportFilename,
  allowsExport,
  fetchExportCapability,
} from '../dbConsole'

describe('dbConsole API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('WS 位址只帶一次性連線票，無 JWT 與憑證欄位', () => {
    const url = new URL(dbConsoleSocketUrl('ct-test'))
    expect(url.pathname).toBe(DB_CONSOLE_WS_PATH)
    expect(url.searchParams.get('connect_token')).toBe('ct-test')
    expect(url.searchParams.has('token')).toBe(false)
    expect(url.searchParams.has('password')).toBe(false)
    expect(url.searchParams.has('username')).toBe(false)
    expect(url.searchParams.has('asset_id')).toBe(false)
    expect([...url.searchParams.keys()]).toEqual(['connect_token'])
  })

  it('WS scheme 依頁面協定推導（http→ws、https→wss）', () => {
    expect(dbConsoleSocketUrl('t')).toMatch(/^ws:\/\//)
    const original = window.location.protocol
    Object.defineProperty(window.location, 'protocol', {
      value: 'https:',
      configurable: true,
    })
    expect(dbConsoleSocketUrl('t')).toMatch(/^wss:\/\//)
    Object.defineProperty(window.location, 'protocol', {
      value: original,
      configurable: true,
    })
  })

  it('匯出位址以 event_id 定址，set 走查詢參數', () => {
    expect(resultExportPath(42, '01J8ZXAMPLE0000000000000AA')).toBe(
      '/db-console/sessions/42/results/01J8ZXAMPLE0000000000000AA/export'
    )
    downloadResultCsv(42, '01J8ZXAMPLE0000000000000AA', 2)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/db-console/sessions/42/results/01J8ZXAMPLE0000000000000AA/export',
      method: 'get',
      params: { set: 2, format: 'csv' },
      responseType: 'blob',
      skipErrorToast: true,
    })
  })

  it('匯出位址對識別字做百分比編碼', () => {
    expect(resultExportPath('a/b', 'x y')).toBe(
      '/db-console/sessions/a%2Fb/results/x%20y/export'
    )
  })

  it('匯出檔名含資產名、序號、結果集與時戳，且折去路徑分隔', () => {
    const name = exportFilename({
      assetName: 'prod/db 01',
      seq: 3,
      setIndex: 1,
      at: new Date(2026, 8, 2, 14, 5, 6),
    })
    expect(name).toBe('prod_db_01-3-1-20260902-140506.csv')
  })

  it('能力查譯：未取得視為可用，false 才停用', () => {
    expect(allowsExport(null)).toBe(true)
    expect(allowsExport(undefined)).toBe(true)
    expect(allowsExport({})).toBe(true)
    expect(allowsExport({ [EXPORT_CAPABILITY]: true })).toBe(true)
    expect(allowsExport({ [EXPORT_CAPABILITY]: false })).toBe(false)
  })

  it('重抓能力投影：成功回布林、查詢失敗回 null（呼叫端保留上一次值）', async () => {
    capabilitiesMock.mockResolvedValueOnce({ capabilities: { file_download: false } })
    await expect(fetchExportCapability(7)).resolves.toBe(false)
    expect(capabilitiesMock).toHaveBeenCalledWith(7)

    capabilitiesMock.mockRejectedValueOnce(new Error('boom'))
    await expect(fetchExportCapability(7)).resolves.toBeNull()

    capabilitiesMock.mockResolvedValueOnce({})
    await expect(fetchExportCapability(7)).resolves.toBeNull()

    await expect(fetchExportCapability(null)).resolves.toBeNull()
  })
})
