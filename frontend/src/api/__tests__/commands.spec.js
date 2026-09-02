import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import { getSessionCommands, searchCommands, serializeCommandParams } from '../commands'

describe('commands API methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('exposes all command methods as functions', () => {
    expect(typeof getSessionCommands).toBe('function')
    expect(typeof searchCommands).toBe('function')
  })

  it('getSessionCommands requests GET /sessions/:id/commands', () => {
    getSessionCommands('abc-123')
    expect(requestMock).toHaveBeenCalledWith({
      url: '/sessions/abc-123/commands',
      method: 'get',
    })
  })

  it('searchCommands requests GET /commands with query params', () => {
    const params = {
      keyword: 'rm -rf',
      user_id: 1,
      asset_id: 2,
      start_time: '2026-06-01T00:00:00Z',
      end_time: '2026-06-12T00:00:00Z',
      page: 1,
      page_size: 20,
    }
    searchCommands(params)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/commands',
      method: 'get',
      params,
      paramsSerializer: serializeCommandParams,
    })
  })

  it('searchCommands 帶結果事實篩選四參數', () => {
    const params = {
      source: 'console',
      target_database: 'payments',
      result_status: ['partial', 'effect_unknown'],
      error_code: '42601',
    }
    searchCommands(params)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/commands',
      method: 'get',
      params,
      paramsSerializer: serializeCommandParams,
    })
  })

  it('serializeCommandParams 多選以重複鍵序列化（非 [] 形式）', () => {
    const qs = serializeCommandParams({
      source: 'console',
      result_status: ['ok', 'partial'],
    })
    expect(qs).toBe('source=console&result_status=ok&result_status=partial')
    expect(qs).not.toContain('%5B%5D')
    expect(qs).not.toContain('[]')
  })

  it('serializeCommandParams 略去空值，不把空字串當篩選條件', () => {
    const qs = serializeCommandParams({
      keyword: '',
      target_database: undefined,
      error_code: null,
      result_status: ['', 'blocked'],
      page: 1,
    })
    expect(qs).toBe('result_status=blocked&page=1')
  })
})
