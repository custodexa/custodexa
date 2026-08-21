import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import { getSessionCommands, searchCommands } from '../commands'

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
    })
  })
})
