import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import { getAuditFailures } from '../auditFailures'

describe('auditFailures API methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('getAuditFailures requests GET /audit-failures with pagination params', () => {
    const params = { page: 1, page_size: 20 }
    getAuditFailures(params)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/audit-failures',
      method: 'get',
      params,
    })
  })
})
