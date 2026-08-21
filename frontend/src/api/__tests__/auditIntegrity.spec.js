import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import { verifyAuditIntegrity } from '../auditIntegrity'

describe('auditIntegrity API methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('verifyAuditIntegrity requests GET /audit-integrity/verify with date range', () => {
    const params = { from: '2026-07-07', to: '2026-07-13' }
    verifyAuditIntegrity(params)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/audit-integrity/verify',
      method: 'get',
      params,
    })
  })
})
