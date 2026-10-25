import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import { acceptPermissionState, getAuditFailures } from '../auditFailures'

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

  it('acceptPermissionState posts the reason to the super-admin confirmation endpoint', () => {
    acceptPermissionState({ reason: '已核對' })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/audit-failures/permission-state/accept',
      method: 'post',
      data: { reason: '已核對' },
    })
  })
})
