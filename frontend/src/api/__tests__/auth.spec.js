import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import {
  login,
  verifyMFA,
  getMFASetup,
  enableMFA,
  disableMFA,
} from '../auth'
import { adminDisableMFA } from '../user'

describe('auth API MFA methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('exposes all MFA methods as functions', () => {
    expect(typeof login).toBe('function')
    expect(typeof verifyMFA).toBe('function')
    expect(typeof getMFASetup).toBe('function')
    expect(typeof enableMFA).toBe('function')
    expect(typeof disableMFA).toBe('function')
    expect(typeof adminDisableMFA).toBe('function')
  })

  it('verifyMFA posts pending token and code to /auth/mfa/verify', () => {
    verifyMFA({ pending_token: 'pending-jwt', code: '123456' })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/auth/mfa/verify',
      method: 'post',
      data: { pending_token: 'pending-jwt', code: '123456' },
    })
  })

  it('getMFASetup posts to /auth/mfa/setup (setup 有副作用，非冪等讀取)', () => {
    getMFASetup()
    expect(requestMock).toHaveBeenCalledWith({
      url: '/auth/mfa/setup',
      method: 'post',
    })
  })

  it('enableMFA posts code to /auth/mfa/enable', () => {
    enableMFA({ code: '654321' })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/auth/mfa/enable',
      method: 'post',
      data: { code: '654321' },
    })
  })

  it('disableMFA posts password to /auth/mfa/disable', () => {
    disableMFA({ password: 'secret-pass' })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/auth/mfa/disable',
      method: 'post',
      data: { password: 'secret-pass' },
    })
  })

  it('adminDisableMFA posts to /users/:id/mfa/disable', () => {
    adminDisableMFA(42)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/users/42/mfa/disable',
      method: 'post',
    })
  })
})
