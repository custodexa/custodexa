import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn()
vi.mock('../request', () => ({ default: (...a) => requestMock(...a) }))

import { retryChangeSecretCandidate } from '../changeSecret'
import { retryCredentialRotationMember } from '../credentials'

const moved = {
  response: { status: 409, data: { code: 'CONFLICT_HOST_IDENTITY_MOVED', detail: 'confirmation_pending' } },
}

// 確認主機身分的 409 由元件顯示單一則說明，全域攔截器的 toast 要關掉；其他錯誤與一般重試不受影響
describe('確認主機身分請求：409 不走全域 toast', () => {
  beforeEach(() => requestMock.mockReset())

  it.each([
    ['候選', () => retryChangeSecretCandidate(9, { confirm_host_identity: {} })],
    ['輪替成員', () => retryCredentialRotationMember(1, 2, 3, { confirm_host_identity: {} })],
  ])('%s：帶確認 body 時 skipErrorToast 只接手 CONFLICT_HOST_IDENTITY_MOVED', (_n, call) => {
    call()
    const cfg = requestMock.mock.calls[0][0]
    expect(typeof cfg.skipErrorToast).toBe('function')
    expect(cfg.skipErrorToast(moved)).toBe(true)
    expect(cfg.skipErrorToast({ response: { status: 409, data: { code: 'OTHER' } } })).toBe(false)
    expect(cfg.skipErrorToast({ response: { status: 500, data: {} } })).toBe(false)
    expect(cfg.skipErrorToast(new Error('network'))).toBe(false)
  })

  it.each([
    ['候選', () => retryChangeSecretCandidate(9)],
    ['輪替成員', () => retryCredentialRotationMember(1, 2, 3)],
  ])('%s：一般重試（無 body）維持預設 toast', (_n, call) => {
    call()
    const cfg = requestMock.mock.calls[0][0]
    expect(cfg.skipErrorToast).toBeUndefined()
    expect('data' in cfg).toBe(false)
  })
})
