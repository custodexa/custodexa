import { describe, it, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))

import {
  copyRoleDefinition,
  createRoleDefinition,
  deleteRoleDefinition,
  updateRoleDefinition,
  roleErrorCode,
  ROLE_ERROR_NAME_CONFLICT,
  ROLE_ERROR_VERSION_CONFLICT,
} from '@/api/roleDefinitions'

const err = (code) => ({ response: { status: 409, data: { error: 'x', code } } })
const envelopeErr = (code) => ({ response: { status: 409, data: { error: { code } } } })

describe('角色寫入 API 的全域提示抑制', () => {
  beforeEach(() => {
    h.request.mockReset()
    h.request.mockResolvedValue({})
  })

  it('兩個衝突碼的常數值', () => {
    expect(ROLE_ERROR_NAME_CONFLICT).toBe('ROLE_DEFINITION_CONFLICT')
    expect(ROLE_ERROR_VERSION_CONFLICT).toBe('ROLE_DEFINITION_VERSION_CONFLICT')
  })

  it('新增、修改、刪除、複製：名稱重複、版本過期、使用中交給頁面，其餘照常提示', async () => {
    await createRoleDefinition({ name: 'a', description: '', permissions: [] })
    await updateRoleDefinition(1, { name: 'a', description: '', permissions: [], expectedVersion: 2 })
    await deleteRoleDefinition(1, 2)
    await copyRoleDefinition(1, 'b')
    expect(h.request).toHaveBeenCalledTimes(4)
    for (const [cfg] of h.request.mock.calls) {
      const skip = cfg.skipErrorToast
      expect(typeof skip).toBe('function')
      expect(skip(err('ROLE_DEFINITION_CONFLICT'))).toBe(true)
      expect(skip(err('ROLE_DEFINITION_VERSION_CONFLICT'))).toBe(true)
      expect(skip(envelopeErr('ROLE_DEFINITION_VERSION_CONFLICT'))).toBe(true)
      expect(skip(err('ROLE_DEFINITION_IN_USE'))).toBe(true)
      expect(skip(err('ROLE_DEFINITION_LOCKED'))).toBe(false)
      expect(skip({ response: { status: 500, data: {} } })).toBe(false)
    }
  })

  it('roleErrorCode 讀頂層與封套兩種形狀', () => {
    expect(roleErrorCode(err('ROLE_DEFINITION_VERSION_CONFLICT'))).toBe('ROLE_DEFINITION_VERSION_CONFLICT')
    expect(roleErrorCode(envelopeErr('ROLE_DEFINITION_CONFLICT'))).toBe('ROLE_DEFINITION_CONFLICT')
    expect(roleErrorCode(undefined)).toBe('')
  })
})
