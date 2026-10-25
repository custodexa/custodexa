import { describe, it, expect, beforeEach } from 'vitest'
import { useRoles, roleNames, hasRole } from '../useRoles'

// useRoles 只剩角色「資料」與本人 ID：授權判斷已全部改由後端 permissions（useCapabilities.can）決定。
describe('useRoles（角色資料與本人識別，不含授權旗標）', () => {
  beforeEach(() => localStorage.clear())

  it('讀登入快取的角色清單與本人 ID', () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, username: 't', roles: ['user', 'auditor'] }))
    const r = useRoles()
    expect(r.roles.value).toEqual(['user', 'auditor'])
    expect(r.currentUserId.value).toBe(7)
  })

  it('不再暴露任何授權旗標：角色快取不能被當成能力', () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, username: 'a', roles: ['admin'], is_approver: true }))
    const r = useRoles()
    for (const key of ['isAdmin', 'isAuditor', 'isApprover', 'isEffectiveApprover', 'isPrivileged']) {
      expect(r, key).not.toHaveProperty(key)
    }
  })

  it('壞值/缺 user：空角色、無本人 ID', () => {
    localStorage.setItem('user', '{not json')
    const r = useRoles()
    expect(r.roles.value).toEqual([])
    expect(r.currentUserId.value).toBeNull()
  })

  it('roleNames／hasRole 相容物件與字串兩形（他人資料列的角色標籤用）', () => {
    expect(roleNames([{ name: 'approver' }, 'user', null])).toEqual(['approver', 'user'])
    expect(hasRole([{ name: 'approver' }], 'approver')).toBe(true)
    expect(hasRole(['user'], 'approver')).toBe(false)
    expect(hasRole(undefined, 'approver')).toBe(false)
  })
})
