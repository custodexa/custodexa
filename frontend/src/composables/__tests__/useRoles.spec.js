import { describe, it, expect, beforeEach } from 'vitest'
import { useRoles } from '../useRoles'

describe('useRoles（角色判定唯一入口）', () => {
  beforeEach(() => localStorage.clear())

  const setUser = (roles) =>
    localStorage.setItem('user', JSON.stringify({ username: 't', roles }))

  it('admin：isAdmin/isPrivileged 為真', () => {
    setUser(['admin'])
    const r = useRoles()
    expect(r.isAdmin.value).toBe(true)
    expect(r.isPrivileged.value).toBe(true)
    expect(r.isApprover.value).toBe(false)
  })

  it('多角色 [user,auditor]：口徑取特權（不落自助模式）', () => {
    setUser(['user', 'auditor'])
    const r = useRoles()
    expect(r.isPrivileged.value).toBe(true)
    expect(r.isAuditor.value).toBe(true)
  })

  it('user+approver：疊加獨立判定、仍非特權', () => {
    setUser(['user', 'approver'])
    const r = useRoles()
    expect(r.isPrivileged.value).toBe(false)
    expect(r.isApprover.value).toBe(true)
  })

  it('壞值/缺 user：全 false 容錯', () => {
    localStorage.setItem('user', '{not json')
    const r = useRoles()
    expect(r.roles.value).toEqual([])
    expect(r.isPrivileged.value).toBe(false)
  })
})
