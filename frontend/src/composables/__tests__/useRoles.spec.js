import { describe, it, expect, beforeEach } from 'vitest'
import { useRoles } from '../useRoles'

describe('useRoles（角色判定唯一入口）', () => {
  beforeEach(() => localStorage.clear())

  const setUser = (roles, isApprover) => {
    const user = { username: 't', roles }
    if (isApprover !== undefined) user.is_approver = isApprover
    localStorage.setItem('user', JSON.stringify(user))
  }

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

  it('admin 不具審核資格：isEffectiveApprover 為假（守衛端不認 admin 兜底）', () => {
    setUser(['admin'], false)
    const r = useRoles()
    expect(r.isAdmin.value).toBe(true)
    expect(r.isEffectiveApprover.value).toBe(false)
  })

  it('群組審核方：roles 無 approver 但 is_approver 為真，isEffectiveApprover 為真', () => {
    setUser(['user'], true)
    const r = useRoles()
    expect(r.isApprover.value).toBe(false)
    expect(r.isEffectiveApprover.value).toBe(true)
  })

  it('矛盾快取：is_approver 明確為 false 壓過殘留的 approver 角色', () => {
    // persistApproverFlag 只改 is_approver、不動 roles，撤角色後兩者會並存且矛盾。
    // 權威值是 is_approver（後端現算），寫成 OR 會讓過期角色復活資格並打出必敗請求。
    setUser(['user', 'approver'], false)
    const r = useRoles()
    expect(r.isApprover.value).toBe(true)
    expect(r.isEffectiveApprover.value).toBe(false)
  })

  it('舊版快取無 is_approver 欄：具 approver 角色仍判為有效審核者', () => {
    setUser(['user', 'approver'])
    const r = useRoles()
    expect(r.isEffectiveApprover.value).toBe(true)
  })

  it('壞值/缺 user：全 false 容錯', () => {
    localStorage.setItem('user', '{not json')
    const r = useRoles()
    expect(r.roles.value).toEqual([])
    expect(r.isPrivileged.value).toBe(false)
    expect(r.isEffectiveApprover.value).toBe(false)
  })
})
