import { describe, it, expect, vi, beforeEach } from 'vitest'
import router, { createAuthGuard } from '../index'

const guard = createAuthGuard()

const route = (path, meta = {}) => ({ path, meta })

describe('auth guard', () => {
  let next

  beforeEach(() => {
    localStorage.clear()
    next = vi.fn()
  })

  it('redirects unauthenticated user to /login for protected routes', () => {
    guard(route('/assets', { requiresAuth: true }), route('/'), next)
    expect(next).toHaveBeenCalledWith('/login')
  })

  it('allows unauthenticated user on public routes', () => {
    guard(route('/login'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects authenticated user away from /login to /dashboard', () => {
    localStorage.setItem('token', 'abc')
    guard(route('/login'), route('/'), next)
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('allows authenticated user on protected routes', () => {
    localStorage.setItem('token', 'abc')
    guard(route('/assets', { requiresAuth: true }), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects non-admin user to /dashboard on admin-only routes', () => {
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'] }))
    guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('allows admin user on admin-only routes', () => {
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects to /login when token exists but user data is absent (fail-closed)', () => {
    // codex 審查修復：原實作在 roles 路由上 token 在、user 缺時跳過角色檢查放行
    localStorage.setItem('token', 'abc')
    guard(
      route('/access-control', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/login')
  })

  it('redirects non-admin user to /dashboard on /access-control', () => {
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'] }))
    guard(
      route('/access-control', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('allows group-only approver on approver routes via is_approver (D-7, codex P1)', () => {
    // 群組審核方：roles 不含 approver，但後端 is_approver 為真
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', JSON.stringify({ username: 'g', roles: ['user'], is_approver: true }))
    guard(
      route('/approvals', { requiresAuth: true, roles: ['admin', 'approver'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects non-approver without is_approver on approver routes', () => {
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'], is_approver: false }))
    guard(
      route('/approvals', { requiresAuth: true, roles: ['admin', 'approver'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  // W7b 對抗輪（High）：D-12 後 admin 對審核端點一律 403，前端資格閘卻仍留著
  // admin 述詞——admin 進得了審核中心，四個頁籤全部 403，頁面卻渲染成「目前沒有
  // 等候審核的申請」。有待審單時他會誤判佇列已清空。以下釘住實際註冊的路由 meta
  it('僅具 admin 者不得進入審核中心（D-12 收斂，registered route meta）', () => {
    const approvalsRoute = router.getRoutes().find((r) => r.name === 'Approvals')
    expect(approvalsRoute, '審核中心路由必須存在').toBeTruthy()
    expect(approvalsRoute.meta.roles).not.toContain('admin')

    localStorage.setItem('token', 'abc')
    localStorage.setItem(
      'user',
      JSON.stringify({ username: 'a', roles: ['admin'], is_approver: false })
    )
    guard(route('/approvals', approvalsRoute.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('有效審核者仍可進入審核中心（registered route meta）', () => {
    const approvalsRoute = router.getRoutes().find((r) => r.name === 'Approvals')
    localStorage.setItem('token', 'abc')
    localStorage.setItem(
      'user',
      JSON.stringify({ username: 'p', roles: ['user'], is_approver: true })
    )
    guard(route('/approvals', approvalsRoute.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('is_approver does not bypass non-approver routes (admin-only stays admin-only)', () => {
    // is_approver 僅對要求 approver 的路由放行，不得繞過 admin-only 頁
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', JSON.stringify({ username: 'g', roles: ['user'], is_approver: true }))
    guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  // kek-provider-modularization D6.6：封印期只有 /health、/seal/status、/seal/unseal
  // 可達，登入端點本身回 503。解封頁若要求登入，管理員會被導去一個打不通的頁面
  it('解封路由不要求登入，未登入亦放行', () => {
    const unsealRoute = router.getRoutes().find((r) => r.name === 'Unseal')
    expect(unsealRoute, '解封路由必須存在').toBeTruthy()
    expect(unsealRoute.meta.requiresAuth).toBeFalsy()

    guard(route('/unseal', unsealRoute.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('已登入者進解封頁不被導走（重啟後可能又封印）', () => {
    localStorage.setItem('token', 'abc')
    guard(route('/unseal', {}), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects to /login when stored user data is corrupted', () => {
    localStorage.setItem('token', 'abc')
    localStorage.setItem('user', '{not-json')
    guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/login')
  })
})
