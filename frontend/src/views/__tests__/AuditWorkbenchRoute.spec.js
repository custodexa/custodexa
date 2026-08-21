import { describe, it, expect, vi, beforeEach } from 'vitest'
import router, { createAuthGuard } from '@/router'

// 工作台路由與角色閘（auditor-workbench 6.1）。
// 本檔不 mock vue-router——要驗的正是真實路由表與真實守衛的裁決。

const workbenchRoute = () =>
  router.getRoutes().find((r) => r.name === 'AuditWorkbench')

describe('/audit/workbench 路由', () => {
  it('掛在 MainLayout 之下，路徑與稽核頁權限一致', () => {
    const route = workbenchRoute()
    expect(route).toBeTruthy()
    expect(route.path).toBe('/audit/workbench')
    expect(route.meta.requiresAuth).toBe(true)
    expect(route.meta.roles).toEqual(['admin', 'auditor'])
  })
})

describe('角色閘', () => {
  beforeEach(() => {
    localStorage.clear()
    localStorage.setItem('token', 'fake-token')
  })

  const enter = (roles) => {
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles }))
    const next = vi.fn()
    createAuthGuard()({ path: '/audit/workbench', meta: workbenchRoute().meta }, {}, next)
    return next
  }

  it('auditor 與 admin 放行', () => {
    expect(enter(['auditor'])).toHaveBeenCalledWith()
    expect(enter(['admin'])).toHaveBeenCalledWith()
  })

  it('一般使用者直接輸網址被擋回總覽', () => {
    expect(enter(['user'])).toHaveBeenCalledWith('/dashboard')
  })

  it('未登入導向登入頁', () => {
    localStorage.clear()
    const next = vi.fn()
    createAuthGuard()({ path: '/audit/workbench', meta: workbenchRoute().meta }, {}, next)
    expect(next).toHaveBeenCalledWith('/login')
  })
})
