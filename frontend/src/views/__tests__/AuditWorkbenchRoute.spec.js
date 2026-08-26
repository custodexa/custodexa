import { describe, it, expect, vi, beforeEach } from 'vitest'
import router, { createAuthGuard } from '@/router'
import { WORKBENCH_PATH, buildAddressPivotLink } from '@/components/audit/timelineQuery'

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

// 位址深連結由告警列表與事件列共用，目的地寫在 timelineQuery 的常數上。
// 常數與真實路由分岔時，每一個深連結都會落到 404——而那是點下去才會發現的
describe('位址深連結的目的地', () => {
  it('WORKBENCH_PATH 等於實際註冊的工作台路徑', () => {
    expect(WORKBENCH_PATH).toBe(workbenchRoute().path)
  })

  it('深連結解析得到工作台路由，且位址原樣落在 id 上', () => {
    const link = buildAddressPivotLink('203.0.113.5', {
      from: '2026-08-26T00:00:00+08:00',
      to: '2026-08-27T00:00:00+08:00',
    })
    const resolved = router.resolve(link)
    expect(resolved.name).toBe('AuditWorkbench')
    expect(resolved.query.subject).toBe('ip')
    expect(resolved.query.id).toBe('203.0.113.5')
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
