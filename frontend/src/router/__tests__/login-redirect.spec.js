// 導向登入頁時帶「登入後回到原頁」的目的地。
//
// 只有「登入後可回到的路由」清單內的頁面帶 next；目的地放在路由器的 query，由路由器編碼一次。
// API 認證失敗的整頁導向在當下頁面屬清單時帶；主動登出不帶。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'

vi.mock('element-plus', () => ({
  ElMessage: { error: vi.fn(), success: vi.fn(), info: vi.fn(), warning: vi.fn() },
}))

const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
  logout: vi.fn(),
}))

import router, { createAuthGuard } from '../index'
import request from '@/api/request'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import {
  loginLocationFor,
  loginHrefForCurrentPage,
  rememberCurrentRoute,
  resetCurrentRouteForTests,
} from '../loginRedirect'
import mainLayoutSource from '@/components/MainLayout.vue?raw'

const guard = createAuthGuard()

// 以註冊的路由解析出 name、meta、fullPath，與實際導覽時守衛拿到的形狀相同
const resolved = (path) => {
  const r = router.resolve(path)
  return { path: r.path, name: r.name, meta: r.meta, fullPath: r.fullPath, query: r.query }
}

describe('認證守衛：登入後可回到的頁面才帶 next', () => {
  let next
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    getCurrentUserMock.mockReset()
    next = vi.fn()
  })

  it('(a)(e) 未登入開審核中心直達網址：導向登入頁並以路由器 query 交出 next，網址只編碼一次', async () => {
    const to = resolved('/approvals?tab=pending&request=42')
    await guard(to, resolved('/'), next)
    expect(next).toHaveBeenCalledTimes(1)
    const loc = next.mock.calls[0][0]
    expect(loc).toEqual({ path: '/login', query: { next: '/approvals?tab=pending&request=42' } })

    // 交給路由器編碼後的登入頁網址：解碼一次就得到原本的 fullPath（沒有 %25 這類二次編碼）
    const href = router.resolve(loc).href
    expect(href.startsWith('/login?next=')).toBe(true)
    expect(href).not.toContain('%25')
    expect(new URL(href, 'http://localhost').searchParams.get('next')).toBe('/approvals?tab=pending&request=42')
    // 登入頁以路由器解析時拿到的也是原值
    expect(router.resolve(href).query.next).toBe('/approvals?tab=pending&request=42')
  })

  it.each([
    '/audit-logs?tab=reviews',
    '/audit/agent-tasks/42',
    '/agent-breakers?user_id=9',
    '/alerts',
    '/sessions/42',
    '/notification-channels',
  ])('清單內的其他頁面同樣帶 next：%s', async (path) => {
    await guard(resolved(path), resolved('/'), next)
    expect(next).toHaveBeenCalledWith({ path: '/login', query: { next: path } })
  })

  // 「/」由路由表重導到 /dashboard，守衛實際拿到的是 /dashboard
  it.each(['/users', '/terminal/7', '/dashboard', '/workspace?asset=3', '/sessions/7/monitor'])(
    '(b) 不在清單的頁面只導向 /login，不帶 next：%s',
    async (path) => {
      await guard(resolved(path), resolved('/'), next)
      expect(next).toHaveBeenCalledWith('/login')
    }
  )

  it('(c) 主動登出：導向 /login 本身不帶 next，守衛對登入頁放行且不加任何參數', async () => {
    await guard(resolved('/login'), resolved('/approvals?tab=pending&request=42'), next)
    expect(next).toHaveBeenCalledWith()
    // 登出處理導向純 /login（不以 loginLocationFor 帶目的地）
    const logoutBlock = mainLayoutSource.slice(mainLayoutSource.indexOf('const handleLogout'))
    expect(logoutBlock.slice(0, logoutBlock.indexOf('\n}\n'))).toContain("router.push('/login')")
    expect(logoutBlock.slice(0, logoutBlock.indexOf('\n}\n'))).not.toContain('next')
  })

  it('loginLocationFor 只接受站內路徑；名稱不是字串或不在清單一律回 /login', () => {
    expect(loginLocationFor({ name: 'Approvals', fullPath: 'https://evil.example/approvals' })).toBe('/login')
    expect(loginLocationFor({ name: Symbol('x'), fullPath: '/approvals' })).toBe('/login')
    expect(loginLocationFor(null)).toBe('/login')
  })
})

describe('(d) API 認證失敗的整頁導向', () => {
  const originalAdapter = request.defaults.adapter
  const responseHandler = request.interceptors.response.handlers[0]
  const make401 = (url) => ({
    response: { status: 401, data: { error: '未授權', code: 'AUTH_TOKEN_INVALID' } },
    config: { url, headers: { Authorization: 'Bearer stale' }, skipErrorToast: true },
  })

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    resetCurrentRouteForTests()
    request.defaults.adapter = vi.fn()
    setAccessToken('stale')
    // 續期被伺服器明確拒絕：認證結論，清會話並整頁導向
    vi.spyOn(axios, 'post').mockRejectedValue(make401('/auth/refresh'))
  })

  afterEach(() => {
    request.defaults.adapter = originalAdapter
    vi.restoreAllMocks()
  })

  it('停在審核中心時遇 401：導向的登入頁帶原本的網址', async () => {
    window.location.href = 'http://localhost:3000/approvals?tab=pending&request=42'
    rememberCurrentRoute(resolved('/approvals?tab=pending&request=42'))
    await expect(responseHandler.rejected(make401('/access-requests/pending'))).rejects.toBeTruthy()
    const url = new URL(window.location.href)
    expect(url.pathname).toBe('/login')
    expect(url.searchParams.get('next')).toBe('/approvals?tab=pending&request=42')
    expect(window.location.href).not.toContain('%25')
  })

  it('停在使用者管理頁時遇 401：只導向 /login', async () => {
    window.location.href = 'http://localhost:3000/users'
    rememberCurrentRoute(resolved('/users'))
    await expect(responseHandler.rejected(make401('/users'))).rejects.toBeTruthy()
    const url = new URL(window.location.href)
    expect(url.pathname).toBe('/login')
    expect(url.search).toBe('')
  })

  it('記下的路由與網址列不一致（尚未導覽完成）時不帶', () => {
    rememberCurrentRoute(resolved('/approvals?request=42'))
    expect(loginHrefForCurrentPage('/users')).toBe('/login')
    expect(loginHrefForCurrentPage('/approvals')).toBe('/login?next=%2Fapprovals%3Frequest%3D42')
  })
})
