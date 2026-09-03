import { describe, it, expect, vi, beforeEach } from 'vitest'
import router, { createAuthGuard } from '../index'
import axios from 'axios'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import {
  RELOGIN_INSECURE_TRANSPORT,
  consumeReloginContext,
  markRefreshSucceeded,
  resetReloginContext,
} from '@/utils/reloginContext'

const guard = createAuthGuard()

const route = (path, meta = {}) => ({ path, meta })

describe('auth guard', () => {
  let next

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.restoreAllMocks()
    next = vi.fn()
  })

  it('redirects unauthenticated user to /login for protected routes', async () => {
    await guard(route('/assets', { requiresAuth: true }), route('/'), next)
    expect(next).toHaveBeenCalledWith('/login')
  })

  it('allows unauthenticated user on public routes', async () => {
    await guard(route('/login'), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects authenticated user away from /login to /dashboard', async () => {
    setAccessToken('abc')
    await guard(route('/login'), route('/'), next)
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('allows authenticated user on protected routes', async () => {
    setAccessToken('abc')
    await guard(route('/assets', { requiresAuth: true }), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects non-admin user to /dashboard on admin-only routes', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'] }))
    await guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('allows admin user on admin-only routes', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    await guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith()
  })

  // 輪替證據以註冊的 route meta 驅動（不是硬編路徑）：一般 user 直打網址也進不去
  it('一般 user 直接開輪替證據網址被導走（registered route meta）', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'] }))
    const resolved = router.resolve('/rotation-evidence')
    await guard(route('/rotation-evidence', resolved.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('auditor 可進輪替證據（registered route meta）', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['auditor'] }))
    const resolved = router.resolve('/rotation-evidence')
    await guard(route('/rotation-evidence', resolved.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects to /login when token exists but user data is absent (fail-closed)', async () => {
    // 原實作在 roles 路由上 token 在、user 缺時跳過角色檢查放行，此處釘死 fail-closed
    setAccessToken('abc')
    await guard(
      route('/access-control', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/login')
  })

  it('redirects non-admin user to /dashboard on /access-control', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'] }))
    await guard(
      route('/access-control', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('allows group-only approver on approver routes via is_approver', async () => {
    // 群組審核方：roles 不含 approver，但後端 is_approver 為真
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'g', roles: ['user'], is_approver: true }))
    await guard(
      route('/approvals', { requiresAuth: true, roles: ['admin', 'approver'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects non-approver without is_approver on approver routes', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'u', roles: ['user'], is_approver: false }))
    await guard(
      route('/approvals', { requiresAuth: true, roles: ['admin', 'approver'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  // admin 對審核端點一律 403，前端資格閘卻仍留著
  // admin 述詞——admin 進得了審核中心，四個頁籤全部 403，頁面卻渲染成「目前沒有
  // 等候審核的申請」。有待審單時他會誤判佇列已清空。以下釘住實際註冊的路由 meta
  it('僅具 admin 者不得進入審核中心（registered route meta）', async () => {
    const approvalsRoute = router.getRoutes().find((r) => r.name === 'Approvals')
    expect(approvalsRoute, '審核中心路由必須存在').toBeTruthy()
    expect(approvalsRoute.meta.roles).not.toContain('admin')

    setAccessToken('abc')
    localStorage.setItem(
      'user',
      JSON.stringify({ username: 'a', roles: ['admin'], is_approver: false })
    )
    await guard(route('/approvals', approvalsRoute.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('有效審核者仍可進入審核中心（registered route meta）', async () => {
    const approvalsRoute = router.getRoutes().find((r) => r.name === 'Approvals')
    setAccessToken('abc')
    localStorage.setItem(
      'user',
      JSON.stringify({ username: 'p', roles: ['user'], is_approver: true })
    )
    await guard(route('/approvals', approvalsRoute.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('is_approver does not bypass non-approver routes (admin-only stays admin-only)', async () => {
    // is_approver 僅對要求 approver 的路由放行，不得繞過 admin-only 頁
    setAccessToken('abc')
    localStorage.setItem('user', JSON.stringify({ username: 'g', roles: ['user'], is_approver: true }))
    await guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  // 封印期只有 /health、/seal/status、/seal/unseal
  // 可達，登入端點本身回 503。解封頁若要求登入，管理員會被導去一個打不通的頁面
  it('解封路由不要求登入，未登入亦放行', async () => {
    const unsealRoute = router.getRoutes().find((r) => r.name === 'Unseal')
    expect(unsealRoute, '解封路由必須存在').toBeTruthy()
    expect(unsealRoute.meta.requiresAuth).toBeFalsy()

    await guard(route('/unseal', unsealRoute.meta), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('已登入者進解封頁不被導走（重啟後可能又封印）', async () => {
    setAccessToken('abc')
    await guard(route('/unseal', {}), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('redirects to /login when stored user data is corrupted', async () => {
    setAccessToken('abc')
    localStorage.setItem('user', '{not-json')
    await guard(
      route('/users', { requiresAuth: true, roles: ['admin'] }),
      route('/'),
      next
    )
    expect(next).toHaveBeenCalledWith('/login')
  })
  // 記憶體 token 在重新載入後是空的：守衛必須先以續期憑證換發一次，
  // 才知道使用者到底登入了沒有
  it('有登入跡象且換發成功 → 放行受保護路由', async () => {
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockResolvedValue({ data: { token: 'restored-jwt' } })

    await guard(route('/assets', { requiresAuth: true }), route('/'), next)

    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(next).toHaveBeenCalledWith()
  })

  it('有登入跡象但換發失敗 → 導向登入頁', async () => {
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    vi.spyOn(axios, 'post').mockRejectedValue({ response: { status: 401 } })

    await guard(route('/assets', { requiresAuth: true }), route('/'), next)

    expect(next).toHaveBeenCalledWith('/login')
    expect(localStorage.getItem('user')).toBeNull()
  })

  // 明文 HTTP 部署且續期 cookie 帶 Secure：瀏覽器根本不保存那枚 cookie，
  // 於是每一次重新載入都帶不出憑證、續期必然 401。使用者看到的是「又要我登入」，
  // 而畫面若只說「會話已過期」，真正的原因（部署協定）沒有任何線索指得出來。
  //
  // 這一組釘住三件事：**回未登入**、**導向登入頁**、**留下可解釋的脈絡**，
  // 外加**不迴圈**——導向登入頁後不得再打一次續期端點，否則每次載入都在稽核紀錄
  // 裡疊一列拒絕事件，把真正有意義的失敗事件淹掉。
  it('明文連線下續期帶不出 cookie → 回未登入、導向登入頁並留下協定脈絡', async () => {
    resetReloginContext()
    expect(window.location.protocol).toBe('http:')
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockRejectedValue({ response: { status: 401 } })

    await guard(route('/assets', { requiresAuth: true }), route('/'), next)

    expect(next).toHaveBeenCalledWith('/login')
    expect(postSpy).toHaveBeenCalledTimes(1)
    // 登入頁讀得到「是連線協定造成的」——讀後即清，重新整理登入頁不重播
    expect(consumeReloginContext()).toBe(RELOGIN_INSECURE_TRANSPORT)
    expect(consumeReloginContext()).toBe('')
  })

  it('明文連線導向登入頁後不再打續期端點（不迴圈）', async () => {
    resetReloginContext()
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    const postSpy = vi
      .spyOn(axios, 'post')
      .mockRejectedValue({ response: { status: 401 } })

    await guard(route('/assets', { requiresAuth: true }), route('/'), next)
    expect(next).toHaveBeenCalledWith('/login')
    // 跡象已被清除，登入頁這一趟不得再觸發續期
    await guard(route('/login'), route('/'), next)

    expect(postSpy).toHaveBeenCalledTimes(1)
    expect(next).toHaveBeenLastCalledWith()
  })

  // 健康的明文部署（Secure 已關閉）續期失敗幾乎都發生在多次成功續期之後，
  // 那是正常的會話到期。誤扣「協定問題」的帽子三次，訊息就死了
  it('本分頁曾成功續期過 → 不扣協定問題的帽子', async () => {
    resetReloginContext()
    markRefreshSucceeded()
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'] }))
    vi.spyOn(axios, 'post').mockRejectedValue({ response: { status: 401 } })

    await guard(route('/assets', { requiresAuth: true }), route('/'), next)

    expect(next).toHaveBeenCalledWith('/login')
    expect(consumeReloginContext()).toBe('')
  })

  // 未登入訪客開登入頁不得打續期端點：每一次都會在稽核紀錄裡留一列拒絕事件，
  // 而失敗事件對稽核有意義，不該被雜訊淹沒
  it('無登入跡象 → 不呼叫續期端點', async () => {
    const postSpy = vi.spyOn(axios, 'post')

    await guard(route('/login'), route('/'), next)

    expect(postSpy).not.toHaveBeenCalled()
    expect(next).toHaveBeenCalledWith()
  })
})
