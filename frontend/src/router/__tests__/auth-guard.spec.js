import { describe, it, expect, vi, beforeEach } from 'vitest'
import router, { createAuthGuard } from '../index'
import axios from 'axios'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import { meBody } from '@/composables/__tests__/capabilityFixtures'
import {
  RELOGIN_INSECURE_TRANSPORT,
  consumeReloginContext,
  markRefreshSucceeded,
  resetReloginContext,
} from '@/utils/reloginContext'

// 能力由守衛透過共用能力狀態向 /auth/me 取得；本檔以 mock 控制該回應
const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
  logout: vi.fn(),
}))

const guard = createAuthGuard()

const route = (path, meta = {}) => ({ path, meta })

describe('auth guard', () => {
  let next

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.restoreAllMocks()
    getCurrentUserMock.mockReset()
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

  it('已登入開帶合法 source 的登入測試連結：停在 /login，不導向儀表板', async () => {
    setAccessToken('abc')
    await guard({ path: '/login', meta: {}, query: { source: 'oidc:4' } }, route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  it('已登入且 source 缺席或格式不符：照舊導到 /dashboard', async () => {
    setAccessToken('abc')
    await guard({ path: '/login', meta: {}, query: {} }, route('/'), next)
    expect(next).toHaveBeenLastCalledWith('/dashboard')
    await guard({ path: '/login', meta: {}, query: { source: 'oidc:abc' } }, route('/'), next)
    expect(next).toHaveBeenLastCalledWith('/dashboard')
  })

  it('allows authenticated user on protected routes', async () => {
    setAccessToken('abc')
    await guard(route('/assets', { requiresAuth: true }), route('/'), next)
    expect(next).toHaveBeenCalledWith()
  })

  // 以註冊的 route meta 驅動（不是硬編路徑）：meta 取自 router.resolve，改了路由設定這裡才跟著動。
  // 能力來自 /auth/me 的 permissions，快取裡的角色不參與裁決
  const signInAs = (roles, flags) => {
    setAccessToken('abc')
    getCurrentUserMock.mockResolvedValue(meBody(roles, flags))
  }
  const enter = async (path) => {
    const resolved = router.resolve(path)
    await guard(route(path, resolved.meta), route('/'), next)
  }

  it('一般 user 直接開管理頁網址被導走，admin 放行', async () => {
    signInAs(['user'])
    await enter('/users')
    expect(next).toHaveBeenCalledWith('/dashboard')

    next.mockClear()
    resetSessionForTests()
    signInAs(['admin'])
    await enter('/users')
    expect(next).toHaveBeenCalledWith()
  })

  it('輪替證據：一般 user 被導走、auditor 放行（registered route meta）', async () => {
    signInAs(['user'])
    await enter('/rotation-evidence')
    expect(next).toHaveBeenCalledWith('/dashboard')

    next.mockClear()
    resetSessionForTests()
    signInAs(['auditor'])
    await enter('/rotation-evidence')
    expect(next).toHaveBeenCalledWith()
  })

  // 憑證庫是 admin-only：auditor 與一般 user 直打網址都要被導走
  it('憑證庫：auditor 與一般 user 被導走，admin 放行（registered route meta）', async () => {
    for (const [roles, allowed] of [[['auditor'], false], [['user'], false], [['admin'], true]]) {
      next.mockClear()
      resetSessionForTests()
      signInAs(roles)
      await enter('/credentials')
      if (allowed) expect(next).toHaveBeenCalledWith()
      else expect(next).toHaveBeenCalledWith('/dashboard')
    }
  })

  it('/access-control 與 /security-policies 同一能力：非 admin 被導走', async () => {
    signInAs(['user'])
    await enter('/access-control')
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('已登入但 /auth/me 取不到：受限入口不放行（沒有角色回退），登入即可的入口照常', async () => {
    setAccessToken('abc')
    // 舊快取說自己是 admin——能力載入失敗時這份快取不得被當成依據
    localStorage.setItem('user', JSON.stringify({ username: 'a', roles: ['admin'], is_approver: true }))
    getCurrentUserMock.mockRejectedValue(new Error('network'))
    await enter('/users')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
    await enter('/dashboard')
    expect(next).toHaveBeenLastCalledWith()
    await enter('/my-requests')
    expect(next).toHaveBeenLastCalledWith()
  })

  it('/auth/me 沒有 permissions 欄位（升級前的回應）：不以角色推導，受限入口不放行', async () => {
    setAccessToken('abc')
    getCurrentUserMock.mockResolvedValue({ id: 1, username: 'a', roles: ['admin'], is_approver: true })
    await enter('/users')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
    await enter('/approvals')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
  })

  it('型別錯誤的 permissions 視為無效，不放行', async () => {
    setAccessToken('abc')
    getCurrentUserMock.mockResolvedValue({ id: 1, permissions: 'user:manage' })
    await enter('/users')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
    resetSessionForTests()
    setAccessToken('abc')
    getCurrentUserMock.mockResolvedValue({ id: 1, permissions: [1, null] })
    await enter('/users')
    expect(next).toHaveBeenLastCalledWith('/dashboard')
  })

  it('沒有會話的受限入口去登入頁（fail-closed）', async () => {
    await enter('/users')
    expect(next).toHaveBeenCalledWith('/login')
    expect(getCurrentUserMock).not.toHaveBeenCalled()
  })

  it('群組審核方（roles 無 approver）以審核呈現點進審核中心；未具資格者被導走', async () => {
    signInAs(['user'], { approver: true })
    await enter('/approvals')
    expect(next).toHaveBeenCalledWith()

    next.mockClear()
    resetSessionForTests()
    signInAs(['user'], { approver: false })
    await enter('/approvals')
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  // admin 對審核端點一律 403，前端資格閘不得兜底：
  // 否則 admin 進了審核中心，四個頁籤全部 403，頁面卻渲染成「目前沒有等候審核的申請」
  it('僅具 admin 者不得進入審核中心（registered route meta）', async () => {
    const approvalsRoute = router.getRoutes().find((r) => r.name === 'Approvals')
    expect(approvalsRoute, '審核中心路由必須存在').toBeTruthy()
    expect(approvalsRoute.meta.permissionsAll).toEqual(['ui:approvals'])
    expect(approvalsRoute.meta.roles).toBeUndefined()

    signInAs(['admin'], { approver: false })
    await enter('/approvals')
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('持審核資格不繞過其他受限入口', async () => {
    signInAs(['user'], { approver: true })
    await enter('/users')
    expect(next).toHaveBeenCalledWith('/dashboard')
  })

  it('同一會話的多次導覽共用一次 /auth/me', async () => {
    signInAs(['admin'])
    await enter('/users')
    await enter('/roles')
    await enter('/credentials')
    expect(getCurrentUserMock).toHaveBeenCalledTimes(1)
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
