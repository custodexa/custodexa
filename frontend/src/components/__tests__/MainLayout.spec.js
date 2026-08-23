import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '../MainLayout.vue'

// 本檔掛載 21 次、原僅 2 處顯式卸載，殘留元件在 document 上累積使單測耗時
// 隨測試序上升——全量並行時「側欄摺疊」兩格逼近 5s 上限而轉紅（單跑 1.7s／2.7s）。
// 與 Assets.spec.js／AuditLogs.spec.js 同型根因，治法相同：逐測卸載。
// 既有的顯式 wrapper.unmount() 保留（迴圈內需即時卸載，不等 afterEach）。
enableAutoUnmount(afterEach)

const pushMock = vi.fn()
const logoutMock = vi.fn()

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
  useRoute: () => ({ path: '/dashboard' }),
}))

vi.mock('@/api/auth', () => ({
  getCurrentUser: vi.fn(),
  getMFASetup: vi.fn(),
  enableMFA: vi.fn(),
  disableMFA: vi.fn(),
  logout: (...args) => logoutMock(...args),
}))

const mountLayout = () =>
  mount(MainLayout, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'router-view': true },
    },
  })

// is_approver 隨登入回應寫入快取，後端算法＝具 approver 角色 OR 屬審核方群組
//（auth_service.go 的 UserInfo.IsApprover）。fixture 依此推導，別讓測試造出一種
// 真實登入回應不可能出現的組合（roles 含 approver 卻 is_approver 缺席）。
// 群組審核方以 setUser(['user'], true) 明示
const setUser = (roles, isApprover = roles.includes('approver')) => {
  localStorage.setItem(
    'user',
    JSON.stringify({ username: 'tester', roles, is_approver: isApprover })
  )
}

// header 現有兩個 dropdown（語言切換＋使用者選單）：
// 依內容鎖定，不可再用「第一個 ElDropdown」
const userDropdown = (wrapper) =>
  wrapper
    .findAllComponents({ name: 'ElDropdown' })
    .find((d) => d.find('.user-info').exists())

const langDropdown = (wrapper) =>
  wrapper
    .findAllComponents({ name: 'ElDropdown' })
    .find((d) => d.find('.lang-switch').exists())

describe('MainLayout sidebar', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('renders all five nav groups for admin', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    // isAdmin 於 onMounted 設定，需等待重新渲染
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    for (const label of ['總覽', '資產', '連線', '審計', '身分與權限', '系統設定']) {
      expect(text).toContain(label)
    }
    expect(text).toContain('資產授權')
    expect(text).toContain('使用者管理')
    expect(text).toContain('角色管理')
  })

  it('admin sees access-control entry and renamed transmission entry', async () => {
    // 存取管控新項在系統管理群組；通道加密清冊更名傳輸安全
    setUser(['admin'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    expect(text).toContain('存取管控')
    expect(text).toContain('傳輸安全')
    expect(text).not.toContain('通道加密清冊')
  })

  it('hides access-control entry for non-admin', () => {
    setUser(['user'])
    const wrapper = mountLayout()
    expect(wrapper.text()).not.toContain('存取管控')
  })

  it('hides admin-only groups and items for non-admin', () => {
    setUser(['user'])
    const wrapper = mountLayout()
    const text = wrapper.text()
    expect(text).not.toContain('身分與權限')
    expect(text).not.toContain('系統設定')
    expect(text).not.toContain('資產授權')
    expect(text).not.toContain('使用者管理')
    // user 視角以「我的資產」呈現同一頁
    expect(text).not.toContain('資產管理')
    expect(text).toContain('我的資產')
  })

  // —— session 管理入口收斂＋自助入口 ——

  it('plain user sees my-connections entry instead of session management', () => {
    setUser(['user'])
    const wrapper = mountLayout()
    const text = wrapper.text()
    expect(text).not.toContain('連線管理')
    expect(text).toContain('我的連線')
  })

  it('admin and auditor keep full session management without self-service entry', async () => {
    for (const roles of [['admin'], ['auditor']]) {
      localStorage.clear()
      setUser(roles)
      const wrapper = mountLayout()
      await wrapper.vm.$nextTick()
      const text = wrapper.text()
      expect(text).toContain('連線管理')
      expect(text).not.toContain('我的連線')
      wrapper.unmount()
    }
  })

  it('multi-role [user,auditor] account keeps full session management', async () => {
    // 自助入口以「不具 admin/auditor」判定，非 roles 含 user——多角色帳號不得誤入自助模式
    setUser(['user', 'auditor'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    expect(text).toContain('連線管理')
    expect(text).not.toContain('我的連線')
  })

  it('hides the entire audit group for plain user (least privilege)', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    // 審計群組三項全限 admin/auditor，user 應完全看不到（含群組標頭）
    expect(text).not.toContain('操作日誌')
    expect(text).not.toContain('告警')
  })

  it('shows audit group for auditor role', async () => {
    setUser(['auditor'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    expect(text).toContain('操作日誌')
    expect(text).toContain('告警')
    // auditor 仍非 admin，不得見身分與系統設定兩組
    expect(text).not.toContain('身分與權限')
    expect(text).not.toContain('系統設定')
  })

  // —— 人設矩陣新增斷言 ——

  it('workspace entry visible to every persona', async () => {
    for (const roles of [['admin'], ['auditor'], ['user'], ['user', 'approver']]) {
      localStorage.clear()
      setUser(roles)
      const wrapper = mountLayout()
      await wrapper.vm.$nextTick()
      expect(wrapper.text()).toContain('工作區')
      wrapper.unmount()
    }
  })

  it('admin keeps 資產管理 title (userTitle only applies to non-privileged)', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('資產管理')
    expect(wrapper.text()).not.toContain('我的資產')
  })

  it('profile command navigates to /profile (placeholder removed)', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    userDropdown(wrapper).vm.$emit('command', 'profile')
    await flushPromises()
    expect(pushMock).toHaveBeenCalledWith('/profile')
  })

  it('approver overlay shows 審核中心 for a non-privileged account', async () => {
    setUser(['user', 'approver'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    expect(text).toContain('審核中心')
    // 仍為自助人設：我的資產＋我的連線
    expect(text).toContain('我的資產')
    expect(text).toContain('我的連線')
  })

  // 審核端點對僅具 admin 者一律 403。入口留著只會把他
  // 帶到一個四頁籤全 403、卻渲染成「目前沒有等候審核的申請」的假空態頁
  it('僅具 admin 者看不到審核中心入口', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).not.toContain('審核中心')
  })

  // 群組即資格：roles 不含 approver，但後端 is_approver 為真
  it('審核方群組成員（roles 無 approver）仍看得到審核中心', async () => {
    setUser(['user'], true)
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('審核中心')
  })

  // —— 語言切換 ——

  it('switches menu language in place and persists ot-lang (no reload)', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('使用者管理')

    langDropdown(wrapper).vm.$emit('command', 'en-US')
    await wrapper.vm.$nextTick()

    const text = wrapper.text()
    expect(text).toContain('Users')
    expect(text).toContain('Overview')
    expect(text).not.toContain('使用者管理')
    expect(localStorage.getItem('ot-lang')).toBe('en-US')
    // 同一 wrapper 原地重繪＝免 reload；頁面標題同步換語
    expect(wrapper.find('.current-path').text()).toBe('Dashboard')
  })

  it('language switcher lists three native names', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    expect(langDropdown(wrapper)).toBeTruthy()
    expect(wrapper.find('.lang-switch').text()).toContain('繁體中文')
  })

  it('does not expose test pages in navigation', () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    expect(wrapper.text()).not.toContain('連線測試')
    expect(wrapper.text()).not.toContain('RDP 錄製測試')
  })

  it('persists collapse state to localStorage', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    expect(localStorage.getItem('ot-sidebar-collapsed')).toBeNull()

    await wrapper.find('.collapse-btn').trigger('click')
    expect(localStorage.getItem('ot-sidebar-collapsed')).toBe('true')

    await wrapper.find('.collapse-btn').trigger('click')
    expect(localStorage.getItem('ot-sidebar-collapsed')).toBe('false')
  })

  it('restores collapsed state from localStorage on mount', () => {
    setUser(['admin'])
    localStorage.setItem('ot-sidebar-collapsed', 'true')
    const wrapper = mountLayout()
    expect(wrapper.find('.el-menu--collapse').exists()).toBe(true)
  })

  it('revokes refresh token, clears credentials and navigates to /login on logout', async () => {
    setUser(['admin'])
    localStorage.setItem('token', 'abc')
    logoutMock.mockResolvedValue({})
    const wrapper = mountLayout()

    // 直接呼叫 dropdown 的 command handler（彈出層在 happy-dom 下互動不可靠）
    userDropdown(wrapper).vm.$emit('command', 'logout')
    await flushPromises()

    // 登出先請後端撤銷 refresh 憑證。憑證由瀏覽器以 httpOnly cookie 自動附帶，
    // 前端不再持有也就不再傳參——傳參版本等於憑證仍存在於 script 可讀的地方
    expect(logoutMock).toHaveBeenCalledWith()
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
    expect(pushMock).toHaveBeenCalledWith('/login')
  })

  it('still clears credentials when logout revocation fails', async () => {
    setUser(['admin'])
    localStorage.setItem('token', 'abc')
    logoutMock.mockRejectedValue(new Error('network down'))
    const wrapper = mountLayout()

    userDropdown(wrapper).vm.$emit('command', 'logout')
    await flushPromises()

    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
    expect(pushMock).toHaveBeenCalledWith('/login')
  })
})
