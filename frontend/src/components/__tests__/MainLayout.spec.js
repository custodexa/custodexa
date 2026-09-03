import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '../MainLayout.vue'
import { getAccessToken, resetSessionForTests, setAccessToken } from '@/utils/session'

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

// 待審 badge 輪詢：approver 人設的既有測試若不 mock 會打真網路，晚到的 401 回應
// 被 vitest 歸到後面的測試名下變成 stderr 噪音。只擋噪音、回 0 筆，不改任何斷言
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: () => Promise.resolve({ count: 0, review_count: 0 }),
}))

// 單實例守衛橫幅：粗狀態走 seal/status（不寫審計列、可輪詢），細節走 /instance-guard
//（每次呼叫留一列審計讀取、只在橫幅出現時由管理者取一次）。兩條都 mock 掉，
// 本檔的橫幅測試要證明的是「輪詢打的是哪一條」
const getSealStatusMock = vi.fn()
const getInstanceGuardMock = vi.fn()
vi.mock('@/api/seal', () => ({
  getSealStatus: (...args) => getSealStatusMock(...args),
  unseal: vi.fn(),
}))
vi.mock('@/api/instanceGuard', () => ({
  getInstanceGuard: (...args) => getInstanceGuardMock(...args),
}))

const GUARD_HELD = { state: 'held', since: '2026-08-25T09:22:39Z', reason: '', peers: 0 }
const GUARD_OVERRIDDEN = { state: 'overridden', since: '2026-08-25T09:22:39Z', reason: 'ack_startup', peers: 0 }
const sealStatusWith = (guard) => ({ state: 'unsealed', instance_guard: guard })

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
    resetSessionForTests()
    vi.clearAllMocks()
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
  })

  it('renders all five nav groups for admin', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    // isAdmin 於 onMounted 設定，需等待重新渲染
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    for (const label of ['總覽', '資產', '連線', '稽核', '身分與權限', '系統設定']) {
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
      resetSessionForTests()
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

  // 輪替證據：admin 與 auditor 可見，一般 user 連入口都不該有
  it('shows rotation evidence entry to admin and auditor only', async () => {
    for (const roles of [['admin'], ['auditor']]) {
      localStorage.clear()
      resetSessionForTests()
      setUser(roles)
      const wrapper = mountLayout()
      await wrapper.vm.$nextTick()
      expect(wrapper.text()).toContain('輪替證據')
      wrapper.unmount()
    }
    localStorage.clear()
    resetSessionForTests()
    setUser(['user'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).not.toContain('輪替證據')
  })

  // 排程管理留在頁內（admin 專屬區塊），側欄不另開一項——
  // 多一個入口就多一條要各自維權限的路
  it('does not add a separate schedule entry to the sidebar', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).not.toContain('報告排程')
  })

  // —— 人設矩陣新增斷言 ——

  it('workspace entry visible to every persona', async () => {
    for (const roles of [['admin'], ['auditor'], ['user'], ['user', 'approver']]) {
      localStorage.clear()
      resetSessionForTests()
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

  // ui-navigation：收合鈕 SHALL 於初始視窗內可見，SHALL NOT 落在側欄的
  // 捲動摺線之下。它原本住在側欄最底的 sidebar-footer，選單一長就被推出
  // 視窗（1260px 起就看不見）——而螢幕不夠高正是最需要收合的時候。
  // 「不隨選單捲動」的結構前提有三：鈕在 logo 列內、footer 不再存在、
  // 捲動容器是選單而非整條側欄。像素層面的可見性由 Playwright 900px 實點把關
  it('keeps the collapse control in the logo row, above the sidebar scroll fold', () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    expect(wrapper.find('.logo .collapse-btn').exists()).toBe(true)
    expect(wrapper.find('.sidebar-footer').exists()).toBe(false)
  })

  it('labels the collapse control for both directions (icon-only needs a name)', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    const btn = () => wrapper.find('.collapse-btn')
    expect(btn().attributes('aria-label')).toBe('收合側欄')
    await btn().trigger('click')
    expect(btn().attributes('aria-label')).toBe('展開側欄')
  })

  it('restores collapsed state from localStorage on mount', () => {
    setUser(['admin'])
    localStorage.setItem('ot-sidebar-collapsed', 'true')
    const wrapper = mountLayout()
    expect(wrapper.find('.el-menu--collapse').exists()).toBe(true)
  })

  it('revokes refresh token, clears credentials and navigates to /login on logout', async () => {
    setUser(['admin'])
    setAccessToken('abc')
    logoutMock.mockResolvedValue({})
    const wrapper = mountLayout()

    // 直接呼叫 dropdown 的 command handler（彈出層在 happy-dom 下互動不可靠）
    userDropdown(wrapper).vm.$emit('command', 'logout')
    await flushPromises()

    // 登出先請後端撤銷 refresh 憑證。憑證由瀏覽器以 httpOnly cookie 自動附帶，
    // 前端不再持有也就不再傳參——傳參版本等於憑證仍存在於 script 可讀的地方
    expect(logoutMock).toHaveBeenCalledWith()
    expect(getAccessToken()).toBe('')
    expect(localStorage.getItem('user')).toBeNull()
    expect(pushMock).toHaveBeenCalledWith('/login')
  })

  it('still clears credentials when logout revocation fails', async () => {
    setUser(['admin'])
    setAccessToken('abc')
    logoutMock.mockRejectedValue(new Error('network down'))
    const wrapper = mountLayout()

    userDropdown(wrapper).vm.$emit('command', 'logout')
    await flushPromises()

    expect(getAccessToken()).toBe('')
    expect(localStorage.getItem('user')).toBeNull()
    expect(pushMock).toHaveBeenCalledWith('/login')
  })
})

// —— 單實例守衛橫幅（single-instance-guard）——
// 橫幅本體的顯示條件與細節內容在 InstanceGuardBanner.spec.js；本組只釘住 MainLayout 的輪詢契約：
// 打的是不寫審計列的 seal/status，**從不**輪詢會留審計讀取列的 /instance-guard
describe('MainLayout 單實例守衛橫幅輪詢', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
    // 只假 interval：flushPromises 依賴的 setImmediate／setTimeout 維持真實，
    // 否則 await 會卡死（vitest 預設把它們一起假掉）
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('掛載即取一次 seal/status、每 60 秒再取，輪詢不打 /instance-guard', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await flushPromises()
    expect(getSealStatusMock).toHaveBeenCalledTimes(1)
    expect(getSealStatusMock).toHaveBeenCalledWith({ skipErrorToast: true })

    for (let i = 1; i <= 3; i++) {
      vi.advanceTimersByTime(60000)
      await flushPromises()
      expect(getSealStatusMock).toHaveBeenCalledTimes(1 + i)
    }
    // held 且無對等：橫幅不出現、細節端點一次都沒打
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    expect(getInstanceGuardMock).not.toHaveBeenCalled()
  })

  it('overridden 時橫幅出現；admin 的細節只取一次，後續輪詢仍不打 /instance-guard', async () => {
    setUser(['admin'])
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_OVERRIDDEN))
    getInstanceGuardMock.mockResolvedValue({
      ...GUARD_OVERRIDDEN,
      instance: { hostname: 'c4a434007105', pid: 47, started_at: GUARD_OVERRIDDEN.since },
      db_session_pid: 6445,
      holder: {
        application_name: 'custodexa-instance-guard',
        pid: 6401,
        backend_start: '2026-08-25T09:10:59.169055Z',
        code: 'ab12cd34ef56',
        fingerprint_source: 'pg_stat_activity',
      },
      ack: 'ab12cd34ef56',
      lost_total: 0,
    })
    const wrapper = mountLayout()
    await flushPromises()
    const alert = wrapper.find('[role="alert"]')
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('ab12cd34ef56')
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(60000)
    await flushPromises()
    vi.advanceTimersByTime(60000)
    await flushPromises()
    expect(getSealStatusMock).toHaveBeenCalledTimes(3)
    expect(getInstanceGuardMock).toHaveBeenCalledTimes(1)
  })

  it('一般使用者看得到橫幅，但不打 /instance-guard', async () => {
    setUser(['user'])
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_OVERRIDDEN))
    const wrapper = mountLayout()
    await flushPromises()
    const alert = wrapper.find('[role="alert"]')
    expect(alert.exists()).toBe(true)
    expect(alert.text()).toContain('這道橫幅就是通知本身')
    expect(getInstanceGuardMock).not.toHaveBeenCalled()
  })

  it('狀態回到 held 且無對等連線，下一次輪詢後橫幅消失（免重新整理）', async () => {
    setUser(['user'])
    getSealStatusMock.mockResolvedValueOnce(sealStatusWith(GUARD_OVERRIDDEN))
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)

    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
    vi.advanceTimersByTime(60000)
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('輪詢失敗沿用上一次值（橫幅不因一次網路抖動消失）', async () => {
    setUser(['user'])
    getSealStatusMock.mockResolvedValueOnce(sealStatusWith(GUARD_OVERRIDDEN))
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)

    getSealStatusMock.mockRejectedValue(new Error('network down'))
    vi.advanceTimersByTime(60000)
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
  })

  it('卸載後停止輪詢', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    await flushPromises()
    expect(getSealStatusMock).toHaveBeenCalledTimes(1)

    wrapper.unmount()
    vi.advanceTimersByTime(180000)
    await flushPromises()
    expect(getSealStatusMock).toHaveBeenCalledTimes(1)
  })
})
