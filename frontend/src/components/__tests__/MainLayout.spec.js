import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '../MainLayout.vue'
import { setDetailSubject, clearDetailSubject } from '@/utils/detailTitle'
import { getAccessToken, resetSessionForTests, setAccessToken } from '@/utils/session'
import { setCapabilitiesForTests, useCapabilities } from '@/composables/useCapabilities'
import { meBody, permissionsFor } from '@/composables/__tests__/capabilityFixtures'

// 本檔掛載 21 次、原僅 2 處顯式卸載，殘留元件在 document 上累積使單測耗時
// 隨測試序上升——全量並行時「側欄摺疊」兩格逼近 5s 上限而轉紅（單跑 1.7s／2.7s）。
// 與 Assets.spec.js／AuditLogs.spec.js 同型根因，治法相同：逐測卸載。
// 既有的顯式 wrapper.unmount() 保留（迴圈內需即時卸載，不等 afterEach）。
enableAutoUnmount(afterEach)

const pushMock = vi.fn()
const logoutMock = vi.fn()

const routeState = vi.hoisted(() => ({ path: '/dashboard' }))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushMock }),
  useRoute: () => routeState,
}))

const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
  getMFASetup: vi.fn(),
  enableMFA: vi.fn(),
  disableMFA: vi.fn(),
  logout: (...args) => logoutMock(...args),
}))

// 待審 badge 輪詢：approver 人設的既有測試若不 mock 會打真網路，晚到的 401 回應
// 被 vitest 歸到後面的測試名下變成 stderr 噪音。只擋噪音、回 0 筆，不改任何斷言
const getPendingAccessRequestCountMock = vi.fn(() =>
  Promise.resolve({ count: 0, review_count: 0 })
)
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: (...args) => getPendingAccessRequestCountMock(...args),
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

// 每日簽核待簽天數徽章：只對具簽核權限者輪詢。mock 掉以免打真網路，
// 各案以 mockResolvedValue 指定回應
const getDailyReviewPendingCountMock = vi.fn(() =>
  Promise.resolve({ data: { count: 0, overdue_count: 0 } })
)
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewPendingCount: (...args) => getDailyReviewPendingCountMock(...args),
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

// 能力來自後端 /auth/me 的 permissions（伺服器逐請求解析），不是登入快取裡的角色。
// 本夾具把某種身分的能力預先寫入共用能力狀態（首屏即可渲染），並讓 /auth/me 回同一份回應；
// roles 只是敘述「這是誰」，元件不讀它。群組審核方以 setUser(['user'], true) 明示
const setUser = (roles, isApprover = roles.includes('approver')) => {
  localStorage.setItem('user', JSON.stringify({ username: 'tester' }))
  setCapabilitiesForTests(permissionsFor(roles, { approver: isApprover }))
  getCurrentUserMock.mockResolvedValue(meBody(roles, { approver: isApprover }))
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

  // 自助入口對所有已登入者可見（已核准的行為差異）：我的連線、我的申請對所有已登入者可見；連線管理仍只給具 session:view 者
  it('admin and auditor keep full session management and now also see the self-service entries', async () => {
    for (const roles of [['admin'], ['auditor']]) {
      localStorage.clear()
      resetSessionForTests()
      setUser(roles)
      const wrapper = mountLayout()
      await wrapper.vm.$nextTick()
      const text = wrapper.text()
      expect(text).toContain('連線管理')
      expect(text).toContain('我的連線')
      expect(text).toContain('我的申請')
      wrapper.unmount()
    }
  })

  it('multi-role [user,auditor] account keeps full session management', async () => {
    // 連線管理看 session:view（折疊後仍是稽核員能力），不因同時掛 user 角色而降級
    setUser(['user', 'auditor'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    expect(text).toContain('連線管理')
    expect(text).toContain('我的連線')
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
    // auditor 仍非 admin，不得見身分與權限組；系統設定組只因政策組的唯讀入口出現，其餘設定入口不可見
    expect(text).not.toContain('身分與權限')
    expect(text).toContain('政策組')
    expect(text).not.toContain('金鑰管理')
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

  // 帳號憑證庫：admin 專屬，auditor 與一般 user 連入口都不該有
  it('shows credential library entry to admin only', async () => {
    setUser(['admin'])
    let wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('帳號憑證庫')
    wrapper.unmount()

    for (const roles of [['auditor'], ['user']]) {
      localStorage.clear()
      resetSessionForTests()
      setUser(roles)
      wrapper = mountLayout()
      await wrapper.vm.$nextTick()
      expect(wrapper.text(), roles.join()).not.toContain('帳號憑證庫')
      wrapper.unmount()
    }
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

  it('guidance command goes to the dashboard with the guidance query, for any signed-in user', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    userDropdown(wrapper).vm.$emit('command', 'guidance')
    await flushPromises()
    expect(pushMock).toHaveBeenCalledWith({ path: '/dashboard', query: { guidance: '1.18.0' } })
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

  // 能力在掛載時由共用能力狀態向 /auth/me 取得（守衛已載入則共用同一份）
  it('掛載時載入能力：/auth/me 帶審核呈現點就顯示審核中心並開始待審輪詢', async () => {
    localStorage.setItem('user', JSON.stringify({ username: 'tester', roles: ['user'] }))
    getCurrentUserMock.mockResolvedValue(meBody(['user'], { approver: true }))
    getPendingAccessRequestCountMock.mockClear()

    const wrapper = mountLayout()
    await flushPromises()

    const paths = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))
    expect(paths).toContain('/approvals')
    expect(getPendingAccessRequestCountMock).toHaveBeenCalled()
    expect(getCurrentUserMock).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('能力載入前受限入口不顯示、也不拿快取的角色頂替', async () => {
    localStorage.setItem('user', JSON.stringify({ username: 'tester', roles: ['admin'], is_approver: true }))
    let resolveMe
    getCurrentUserMock.mockReturnValue(new Promise((resolve) => { resolveMe = resolve }))

    const wrapper = mountLayout()
    await flushPromises()
    let paths = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))
    expect(paths).not.toContain('/users')
    expect(paths).not.toContain('/approvals')
    expect(paths).toContain('/dashboard') // 登入即可的入口不等能力

    resolveMe(meBody(['admin']))
    await flushPromises()
    paths = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))
    expect(paths).toContain('/users')
    expect(paths).not.toContain('/approvals') // admin 不因管理者身分取得審核入口
    wrapper.unmount()
  })

  it('/auth/me 回報成為 agent 負責人時顯示我的 agent', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))).not.toContain('/my-agents')

    getCurrentUserMock.mockResolvedValue(meBody(['admin'], { owns: true }))
    await useCapabilities().reload()
    await flushPromises()
    expect(wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))).toContain('/my-agents')
    wrapper.unmount()
  })

  it('能力載入失敗時顯示重試提示，重試成功後入口出現', async () => {
    localStorage.setItem('user', JSON.stringify({ username: 'tester' }))
    getCurrentUserMock.mockRejectedValue(new Error('network'))
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('[data-test="capability-load-failed"]').exists()).toBe(true)
    expect(wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))).not.toContain('/users')

    getCurrentUserMock.mockResolvedValue(meBody(['admin']))
    await wrapper.find('[data-test="capability-retry"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="capability-load-failed"]').exists()).toBe(false)
    expect(wrapper.findAllComponents({ name: 'ElMenuItem' }).map((m) => m.props('index'))).toContain('/users')
    wrapper.unmount()
  })

  // 快取說有資格、/auth/me 說沒有（撤角色或移出審核方群組後的下一次取得）：
  // 已起的輪詢必須停掉，否則它每 30 秒對必敗端點打一次直到整個 layout 卸載。
  it('能力更新判定失去審核資格時停止待審輪詢', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    try {
      setUser(['user'], true)
      const wrapper = mountLayout()
      await flushPromises()
      expect(getPendingAccessRequestCountMock).toHaveBeenCalled()

      getCurrentUserMock.mockResolvedValue(meBody(['user'], { approver: false }))
      await useCapabilities().reload()
      await flushPromises()
      const callsAfterReload = getPendingAccessRequestCountMock.mock.calls.length

      await vi.advanceTimersByTimeAsync(90000)
      expect(getPendingAccessRequestCountMock.mock.calls.length).toBe(callsAfterReload)
      wrapper.unmount()
    } finally {
      vi.useRealTimers()
    }
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
    // 細節預設收合（設計裁決）：取回來了但不攤開，展開才看得到指紋
    expect(alert.text()).not.toContain('ab12cd34ef56')
    await wrapper.find('.detail-toggle').trigger('click')
    expect(wrapper.find('[role="alert"]').text()).toContain('ab12cd34ef56')
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

// 政策組與合規對照兩個新入口：合規對照是稽核職能（admin/auditor），
// 政策組是設定職能（admin）。兩者分屬不同群組不是排版偏好——
// 判定結果與判定依據的讀者不同，混在同一區會讓稽核人員走進一個有寫入鈕的頁面
describe('MainLayout 政策組與合規對照的選單入口', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
  })

  it('admin 在稽核群看到合規對照、在系統設定群看到政策組', async () => {
    setUser(['admin'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()

    const text = wrapper.text()
    expect(text).toContain('合規對照')
    expect(text).toContain('政策組')
    const indexes = wrapper
      .findAllComponents({ name: 'ElMenuItem' })
      .map((item) => item.props('index'))
    expect(indexes).toContain('/compliance-map')
    expect(indexes).toContain('/policy-groups')
  })

  it('auditor 看得到合規對照與政策組（政策組只有唯讀入口，寫入動作在頁內依管理權限呈現）', async () => {
    setUser(['auditor'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()

    const text = wrapper.text()
    expect(text).toContain('合規對照')
    expect(text).toContain('政策組')
  })

  it('一般使用者兩個入口都看不到', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()

    const text = wrapper.text()
    expect(text).not.toContain('合規對照')
    expect(text).not.toContain('政策組')
  })
})

it('我的 agent 導覽位於一般使用者我的申請同層', async () => {
  localStorage.clear(); resetSessionForTests(); vi.clearAllMocks()
  getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
  // 我的 agent 只對「負責至少一個 agent 或允許自建」的人出現；
  // 本案例驗的是位置，故以負責人身分掛載。可見性的完整矩陣在 router/__tests__/entry-consistency.spec.js
  localStorage.setItem('user', JSON.stringify({ username: 'tester' }))
  setCapabilitiesForTests(permissionsFor(['user'], { owns: true }))
  getCurrentUserMock.mockResolvedValue(meBody(['user'], { owns: true }))
  const w = mountLayout(); await flushPromises()
  const menus = w.findAllComponents({ name: 'ElMenuItem' })
  const paths = menus.map(m => m.props('index'))
  expect(paths[paths.indexOf('/my-requests') + 1]).toBe('/my-agents')
  expect(menus.find(m => m.props('index') === '/my-agents').text()).toContain('我的 agent')
})

it('任務入口沿 audit:view 角色，普通人不見', async () => {
  for (const roles of [['user'], ['auditor']]) {
    setUser(roles); const w = mountLayout(); await flushPromises()
    const entries = w.findAllComponents({ name: 'ElMenuItem' }).map(item => item.props('index'))
    expect(entries.includes('/audit/agent-tasks')).toBe(roles.includes('auditor')); w.unmount()
  }
})

// —— 每日簽核站內提醒（側欄徽章）——
describe('MainLayout 每日簽核徽章', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 0, overdue_count: 0 } })
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const badge = (wrapper) => wrapper.find('[data-test="daily-review-badge"]')

  // 防：每位沒有簽核權限的使用者每 30 秒打一次用不到的端點並產生審計列
  it('無簽核權限不輪詢待簽天數', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    await flushPromises()
    vi.advanceTimersByTime(90000)
    await flushPromises()
    expect(getDailyReviewPendingCountMock).not.toHaveBeenCalled()
    expect(badge(wrapper).exists()).toBe(false)
  })

  it('有逾期時徽章帶危險色，只有期限內的日子帶警示色，0 時不顯示', async () => {
    setUser(['auditor'])
    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 4, overdue_count: 3 } })
    let wrapper = mountLayout()
    await flushPromises()
    expect(getDailyReviewPendingCountMock).toHaveBeenCalledWith({ skipErrorToast: true })
    expect(badge(wrapper).text()).toBe('4')
    expect(badge(wrapper).classes()).toContain('daily-review-badge--danger')
    wrapper.unmount()

    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 1, overdue_count: 0 } })
    wrapper = mountLayout()
    await flushPromises()
    expect(badge(wrapper).text()).toBe('1')
    expect(badge(wrapper).classes()).toContain('daily-review-badge--warning')
    wrapper.unmount()

    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 0, overdue_count: 0 } })
    wrapper = mountLayout()
    await flushPromises()
    expect(badge(wrapper).exists()).toBe(false)
  })

  // 防：徽章外框沿用 inline-block，在 40px 行高的選單列裡落到基線，像貼在文字右下的上標。
  // 測試環境不算版面，只能守住樣式規則本身；實際排版另以瀏覽器截圖對照
  it('選單徽章以 flex 與文字垂直置中', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'components', 'MainLayout.vue'), 'utf8')
    const rule = source.match(/\n\.menu-badge \{([^}]*)\}/)
    expect(rule).not.toBeNull()
    expect(rule[1]).toMatch(/display:\s*inline-flex;/)
    expect(rule[1]).toMatch(/align-items:\s*center;/)
    const content = source.match(/\.menu-badge :deep\(\.el-badge__content\) \{([^}]*)\}/)
    expect(content[1]).toMatch(/position:\s*static;/)
    expect(content[1]).toMatch(/transform:\s*none;/)
  })

  it('每 30 秒輪詢；失敗靜默不提示', async () => {
    const { ElMessage } = await import('element-plus')
    const errorSpy = vi.spyOn(ElMessage, 'error')
    setUser(['admin'])
    getDailyReviewPendingCountMock.mockRejectedValue(new Error('network down'))
    mountLayout()
    await flushPromises()
    vi.advanceTimersByTime(30000)
    await flushPromises()
    expect(getDailyReviewPendingCountMock).toHaveBeenCalledTimes(2)
    expect(errorSpy).not.toHaveBeenCalled()
    errorSpy.mockRestore()
  })

  it('簽核或處置告警後派事件，徽章立即重算', async () => {
    setUser(['auditor'])
    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 2, overdue_count: 1 } })
    const wrapper = mountLayout()
    await flushPromises()
    expect(getDailyReviewPendingCountMock).toHaveBeenCalledTimes(1)

    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 1, overdue_count: 0 } })
    window.dispatchEvent(new Event('ot-daily-reviews-changed'))
    await flushPromises()
    expect(getDailyReviewPendingCountMock).toHaveBeenCalledTimes(2)
    expect(badge(wrapper).text()).toBe('1')
  })

  it('有徽章時點操作日誌直接進每日簽核分頁，沒有時維持原路徑', async () => {
    setUser(['auditor'])
    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 2, overdue_count: 0 } })
    const wrapper = mountLayout()
    await flushPromises()
    const item = wrapper
      .findAllComponents({ name: 'ElMenuItem' })
      .find((c) => c.props('index') === '/audit-logs')
    expect(item.props('route')).toEqual({ path: '/audit-logs', query: { tab: 'reviews' } })
    wrapper.unmount()

    getDailyReviewPendingCountMock.mockResolvedValue({ data: { count: 0, overdue_count: 0 } })
    const plain = mountLayout()
    await flushPromises()
    const plainItem = plain
      .findAllComponents({ name: 'ElMenuItem' })
      .find((c) => c.props('index') === '/audit-logs')
    expect(plainItem.props('route')).toBeUndefined()
  })
})

describe('MainLayout 角色頁頂列', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    getSealStatusMock.mockResolvedValue(sealStatusWith(GUARD_HELD))
  })
  afterEach(() => {
    delete routeState.name
    routeState.path = '/dashboard'
  })

  it('新增角色頁頂列是「角色管理 › 新增角色」，不是首頁', async () => {
    setUser(['admin'])
    routeState.name = 'RoleNew'
    routeState.path = '/roles/new'
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const crumbs = wrapper.find('.current-path').text()
    expect(crumbs).toContain('角色管理')
    expect(crumbs).toContain('新增角色')
    expect(crumbs).not.toContain('首頁')
  }, 30000)

  it('編輯角色頁頂列帶出角色名並可回到列表', async () => {
    setUser(['admin'])
    setDetailSubject('稽核員')
    routeState.name = 'RoleDetail'
    routeState.path = '/roles/7'
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const crumbs = wrapper.find('.current-path').text()
    expect(crumbs).toContain('角色管理')
    expect(crumbs).toContain('稽核員')
    expect(crumbs).not.toContain('首頁')
    clearDetailSubject()
  })

  it('告警頁頂列是「稽核 › 告警」，群組名不可點', async () => {
    setUser(['admin'])
    routeState.path = '/alerts'
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const nav = wrapper.find('.current-path')
    expect(nav.text().replace(/\s+/g, '')).toBe('稽核›告警')
    expect(nav.findAll('a.crumb-link')).toHaveLength(0)
  })
})
