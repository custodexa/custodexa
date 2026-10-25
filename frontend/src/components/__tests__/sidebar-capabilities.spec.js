import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '../MainLayout.vue'
import { MENU_GROUPS } from '../sidebarMenu'
import { resetSessionForTests } from '@/utils/session'
import { setCapabilitiesForTests } from '@/composables/useCapabilities'
import { buildSidebarModel, prefsStorageKey, readSidebarPrefs, writeSidebarPrefs } from '@/composables/useSidebarNav'
import { meBody, permissionsFor } from '@/composables/__tests__/capabilityFixtures'

// 側欄分組呈現：分組收合、常用釘選、過濾後單組攤平、每使用者偏好。
// 只驗：多組可收合、單組攤平；釘選置頂不重複且取消回原位置；失權／未知釘選不顯示；
// 偏好不跨帳號；保持整條側欄收合、目前位置、版本行與鍵盤操作。
enableAutoUnmount(afterEach)

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ path: '/assets' }),
}))
const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
  logout: vi.fn(),
}))
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: vi.fn(() => Promise.resolve({ count: 0, review_count: 0 })),
}))
vi.mock('@/api/seal', () => ({
  getSealStatus: vi.fn(() => Promise.resolve({ state: 'unsealed' })),
  unseal: vi.fn(),
}))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewPendingCount: vi.fn(() => Promise.resolve({ data: { count: 0, overdue_count: 0 } })),
}))

const items = (groups) => groups.flatMap((g) => g.items.map((i) => i.id))
const everything = () => true
const none = { collapsed: [], pinned: [] }

describe('側欄模型（純函式）', () => {
  it('每個組與項目都有穩定 ID，/users 與 /users?kind=agent 各自一個', () => {
    const ids = MENU_GROUPS.flatMap((g) => g.items.map((i) => i.id))
    expect(new Set(ids).size).toBe(ids.length)
    expect(MENU_GROUPS.every((g) => g.id)).toBe(true)
    expect(ids).toContain('users')
    expect(ids).toContain('agent-principals')
    // 34 個有選單項的入口（/profile 在帳號選單）＋/users?kind=agent 別名
    expect(MENU_GROUPS.flatMap((g) => g.items)).toHaveLength(35)
  })

  it('多組各自可收合；只剩一個來源組時攤平且不帶收合狀態', () => {
    const model = buildSidebarModel(MENU_GROUPS, everything, { collapsed: ['audit'], pinned: [] })
    expect(model.flat).toBe(false)
    expect(model.groups.find((g) => g.id === 'audit').collapsed).toBe(true)
    expect(model.groups.find((g) => g.id === 'assets').collapsed).toBe(false)

    const onlyOverview = buildSidebarModel(MENU_GROUPS, (i) => ['dashboard', 'workspace'].includes(i.id), {
      collapsed: ['overview'],
      pinned: [],
    })
    expect(onlyOverview.flat).toBe(true)
    expect(onlyOverview.groups).toHaveLength(1)
    expect(onlyOverview.groups[0].collapsed).toBe(false) // 單組不顯示收合控制，就不能被收合
  })

  it('釘選置頂、不重複；取消釘選回原位置；來源組計數在釘選移出之前算', () => {
    const base = buildSidebarModel(MENU_GROUPS, everything, none)
    const pinned = buildSidebarModel(MENU_GROUPS, everything, { collapsed: [], pinned: ['alerts', 'users'] })
    expect(pinned.pinned.map((i) => i.id)).toEqual(['alerts', 'users'])
    expect(items(pinned.groups)).not.toContain('alerts')
    expect(items(pinned.groups)).not.toContain('users')
    expect(items(pinned.groups)).toContain('agent-principals')
    expect(pinned.flat).toBe(false)
    const restored = buildSidebarModel(MENU_GROUPS, everything, none)
    expect(items(restored.groups)).toEqual(items(base.groups))

    // 全組項目都被釘選時該組消失，但仍算一個來源組（不因此攤平）
    const onlyApproval = buildSidebarModel(MENU_GROUPS, (i) => i.id === 'approvals' || i.id === 'dashboard', {
      collapsed: [],
      pinned: ['approvals'],
    })
    expect(onlyApproval.flat).toBe(false)
    expect(onlyApproval.groups.map((g) => g.id)).toEqual(['overview'])
  })

  it('失權或未知的釘選不顯示：收藏不是許可', () => {
    const canSee = (i) => i.id !== 'users'
    const model = buildSidebarModel(MENU_GROUPS, canSee, { collapsed: [], pinned: ['users', 'no-such-item', 'alerts'] })
    expect(model.pinned.map((i) => i.id)).toEqual(['alerts'])
    expect(items(model.groups)).not.toContain('users')
  })

  it('偏好格式：壞資料、舊版本、型別錯誤一律回預設；不跨帳號', () => {
    localStorage.clear()
    writeSidebarPrefs(7, { collapsed: ['audit'], pinned: ['alerts'] })
    expect(readSidebarPrefs(7)).toEqual({ collapsed: ['audit'], pinned: ['alerts'] })
    expect(readSidebarPrefs(8)).toEqual({ collapsed: [], pinned: [] })
    expect(readSidebarPrefs(null)).toEqual({ collapsed: [], pinned: [] })
    localStorage.setItem(prefsStorageKey(7), '{not json')
    expect(readSidebarPrefs(7)).toEqual({ collapsed: [], pinned: [] })
    localStorage.setItem(prefsStorageKey(7), JSON.stringify({ v: 99, collapsed: [], pinned: ['a'] }))
    expect(readSidebarPrefs(7)).toEqual({ collapsed: [], pinned: [] })
    localStorage.setItem(prefsStorageKey(7), JSON.stringify({ v: 1, collapsed: 'audit', pinned: [1] }))
    expect(readSidebarPrefs(7)).toEqual({ collapsed: [], pinned: [] })
    expect(writeSidebarPrefs(null, none)).toBe(false)
  })
})

describe('MainLayout 的側欄呈現', () => {
  const mountLayout = () =>
    mount(MainLayout, { global: { plugins: [ElementPlus], stubs: { 'router-view': true } } })
  const grant = (roles, userId = 5) => {
    setCapabilitiesForTests(permissionsFor(roles), { userId })
    getCurrentUserMock.mockResolvedValue(meBody(roles, {}, { id: userId }))
  }
  const visibleIndexes = (wrapper) =>
    wrapper
      .findAllComponents({ name: 'ElMenuItem' })
      .filter((i) => i.element.style.display !== 'none')
      .map((i) => i.props('index'))

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    getCurrentUserMock.mockReset()
  })

  it('多組時組標題是可聚焦的按鈕，收合後該組項目隱藏、展開回復，偏好寫入本人鍵', async () => {
    grant(['admin'])
    const wrapper = mountLayout()
    await flushPromises()
    const toggle = wrapper.find('[data-test="group-toggle-audit"]')
    expect(toggle.element.tagName).toBe('BUTTON')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(visibleIndexes(wrapper)).toContain('/audit-logs')

    await toggle.trigger('click')
    expect(wrapper.find('[data-test="group-toggle-audit"]').attributes('aria-expanded')).toBe('false')
    expect(visibleIndexes(wrapper)).not.toContain('/audit-logs')
    expect(visibleIndexes(wrapper)).toContain('/users') // 其他組不受影響
    expect(JSON.parse(localStorage.getItem(prefsStorageKey(5))).collapsed).toEqual(['audit'])
    expect(localStorage.getItem(prefsStorageKey(6))).toBeNull()

    await wrapper.find('[data-test="group-toggle-audit"]').trigger('click')
    expect(visibleIndexes(wrapper)).toContain('/audit-logs')
  })

  it('組標題可用鍵盤操作：可取得焦點，Enter 與 Space 的鍵盤事件不被攔截，按瀏覽器的啟用規則展開收合', async () => {
    grant(['admin'])
    const wrapper = mount(MainLayout, {
      attachTo: document.body,
      global: { plugins: [ElementPlus], stubs: { 'router-view': true } },
    })
    await flushPromises()
    const sel = '[data-test="group-toggle-audit"]'
    const btn = () => wrapper.find(sel).element
    btn().focus()
    expect(document.activeElement).toBe(btn())
    expect(btn().disabled).toBe(false)
    expect(btn().getAttribute('tabindex')).not.toBe('-1')

    // jsdom 不會把按鍵自動轉成 click；這裡送真的鍵盤事件，確認沒有任何處理器攔下（defaultPrevented），
    // 再依瀏覽器對原生 button 的規則啟用：Enter 在 keydown 啟用，Space 在 keyup 啟用。
    const press = (key, activateOn) => {
      const el = btn()
      const fire = (type) => {
        const ev = new KeyboardEvent(type, { key, code: key === ' ' ? 'Space' : key, bubbles: true, cancelable: true })
        el.dispatchEvent(ev)
        return ev
      }
      const down = fire('keydown')
      const up = fire('keyup')
      expect(down.defaultPrevented).toBe(false)
      expect(up.defaultPrevented).toBe(false)
      if (activateOn === 'keydown' ? !down.defaultPrevented : !up.defaultPrevented) el.click()
    }
    expect(wrapper.find(sel).attributes('aria-expanded')).toBe('true')
    press('Enter', 'keydown')
    await flushPromises()
    expect(wrapper.find(sel).attributes('aria-expanded')).toBe('false')
    expect(visibleIndexes(wrapper)).not.toContain('/audit-logs')
    btn().focus()
    press(' ', 'keyup')
    await flushPromises()
    expect(wrapper.find(sel).attributes('aria-expanded')).toBe('true')
    expect(visibleIndexes(wrapper)).toContain('/audit-logs')
  })

  it('釘選的項目出現在頂部「常用」且原組不重複；取消釘選回到原組', async () => {
    grant(['admin'])
    const wrapper = mountLayout()
    await flushPromises()
    await wrapper.find('[data-test="pin-alerts"]').trigger('click')
    let indexes = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((i) => i.props('index'))
    expect(indexes[0]).toBe('/alerts')
    expect(indexes.filter((p) => p === '/alerts')).toHaveLength(1)
    expect(wrapper.find('[data-test="pinned-label"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="pin-alerts"]').attributes('aria-pressed')).toBe('true')

    await wrapper.find('[data-test="pin-alerts"]').trigger('click')
    indexes = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((i) => i.props('index'))
    expect(indexes[0]).toBe('/dashboard')
    expect(indexes).toContain('/alerts')
    expect(wrapper.find('[data-test="pinned-label"]').exists()).toBe(false)
  })

  it('失權的釘選不顯示；偏好不跨帳號', async () => {
    writeSidebarPrefs(5, { collapsed: [], pinned: ['users', 'alerts'] })
    grant(['user'], 5) // 一般使用者沒有 user:manage 與 audit:view
    const wrapper = mountLayout()
    await flushPromises()
    const indexes = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((i) => i.props('index'))
    expect(indexes).not.toContain('/users')
    expect(indexes).not.toContain('/alerts')
    expect(wrapper.find('[data-test="pinned-label"]').exists()).toBe(false)
    wrapper.unmount()

    resetSessionForTests()
    grant(['admin'], 9) // 另一個帳號沒有這份偏好
    const other = mountLayout()
    await flushPromises()
    expect(other.find('[data-test="pinned-label"]').exists()).toBe(false)
  })

  it('已登入者至少看得到總覽、資產、連線三組（登入即可的入口），所以現況不會攤平；攤平由模型函式涵蓋', async () => {
    setCapabilitiesForTests([], { userId: 5 })
    getCurrentUserMock.mockResolvedValue({ id: 5, permissions: [], scope_summary: [] })
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.findAll('[data-test^="group-toggle-"]').length).toBeGreaterThan(1)
  })

  it('整條側欄收合時圖示列保留全部項目、不顯示組標題與釘選鈕；版本行與目前位置照常', async () => {
    localStorage.setItem('ot-sidebar-collapsed', 'true')
    // 不預載能力：讓版面自己向 /auth/me 取（版本行與能力共用這一次請求）
    getCurrentUserMock.mockResolvedValue(meBody(['admin'], {}, { id: 5, product_version: '1.18.0' }))
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('.sidebar-menu').classes()).toContain('el-menu--collapse')
    expect(wrapper.findAll('[data-test^="pin-"]')).toHaveLength(0)
    expect(visibleIndexes(wrapper)).toContain('/audit-logs')
    expect(wrapper.find('.sidebar-version').text()).toBe('1.18.0')
    expect(wrapper.findComponent({ name: 'ElMenu' }).props('defaultActive')).toBe('/assets')
  })
})
