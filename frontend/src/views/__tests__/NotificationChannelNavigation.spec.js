import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '@/components/MainLayout.vue'
import NotificationChannels from '../NotificationChannels.vue'
import router, { createAuthGuard } from '@/router'
import { ENTRY_RULES } from '@/router/entryRules'
import { MENU_GROUPS } from '@/components/sidebarMenu'
import { resetSessionForTests, setAccessToken } from '@/utils/session'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { prefsStorageKey } from '@/composables/useSidebarNav'
import { meBody, permissionsFor } from '@/composables/__tests__/capabilityFixtures'

// 通知通道獨立頁：系統設定下的入口、直接網址、麵包屑與側欄偏好。
// 側欄與守衛都走真實元件與真實路由表；面板用真實 NotificationChannelPanel，只 mock 網路層。

enableAutoUnmount(afterEach)

// element-plus 表格掛載時會觀察 DOM；測試環境的 MutationObserver 不支援，與告警頁測試同樣以空實作代替
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const routeState = vi.hoisted(() => ({ path: '/dashboard' }))
vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    useRouter: () => ({ push: vi.fn() }),
    useRoute: () => ({ path: routeState.path, query: {} }),
  }
})

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

const getChannelsMock = vi.fn()
vi.mock('@/api/alerts', () => ({
  getChannels: (...a) => getChannelsMock(...a),
  createChannel: vi.fn(),
  updateChannel: vi.fn(),
  deleteChannel: vi.fn(),
  testChannel: vi.fn(),
}))

const CHANNEL_PATH = '/notification-channels'
const CHANNEL_ONLY = ['notification_channel:manage']

const grant = (perms, userId = 5) => {
  setCapabilitiesForTests(perms, { userId })
  getCurrentUserMock.mockResolvedValue({ ...meBody(['user'], {}, { id: userId }), permissions: perms })
}
const mountLayout = () => mount(MainLayout, { global: { plugins: [ElementPlus], stubs: { 'router-view': true } } })
const menuIndexes = (wrapper) => wrapper.findAllComponents({ name: 'ElMenuItem' }).map((i) => i.props('index'))
const guard = createAuthGuard()
const guardAllows = async (path) => {
  const resolved = router.resolve(path)
  const next = vi.fn()
  await guard({ path: resolved.path, meta: resolved.meta }, { path: '/', meta: {} }, next)
  expect(next).toHaveBeenCalledTimes(1)
  return next.mock.calls[0].length === 0
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetSessionForTests()
  setAccessToken('channel-navigation')
  resetCapabilities()
  routeState.path = '/dashboard'
  getChannelsMock.mockResolvedValue({ data: [] })
})

describe('通知通道入口（系統設定）', () => {
  it('有通道管理能力而無稽核能力者：側欄在系統設定下出現，直接網址放行', async () => {
    grant(CHANNEL_ONLY)
    const wrapper = mountLayout()
    await flushPromises()
    const settings = MENU_GROUPS.find((g) => g.id === 'settings')
    expect(settings.items.map((i) => i.path)).toContain(CHANNEL_PATH)
    expect(menuIndexes(wrapper)).toContain(CHANNEL_PATH)
    expect(wrapper.find('[data-test="pin-notification-channels"]').exists()).toBe(true)
    // 該主體沒有稽核能力
    expect(menuIndexes(wrapper)).not.toContain('/audit-logs')
    expect(await guardAllows(CHANNEL_PATH)).toBe(true)
  })

  it('沒有通道管理能力者：入口不見，直接網址導回儀表板（含持稽核與系統告警能力者）', async () => {
    for (const perms of [[], permissionsFor(['user']), ['audit:view', 'systemalert:manage', 'alertrule:manage']]) {
      resetCapabilities()
      grant(perms)
      const wrapper = mountLayout()
      await flushPromises()
      expect(menuIndexes(wrapper), perms.join(',')).not.toContain(CHANNEL_PATH)
      expect(await guardAllows(CHANNEL_PATH), perms.join(',')).toBe(false)
      const resolved = router.resolve(CHANNEL_PATH)
      const next = vi.fn()
      await guard({ path: resolved.path, meta: resolved.meta }, { path: '/', meta: {} }, next)
      expect(next).toHaveBeenCalledWith('/dashboard')
      wrapper.unmount()
    }
  })

  it('入口只看 notification_channel:manage，不另要求告警檢視；規則與路由 meta 同源', () => {
    expect(ENTRY_RULES[CHANNEL_PATH]).toEqual({ permissionsAll: ['notification_channel:manage'] })
    expect(router.resolve(CHANNEL_PATH).meta.permissionsAll).toEqual(['notification_channel:manage'])
    expect(router.resolve(CHANNEL_PATH).name).toBe('NotificationChannels')
  })

  it('麵包屑與標題重用通知通道名稱', async () => {
    routeState.path = CHANNEL_PATH
    grant(CHANNEL_ONLY)
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('.current-path .crumb-current').text()).toBe('通知通道')
  })
})

describe('通知通道頁殼', () => {
  const mountPage = () => mount(NotificationChannels, { global: { plugins: [ElementPlus] } })

  it('直接開頁：掛載即發出通道列表 GET 一次，回兩筆後兩筆都列出（真實面板）', async () => {
    getChannelsMock.mockResolvedValue({
      data: [
        { id: 1, name: 'ops-webhook', type: 'webhook', url: 'https://hooks.example.test/***', enabled: true, has_secret: true },
        { id: 2, name: 'sec-slack', type: 'slack', url: 'https://slack.example.test/***', enabled: true, has_secret: false },
      ],
    })
    const wrapper = mountPage()
    await flushPromises()
    expect(getChannelsMock).toHaveBeenCalledTimes(1)
    expect(wrapper.findComponent({ name: 'NotificationChannelPanel' }).exists()).toBe(true)
    const text = wrapper.text()
    expect(text).toContain('ops-webhook')
    expect(text).toContain('sec-slack')
  })

  it('手動重新整理再發一次列表 GET', async () => {
    const wrapper = mountPage()
    await flushPromises()
    expect(getChannelsMock).toHaveBeenCalledTimes(1)
    await wrapper.find('[data-test="channels-refresh"]').trigger('click')
    await flushPromises()
    expect(getChannelsMock).toHaveBeenCalledTimes(2)
  })
})

describe('通知通道入口的釘選、收合與偏好', () => {
  it('可釘選置頂且原組不重複、取消回原組；收合系統設定組時隱藏', async () => {
    grant(permissionsFor(['admin']))
    const wrapper = mountLayout()
    await flushPromises()
    await wrapper.find('[data-test="pin-notification-channels"]').trigger('click')
    let indexes = menuIndexes(wrapper)
    expect(indexes[0]).toBe(CHANNEL_PATH)
    expect(indexes.filter((p) => p === CHANNEL_PATH)).toHaveLength(1)
    expect(wrapper.find('[data-test="pin-notification-channels"]').attributes('aria-pressed')).toBe('true')
    await wrapper.find('[data-test="pin-notification-channels"]').trigger('click')
    indexes = menuIndexes(wrapper)
    expect(indexes[0]).toBe('/dashboard')
    expect(indexes).toContain(CHANNEL_PATH)

    await wrapper.find('[data-test="group-toggle-settings"]').trigger('click')
    const visible = wrapper
      .findAllComponents({ name: 'ElMenuItem' })
      .filter((i) => i.element.style.display !== 'none')
      .map((i) => i.props('index'))
    expect(visible).not.toContain(CHANNEL_PATH)
    expect(visible).toContain('/dashboard')
  })

  it('已釘選後失去通道能力：釘選項消失；偏好寫在本人鍵下、不跨帳號', async () => {
    grant(CHANNEL_ONLY, 5)
    let wrapper = mountLayout()
    await flushPromises()
    await wrapper.find('[data-test="pin-notification-channels"]').trigger('click')
    expect(JSON.parse(localStorage.getItem(prefsStorageKey(5))).pinned).toEqual(['notification-channels'])
    expect(localStorage.getItem(prefsStorageKey(6))).toBeNull()
    wrapper.unmount()

    // 同一帳號失去通道能力：已釘選的項目依既有規則消失
    resetSessionForTests()
    setAccessToken('channel-navigation')
    grant(permissionsFor(['user']), 5)
    wrapper = mountLayout()
    await flushPromises()
    expect(menuIndexes(wrapper)).not.toContain(CHANNEL_PATH)
    expect(wrapper.find('[data-test="pinned-label"]').exists()).toBe(false)
    wrapper.unmount()

    // 另一個帳號沒有這份偏好
    resetSessionForTests()
    setAccessToken('channel-navigation')
    grant(CHANNEL_ONLY, 9)
    wrapper = mountLayout()
    await flushPromises()
    expect(menuIndexes(wrapper)).toContain(CHANNEL_PATH)
    expect(wrapper.find('[data-test="pinned-label"]').exists()).toBe(false)
  })
})
