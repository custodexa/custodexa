import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '../MainLayout.vue'
import { getCurrentUser } from '@/api/auth'
import { resetSessionForTests } from '@/utils/session'

// 側欄版本行的資料接線：值來自 MainLayout 既有的那一次
// /auth/me（refreshEntryFlags），不另打請求；取不到或請求失敗時不顯示、不報錯。
// mock 形狀比照 MainLayout.spec.js（同一元件、同一組外部依賴）
enableAutoUnmount(afterEach)

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ path: '/dashboard' }),
}))

vi.mock('@/api/auth', () => ({
  getCurrentUser: vi.fn(),
  logout: vi.fn(),
}))

vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: vi.fn(() => Promise.resolve({ count: 0, review_count: 0 })),
}))

vi.mock('@/api/seal', () => ({
  getSealStatus: vi.fn(() => Promise.resolve({ state: 'unsealed', instance_guard: { state: 'held' } })),
  unseal: vi.fn(),
}))

vi.mock('@/api/instanceGuard', () => ({
  getInstanceGuard: vi.fn(),
}))

const mountLayout = () =>
  mount(MainLayout, {
    global: {
      plugins: [ElementPlus],
      stubs: { 'router-view': true },
    },
  })

describe('MainLayout 側欄版本行', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    vi.clearAllMocks()
    localStorage.setItem('user', JSON.stringify({ username: 'tester', roles: ['user'] }))
  })

  it('/auth/me 帶發布版號時，側欄底部顯示「Custodexa <版本>」', async () => {
    getCurrentUser.mockResolvedValue({ username: 'tester', roles: ['user'], product_version: '1.13.0' })
    const wrapper = mountLayout()
    await flushPromises()
    const row = wrapper.find('.sidebar .sidebar-version')
    expect(row.exists()).toBe(true)
    expect(row.text()).toBe('Custodexa 1.13.0')
    // 在選單捲動區之外：不是 el-menu 的子孫
    expect(wrapper.find('.sidebar-menu .sidebar-version').exists()).toBe(false)
    // 與入口資格共用同一次 /auth/me，不另打請求
    expect(getCurrentUser).toHaveBeenCalledTimes(1)
  })

  it('攔截器包一層 data 的回應形狀也讀得到', async () => {
    getCurrentUser.mockResolvedValue({ data: { username: 'tester', product_version: '1.13.0' } })
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('.sidebar-version').text()).toBe('Custodexa 1.13.0')
  })

  it('開發建置回 dev 時不顯示', async () => {
    getCurrentUser.mockResolvedValue({ username: 'tester', product_version: 'dev' })
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('.sidebar-version').exists()).toBe(false)
  })

  it('回應缺 product_version 時不顯示', async () => {
    getCurrentUser.mockResolvedValue({ username: 'tester', roles: ['user'] })
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('.sidebar-version').exists()).toBe(false)
  })

  it('/auth/me 失敗時不顯示、不報錯', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    getCurrentUser.mockRejectedValue(new Error('network down'))
    const wrapper = mountLayout()
    await flushPromises()
    expect(wrapper.find('.sidebar-version').exists()).toBe(false)
    // 側欄其餘部分照常
    expect(wrapper.find('.sidebar-menu').exists()).toBe(true)
    expect(consoleError).not.toHaveBeenCalled()
    consoleError.mockRestore()
  })

  it('收合態只留版號', async () => {
    localStorage.setItem('ot-sidebar-collapsed', 'true')
    getCurrentUser.mockResolvedValue({ username: 'tester', product_version: '1.13.0' })
    const wrapper = mountLayout()
    await flushPromises()
    const row = wrapper.find('.sidebar-version')
    expect(row.classes()).toContain('collapsed')
    expect(row.text()).toBe('1.13.0')
    expect(row.attributes('title')).toBe('Custodexa 1.13.0')
  })
})
