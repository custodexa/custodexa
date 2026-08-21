import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import MainLayout from '@/components/MainLayout.vue'

// 工作台的導覽位置（auditor-workbench 6.1）：審計群**首項**＋麵包屑映射。
// 掛載成本高，故本檔只做三次掛載（順序、角色、麵包屑各一）。

enableAutoUnmount(afterEach)

const routePath = { value: '/dashboard' }

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({
    get path() {
      return routePath.value
    },
  }),
}))

vi.mock('@/api/auth', () => ({
  getCurrentUser: vi.fn(),
  getMFASetup: vi.fn(),
  enableMFA: vi.fn(),
  disableMFA: vi.fn(),
  logout: vi.fn(),
}))

const mountLayout = () =>
  mount(MainLayout, {
    global: { plugins: [ElementPlus], stubs: { 'router-view': true } },
  })

const setUser = (roles) => {
  localStorage.setItem(
    'user',
    JSON.stringify({ username: 'tester', roles, is_approver: false })
  )
}

describe('審計群導覽', () => {
  beforeEach(() => {
    localStorage.clear()
    routePath.value = '/dashboard'
  })

  it('調查工作台排在審計群首項（調查是最高頻入口）', async () => {
    setUser(['auditor'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const text = wrapper.text()
    expect(text).toContain('調查工作台')
    expect(text.indexOf('調查工作台')).toBeLessThan(text.indexOf('操作日誌'))
  })

  it('一般使用者看不到入口', async () => {
    setUser(['user'])
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).not.toContain('調查工作台')
  })

  it('麵包屑映射到工作台標題（不落回「首頁」）', async () => {
    setUser(['admin'])
    routePath.value = '/audit/workbench'
    const wrapper = mountLayout()
    await wrapper.vm.$nextTick()
    const crumb = wrapper.find('.current-path')
    expect(crumb.exists()).toBe(true)
    expect(crumb.text()).toBe('調查工作台')
  })
})
