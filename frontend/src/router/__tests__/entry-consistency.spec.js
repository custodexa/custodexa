import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { Bot } from 'lucide-vue-next'
import MainLayout from '@/components/MainLayout.vue'
import router, { createAuthGuard } from '../index'
import { resetSessionForTests, setAccessToken } from '@/utils/session'

// 入口一致性：**選單看得到 ⇔ 直接輸入網址進得去**。
//
// 兩邊都走真的東西：選單是實際掛載的 MainLayout 渲染出來的項目，
// 路由是註冊表解析出的 meta 交給實際的認證守衛。任一身分、任一選單項目
// 兩邊結論不同就是紅——這正是「看不到也進得去」（管理者直打我的申請）
// 與「看得到卻沒事可做」（無 agent 的一般使用者看見我的 agent）兩類缺陷的形狀。

enableAutoUnmount(afterEach)

vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    useRouter: () => ({ push: vi.fn() }),
    useRoute: () => ({ path: '/dashboard', query: {} }),
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

// 身分：快取（登入回應）與 /auth/me 回同一份，模擬已登入且資料一致的穩態
const persona = (name, roles, { approver = roles.includes('approver'), owns = false, create = false } = {}) => ({
  name,
  user: {
    username: 'tester',
    roles,
    is_approver: approver,
    owns_agents: owns,
    can_self_create_agent: create,
  },
})

// 對照表「誰會看到我的 agent」七列（第六、七列各含管理者與稽核人員兩種身分）
const AGENT_TABLE = [
  { row: 1, ...persona('一般使用者，負責 agent', ['user'], { owns: true }), myAgents: true },
  { row: 2, ...persona('一般使用者，沒有 agent，允許自建', ['user'], { create: true }), myAgents: true },
  { row: 3, ...persona('一般使用者，沒有 agent，不允許自建', ['user']), myAgents: false },
  { row: 4, ...persona('系統管理者，負責 agent', ['admin'], { owns: true }), myAgents: true },
  { row: 5, ...persona('稽核人員，負責 agent', ['auditor'], { owns: true }), myAgents: true },
  { row: 6, ...persona('系統管理者，沒有 agent，允許自建', ['admin'], { create: true }), myAgents: true },
  { row: 6, ...persona('稽核人員，沒有 agent，允許自建', ['auditor'], { create: true }), myAgents: true },
  { row: 7, ...persona('系統管理者，沒有 agent，不允許自建', ['admin']), myAgents: false },
  { row: 7, ...persona('稽核人員，沒有 agent，不允許自建', ['auditor']), myAgents: false },
]

// 選單實際分出的其餘身分（審核疊加、群組審核方、多角色）
const EXTRA_PERSONAS = [
  persona('一般使用者＋審核角色', ['user', 'approver']),
  persona('群組審核方（roles 無 approver）', ['user'], { approver: true }),
  persona('稽核人員＋審核角色', ['auditor', 'approver']),
  persona('系統管理者＋審核角色，負責 agent', ['admin', 'approver'], { owns: true }),
  persona('多角色 user＋auditor', ['user', 'auditor']),
]

const ALL_PERSONAS = [...AGENT_TABLE, ...EXTRA_PERSONAS]

const useUser = (user) => {
  localStorage.setItem('user', JSON.stringify(user))
  getCurrentUserMock.mockResolvedValue({ ...user })
}

const menuFor = async (user) => {
  useUser(user)
  const wrapper = mount(MainLayout, {
    global: { plugins: [ElementPlus], stubs: { 'router-view': true } },
  })
  await flushPromises()
  const items = wrapper.findAllComponents({ name: 'ElMenuItem' })
  const paths = items.map((item) => item.props('index'))
  wrapper.unmount()
  return paths
}

const guard = createAuthGuard()

// 守衛放行＝next() 不帶參數；導走（/dashboard）或要求登入皆視為不放行
const guardAllows = async (user, path) => {
  useUser(user)
  const resolved = router.resolve(path)
  const next = vi.fn()
  await guard({ path: resolved.path, meta: resolved.meta }, { path: '/', meta: {} }, next)
  expect(next).toHaveBeenCalledTimes(1)
  return next.mock.calls[0].length === 0
}

describe('入口一致性：選單可見 ⇔ 路由放行', () => {
  const menus = new Map()
  let catalog = []

  // 每個身分只掛載一次（掛載成本高），各案例共用同一份選單結果
  beforeAll(async () => {
    for (const p of ALL_PERSONAS) {
      localStorage.clear()
      menus.set(p.name, await menuFor(p.user))
    }
    catalog = [...new Set([...menus.values()].flat())]
  }, 60000)

  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    setAccessToken('entry-consistency')
  })

  it('各身分的選單合起來涵蓋全部選單項目', async () => {
    // glob 而非靜態 import：選單宣告檔不存在時只讓本案例紅，不拖垮整支檔案
    const found = Object.values(import.meta.glob('../../components/sidebarMenu.js', { eager: true }))
    expect(found, '選單宣告檔 components/sidebarMenu.js 不存在').toHaveLength(1)
    const { MENU_GROUPS } = found[0]
    const declared = MENU_GROUPS.flatMap((group) => group.items.map((item) => item.path))
    expect([...catalog].sort()).toEqual([...declared].sort())
  })

  it.each(ALL_PERSONAS.map((p) => [p.name, p]))('%s：每個選單項目的可見與放行一致', async (_name, p) => {
    const visible = new Set(menus.get(p.name))
    const mismatches = []
    for (const path of catalog) {
      const allowed = await guardAllows(p.user, path)
      if (visible.has(path) !== allowed) {
        mismatches.push(`${path} 選單${visible.has(path) ? '可見' : '不可見'}、路由${allowed ? '放行' : '擋下'}`)
      }
    }
    expect(mismatches).toEqual([])
  })

  it.each(AGENT_TABLE.map((p) => [p.row, p.name, p]))('對照表第 %i 列「%s」：我的 agent 可見與放行皆符合', async (_row, _name, p) => {
    expect(menus.get(p.name).includes('/my-agents')).toBe(p.myAgents)
    expect(await guardAllows(p.user, '/my-agents')).toBe(p.myAgents)
  })

  it('直接輸入網址被擋時導回 /dashboard（比照既有守衛行為）', async () => {
    const cases = [
      [persona('一般使用者無 agent', ['user']).user, '/my-agents'],
      [persona('系統管理者', ['admin']).user, '/my-requests'],
      [persona('系統管理者', ['admin']).user, '/my-connections'],
      [persona('稽核人員', ['auditor']).user, '/my-requests'],
      [persona('稽核人員', ['auditor']).user, '/my-connections'],
    ]
    for (const [user, path] of cases) {
      useUser(user)
      const resolved = router.resolve(path)
      const next = vi.fn()
      await guard({ path: resolved.path, meta: resolved.meta }, { path: '/', meta: {} }, next)
      expect(next, `${user.roles.join('+')} ${path}`).toHaveBeenCalledWith('/dashboard')
    }
  })
})

describe('我的 agent 選單圖示', () => {
  beforeEach(() => {
    localStorage.clear()
    resetSessionForTests()
    getCurrentUserMock.mockReset()
  })

  it('用機器人圖示（與我的 agent 空白頁同一個），與我的申請區分', async () => {
    useUser(persona('一般使用者，負責 agent', ['user'], { owns: true }).user)
    const wrapper = mount(MainLayout, {
      global: { plugins: [ElementPlus], stubs: { 'router-view': true } },
    })
    await flushPromises()
    const items = wrapper.findAllComponents({ name: 'ElMenuItem' })
    const myAgents = items.find((item) => item.props('index') === '/my-agents')
    const myRequests = items.find((item) => item.props('index') === '/my-requests')
    expect(myAgents.findComponent(Bot).exists()).toBe(true)
    expect(myRequests.findComponent(Bot).exists()).toBe(false)
  })
})
