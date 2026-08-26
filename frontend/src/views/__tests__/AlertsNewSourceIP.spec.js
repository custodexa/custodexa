// 帳號新來源位址告警在告警列表的呈現（source-ip-forensics）。
//
// 這一類**沒有規則、也沒有指令文字**（`rule_id` 為 NULL、`rule_name` 存機器碼、
// `command` 為空字串）。照一般列渲染會得到「規則 new_source_ip 命中了一個空指令」
// ——兩個欄位同時說謊。位址就是這一列的內容本身，且必須一鍵進得去位址樞紐，
// 否則稽核員得自己複製位址、切樞紐、重設時間窗。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { createRouter, createWebHistory } from 'vue-router'
import Alerts from '../Alerts.vue'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.setConfig({ testTimeout: 20_000 })

const searchAlertsMock = vi.fn()

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
  getAlertRules: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAlertRule: vi.fn(),
  updateAlertRule: vi.fn(),
  deleteAlertRule: vi.fn(),
  getChannels: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createChannel: vi.fn(),
  updateChannel: vi.fn(),
  deleteChannel: vi.fn(),
  testChannel: vi.fn(),
}))

const IP = '203.0.113.5'

const newSourceAlert = (over = {}) => ({
  id: 21,
  rule_id: null,
  rule_name: 'new_source_ip',
  kind: 'new_source_ip',
  reason_code: 'new_source_ip_session',
  session_id: 'sess-021',
  user_id: 7,
  asset_id: 3,
  command: '',
  severity: 'medium',
  client_ip: IP,
  // 本地時區 2026-06-12 16:05（+08:00）
  triggered_at: '2026-06-12T08:05:00Z',
  ...over,
})

// 真路由（非 mock）：深連結的目的地與參數是本檔的斷言重心，
// stub 掉 router-link 等於把要驗的東西驗掉
const mountAlerts = () => {
  const router = createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/audit/workbench', component: { template: '<div />' } },
      { path: '/sessions/:id', component: { template: '<div />' } },
    ],
  })
  return mount(Alerts, { global: { plugins: [ElementPlus, router] } })
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['admin'] }))
  searchAlertsMock.mockResolvedValue({
    data: [newSourceAlert()],
    total: 1,
    page: 1,
    page_size: 20,
  })
})

describe('Alerts 新來源位址告警', () => {
  it('規則名欄顯示來源類別散文，不把機器碼丟給稽核員', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    const kind = wrapper.find('[data-test="alert-new-source-ip-kind"]')
    expect(kind.exists()).toBe(true)
    expect(kind.text()).toBe('帳號新來源位址')
    expect(wrapper.text()).not.toContain('new_source_ip')
  })

  it('指令欄改說位址＋「首次自此位址建線」，不留空白格', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    const cell = wrapper.find('[data-test="alert-new-source-ip"]')
    expect(cell.exists()).toBe(true)
    expect(cell.text()).toContain(IP)
    expect(cell.text()).toContain('首次自此位址建立連線')
    // 不得沿用「沒有指令文字」的通用句——這一列不是缺文字，是本來就沒有指令
    expect(wrapper.find('[data-test="alert-no-command"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="alert-degraded"]').exists()).toBe(false)
  })

  it('位址是深連結：位址樞紐＋觸發當日整日＋全部類別', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    const link = wrapper.find('[data-test="alert-new-source-ip-link"]')
    expect(link.exists()).toBe(true)
    const href = decodeURIComponent(link.attributes('href'))
    expect(href).toContain('/audit/workbench')
    expect(href).toContain('subject=ip')
    expect(href).toContain(`id=${IP}`)
    // 當日整日（本地時區）：起點 00:00:00、終點次日 00:00:00
    expect(href).toMatch(/from=2026-06-12T00:00:00/)
    expect(href).toMatch(/to=2026-06-13T00:00:00/)
    // 類別全部＝不寫 types（缺席＝全部，與工作台的 URL 三態一致）
    expect(href).not.toContain('types=')
  })

  it('會話缺失而沒有位址時不給連結，改說沒有可用的來源位址', async () => {
    searchAlertsMock.mockResolvedValue({
      data: [newSourceAlert({ client_ip: undefined })],
      total: 1,
      page: 1,
      page_size: 20,
    })
    const wrapper = mountAlerts()
    await flushPromises()
    expect(wrapper.find('[data-test="alert-new-source-ip-link"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="alert-new-source-ip"]').text()).toContain(
      '沒有可用的來源位址'
    )
  })

  it('審閱處置沿用（新 kind 不繞過既有審閱流程）', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    // 審閱狀態欄與審閱入口都照舊：新 kind 只換掉規則名與指令兩格的渲染
    expect(wrapper.text()).toContain('未審閱')
    const actions = wrapper.findAll('.el-button--primary.is-link, .el-button--warning.is-link')
    expect(actions.length).toBeGreaterThan(0)
    expect(wrapper.text()).toContain('檢視連線')
    expect(wrapper.text()).toContain('審閱')
  })

  it('規則類告警不受影響（新分支不吃掉既有渲染）', async () => {
    searchAlertsMock.mockResolvedValue({
      data: [
        {
          id: 1,
          rule_id: 1,
          rule_name: '刪除根目錄',
          kind: 'rule',
          reason_code: '',
          session_id: 'sess-001',
          user_id: 7,
          asset_id: 3,
          command: 'rm -rf /',
          severity: 'high',
          triggered_at: '2026-06-12T08:00:00Z',
        },
      ],
      total: 1,
      page: 1,
      page_size: 20,
    })
    const wrapper = mountAlerts()
    await flushPromises()
    expect(wrapper.find('[data-test="alert-new-source-ip"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('刪除根目錄')
    expect(wrapper.text()).toContain('rm -rf /')
  })
})
