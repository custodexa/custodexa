// 降級告警在告警列表的呈現。
//
// 降級告警**本來就沒有指令文字**（`command=""`、`rule_id` 為 NULL、
// `rule_name` 存的是機器碼）。若照一般列渲染，稽核員會看到一列「規則
// audit_degraded_span 命中了一個空指令」——兩個欄位同時說謊。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Alerts from '../Alerts.vue'
import zhTW from '@/i18n/locales/zh-TW.json'

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

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

const degradedAlert = {
  id: 9,
  rule_id: null,
  rule_name: 'audit_degraded_span',
  kind: 'audit_degraded',
  reason_code: 'audit_degraded_span',
  session_id: 'sess-009',
  user_id: 7,
  asset_id: 3,
  command: '',
  severity: 'medium',
  triggered_at: '2026-06-12T08:05:00Z',
}

const ruleAlert = {
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
}

const mountAlerts = () => mount(Alerts, { global: { plugins: [ElementPlus] } })

describe('Alerts 降級告警呈現', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.setItem('user', JSON.stringify({ username: 'tester', roles: ['auditor'] }))
  })

  it('降級告警渲染成狀態列＋原因，不留看起來像空指令的格子', async () => {
    searchAlertsMock.mockResolvedValue({ data: [degradedAlert], total: 1 })

    const wrapper = mountAlerts()
    await flushPromises()

    const cell = wrapper.find('[data-test="alert-degraded"]')
    expect(cell.exists()).toBe(true)
    expect(cell.text()).toContain(zhTW.commands.degrade.title)
    expect(cell.text()).toContain(zhTW.enum.commandAlertReason.audit_degraded_span)
  })

  it('降級告警不把機器碼當規則名丟給稽核員', async () => {
    searchAlertsMock.mockResolvedValue({ data: [degradedAlert], total: 1 })

    const wrapper = mountAlerts()
    await flushPromises()

    expect(wrapper.text()).toContain(zhTW.alerts.kindAuditDegraded)
    expect(wrapper.text()).not.toContain('audit_degraded_span')
  })

  it('規則告警不受影響（指令文字照舊、規則名照舊）', async () => {
    searchAlertsMock.mockResolvedValue({ data: [ruleAlert], total: 1 })

    const wrapper = mountAlerts()
    await flushPromises()

    expect(wrapper.find('[data-test="alert-degraded"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('rm -rf /')
    expect(wrapper.text()).toContain('刪除根目錄')
  })

  it('非降級類但沒有指令文字時，只陳述事實、不宣稱成因', async () => {
    searchAlertsMock.mockResolvedValue({
      data: [{ ...ruleAlert, command: '' }],
      total: 1,
    })

    const wrapper = mountAlerts()
    await flushPromises()

    const cell = wrapper.find('[data-test="alert-no-command"]')
    expect(cell.exists()).toBe(true)
    expect(cell.text()).toBe(zhTW.alerts.noCommandText)
  })
})
