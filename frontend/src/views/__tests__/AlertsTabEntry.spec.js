import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Alerts from '../Alerts.vue'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 告警頁依頁籤能力決定預設頁籤與可呼叫的 API：只持有某頁籤能力的人，
// 進頁後不得打自己無權的 API（否則冒 403 訊息）。

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
const getAlertRulesMock = vi.fn()
const getChannelsMock = vi.fn()
const getSystemAlertTypesMock = vi.fn()

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...a) => searchAlertsMock(...a),
  getAlertRules: (...a) => getAlertRulesMock(...a),
  getChannels: (...a) => getChannelsMock(...a),
  createAlertRule: vi.fn(),
  updateAlertRule: vi.fn(),
  deleteAlertRule: vi.fn(),
  reviewAlert: vi.fn(),
  createChannel: vi.fn(),
  updateChannel: vi.fn(),
  deleteChannel: vi.fn(),
  testChannel: vi.fn(),
}))
vi.mock('@/api/systemAlerts', () => ({
  getSystemAlertTypes: (...a) => getSystemAlertTypesMock(...a),
  updateSystemAlertSeverity: vi.fn(),
  getSystemAlertDetail: vi.fn(),
}))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))

const mountAlerts = () => mount(Alerts, { global: { plugins: [ElementPlus] } })
const activeTabName = (wrapper) => wrapper.findComponent({ name: 'ElTabs' }).props('modelValue')
const tabNames = (wrapper) => wrapper.findAllComponents({ name: 'ElTabPane' }).map((p) => p.props('name'))

describe('Alerts 頁籤預設與 API 呼叫依能力', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    resetCapabilities()
    searchAlertsMock.mockResolvedValue({ data: [], total: 0 })
    getAlertRulesMock.mockResolvedValue({ data: [] })
    getChannelsMock.mockResolvedValue({ data: [] })
    getSystemAlertTypesMock.mockResolvedValue({ data: [] })
  })

  it('只有 systemalert:manage：預設系統告警頁籤，不打指令告警與規則 API', async () => {
    setCapabilitiesForTests(['systemalert:manage'])
    const wrapper = mountAlerts()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('systemAlerts')
    expect(tabNames(wrapper)).toEqual(['systemAlerts'])
    expect(searchAlertsMock).not.toHaveBeenCalled()
    expect(getAlertRulesMock).not.toHaveBeenCalled()
    expect(getChannelsMock).not.toHaveBeenCalled()
    expect(getSystemAlertTypesMock).toHaveBeenCalled()
    // 重新整理也不得補打無權 API
    await wrapper.findAll('button').find((b) => b.text().length > 0)?.trigger('click')
    await flushPromises()
    expect(searchAlertsMock).not.toHaveBeenCalled()
  })

  it('只有 notification_channel:manage：頁內無通道頁籤、不發任何通道 API', async () => {
    // 該主體進不到告警頁屬入口規則，不在這裡驗；這裡只驗頁面本身不再承載通道
    setCapabilitiesForTests(['notification_channel:manage'])
    const wrapper = mountAlerts()
    await flushPromises()
    expect(tabNames(wrapper)).toEqual([])
    expect(tabNames(wrapper)).not.toContain('channels')
    expect(wrapper.findComponent({ name: 'NotificationChannelPanel' }).exists()).toBe(false)
    expect(getChannelsMock).not.toHaveBeenCalled()
    expect(searchAlertsMock).not.toHaveBeenCalled()
    expect(getAlertRulesMock).not.toHaveBeenCalled()
    expect(getSystemAlertTypesMock).not.toHaveBeenCalled()
  })

  it('三種頁籤能力俱全：頁籤順序為記錄、規則、系統告警，沒有通道頁籤也不載入通道', async () => {
    setCapabilitiesForTests(['audit:view', 'alertrule:manage', 'systemalert:manage', 'notification_channel:manage'])
    const wrapper = mountAlerts()
    await flushPromises()
    expect(tabNames(wrapper)).toEqual(['alerts', 'rules', 'systemAlerts'])
    expect(activeTabName(wrapper)).toBe('alerts')
    expect(getChannelsMock).not.toHaveBeenCalled()
  })

  it('持有 audit:view：維持預設告警記錄頁籤並載入列表', async () => {
    setCapabilitiesForTests(['audit:view', 'systemalert:manage'])
    const wrapper = mountAlerts()
    await flushPromises()
    expect(activeTabName(wrapper)).toBe('alerts')
    expect(searchAlertsMock).toHaveBeenCalled()
  })
})
