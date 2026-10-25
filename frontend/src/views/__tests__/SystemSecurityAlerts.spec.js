import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import Alerts from '../Alerts.vue'
import NotificationChannels from '../NotificationChannels.vue'
import NotificationChannelPanel from '@/components/alerts/NotificationChannelPanel.vue'
import SystemAlertCatalog from '@/components/system-alert/SystemAlertCatalog.vue'
import { t } from '@/i18n'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 系統告警的前端呈現：目錄（分級調整）、告警頁（篩選與明細抽屜）。
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
const getChannelsMock = vi.fn()
const deleteChannelMock = vi.fn()
const getTypesMock = vi.fn()
const updateSeverityMock = vi.fn()
const getDetailMock = vi.fn()

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
  reviewAlert: vi.fn(),
  getAlertRules: vi.fn().mockResolvedValue({ data: [] }),
  createAlertRule: vi.fn(),
  updateAlertRule: vi.fn(),
  deleteAlertRule: vi.fn(),
  getChannels: (...args) => getChannelsMock(...args),
  createChannel: vi.fn(),
  updateChannel: vi.fn(),
  deleteChannel: (...args) => deleteChannelMock(...args),
  testChannel: vi.fn(),
}))

vi.mock('@/api/systemAlerts', () => ({
  getSystemAlertTypes: (...args) => getTypesMock(...args),
  updateSystemAlertSeverity: (...args) => updateSeverityMock(...args),
  getSystemAlertDetail: (...args) => getDetailMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}))

const typeRow = (key, group, def, eff, extra = {}) => ({
  key, group, default_severity: def, effective_severity: eff, adjusted: def !== eff, ...extra,
})

// 對話框與抽屜可能傳送到 body：元件掛在 body 上，統一從 body 找
const q = (sel) => document.body.querySelector(sel)

const catalogRows = (withRecent) => [
  typeRow('asset_address_changed', 'address_transport', 'high', 'high', withRecent ? { recent_30d: 3 } : {}),
  typeRow('custom_secret_used', 'secret', 'high', 'medium', withRecent ? { recent_30d: 12 } : {}),
  typeRow('self_privilege_decreased', 'identity_privilege', 'low', 'low', withRecent ? { recent_30d: 2 } : {}),
  typeRow('notification_channel_changed', 'notification', 'high', 'high', withRecent ? { recent_30d: 1 } : {}),
]

const mountCatalog = () => mount(SystemAlertCatalog, { attachTo: document.body, global: { plugins: [ElementPlus] } })

describe('系統告警目錄', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getTypesMock.mockReset()
    updateSeverityMock.mockReset()
    resetCapabilities()
    setCapabilitiesForTests(['systemalert:manage'])
  })

  it('依 API 回應渲染全部列與分組；筆數欄缺席時不顯示', async () => {
    getTypesMock.mockResolvedValue({ types: catalogRows(false) })
    const wrapper = mountCatalog()
    await flushPromises()

    for (const row of catalogRows(false)) {
      expect(wrapper.find(`[data-test="catalog-row-${row.key}"]`).exists()).toBe(true)
      expect(wrapper.text()).toContain(t(`systemAlerts.types.${row.key}.name`))
    }
    for (const g of ['address_transport', 'secret', 'identity_privilege', 'notification']) {
      expect(wrapper.find(`[data-test="catalog-group-${g}"]`).exists()).toBe(true)
    }
    expect(wrapper.find('[data-test="catalog-group-security_settings"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="catalog-recent-asset_address_changed"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain(t('systemAlerts.catalog.columnRecent'))
    expect(wrapper.get('[data-test="catalog-total"]').text()).toBe(t('systemAlerts.catalog.total', { count: 4 }))
    // 已調整標記只在覆寫列出現
    expect(wrapper.find('[data-test="catalog-adjusted-custom_secret_used"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="catalog-adjusted-asset_address_changed"]').exists()).toBe(false)
  })

  it('API 帶筆數時顯示近 30 天欄', async () => {
    getTypesMock.mockResolvedValue({ types: catalogRows(true) })
    const wrapper = mountCatalog()
    await flushPromises()
    expect(wrapper.text()).toContain(t('systemAlerts.catalog.columnRecent'))
    expect(wrapper.get('[data-test="catalog-recent-custom_secret_used"]').text()).toBe(
      t('systemAlerts.catalog.recentCount', { count: 12 })
    )
  })

  it('無分級權限時不可調，只剩唯讀提示', async () => {
    setCapabilitiesForTests([])
    getTypesMock.mockResolvedValue({ types: catalogRows(false) })
    const wrapper = mountCatalog()
    await flushPromises()
    expect(wrapper.find('[data-test="catalog-adjust-asset_address_changed"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="catalog-readonly"]').exists()).toBe(true)
  })

  it('調整對話框說明仍會產生並送到每個啟用通道、不受推送門檻影響、記入操作日誌；儲存只送分級', async () => {
    getTypesMock.mockResolvedValue({ types: catalogRows(false) })
    updateSeverityMock.mockResolvedValue({})
    const wrapper = mountCatalog()
    await flushPromises()

    await wrapper.get('[data-test="catalog-adjust-custom_secret_used"]').trigger('click')
    await flushPromises()
    const note = q('[data-test="catalog-dialog-note"]')
    expect(note).not.toBeNull()
    expect(note.textContent).toBe(t('systemAlerts.catalog.dialogNote'))
    // 三個要點都在文案裡
    expect(note.textContent).toContain('每一個啟用中的通知通道')
    expect(note.textContent).toContain('不受通道')
    expect(note.textContent).toContain('操作日誌')

    q('[data-test="catalog-level-low"] input').click()
    await flushPromises()
    q('[data-test="catalog-save"]').click()
    await flushPromises()
    expect(updateSeverityMock).toHaveBeenCalledWith('custom_secret_used', 'low', { skipErrorToast: true })
  })

  it('元件內不存在刪除或停用控制', async () => {
    getTypesMock.mockResolvedValue({ types: catalogRows(false) })
    const wrapper = mountCatalog()
    await flushPromises()
    expect(wrapper.findAll('.el-switch').length).toBe(0)
    expect(wrapper.html()).not.toMatch(/data-test="[^"]*(delete|disable|toggle)[^"]*"/)
    const buttonTexts = wrapper.findAll('button').map((b) => b.text())
    for (const text of buttonTexts) {
      expect(text).not.toMatch(/刪除|停用/)
    }
  })
})

const systemAlert = {
  id: 31,
  rule_name: 'self_privilege_increased',
  kind: 'system_security',
  reason_code: 'self_privilege_increased',
  session_id: null,
  user_id: 7,
  command: '',
  severity: 'high',
  triggered_at: '2026-10-15T08:42:00Z',
  reviewed_at: null,
  disposition: '',
}

const privilegeDetail = {
  alert_id: 31,
  alert_type: 'self_privilege_increased',
  group: 'identity_privilege',
  severity: 'high',
  triggered_at: '2026-10-15T08:42:00Z',
  actor: '張家豪',
  target_kind: 'user',
  target_id: '7',
  params: {
    path: 'direct_assign',
    roles_before: '身分管理員',
    roles_after: '身分管理員,資產管理員',
    manageable_before: '0',
    manageable_after: '20',
    connectable_before: '3',
    connectable_after: '3',
  },
  correlation_id: 'c0ffee00c0ffee00c0ffee00c0ffee00',
  audit_log_id: 871,
  deliveries: [
    { dest_type: 'slack', dest_name: '資安 Slack 頻道', state: 'delivered', attempts: 1, next_attempt_at: '2026-10-15T08:42:00Z' },
    { dest_type: 'webhook', dest_name: 'SOC Webhook', state: 'retrying', attempts: 2, next_attempt_at: '2026-10-15T08:43:00Z' },
  ],
}

const mountAlerts = () => mount(Alerts, { attachTo: document.body, global: { plugins: [ElementPlus] } })
// 通道面板已搬到系統設定的獨立頁；通知通道案例改掛該頁，斷言不變
const mountChannels = () => mount(NotificationChannels, { attachTo: document.body, global: { plugins: [ElementPlus] } })


describe('告警頁的系統告警', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    searchAlertsMock.mockReset()
    getDetailMock.mockReset()
    resetCapabilities()
    setCapabilitiesForTests(['audit:view', 'alert:manage'])
    searchAlertsMock.mockResolvedValue({ data: [systemAlert], total: 1 })
  })

  it('來源類別篩選送出 kind=system_security，列以類型名稱呈現', async () => {
    const wrapper = mountAlerts()
    await flushPromises()
    expect(wrapper.get('[data-test="alert-system-name"]').text()).toBe(t('systemAlerts.types.self_privilege_increased.name'))
    searchAlertsMock.mockClear()
    wrapper.vm.filters.kind = 'system_security'
    wrapper.vm.handleSearch()
    await flushPromises()
    expect(searchAlertsMock).toHaveBeenCalledWith({ page: 1, page_size: 20, kind: 'system_security' })
    // 選項清單含「系統告警」
    expect(wrapper.vm.kindOptions.some((o) => o.value === 'system_security' && o.label === t('alerts.kindSystemSecurity'))).toBe(true)
  })

  it('權限類型的明細顯示前後角色與數量、各目的地狀態與操作日誌連結，不出現「權限一覽」按鈕', async () => {
    getDetailMock.mockResolvedValue(privilegeDetail)
    const wrapper = mountAlerts()
    await flushPromises()
    await wrapper.get('[data-test="alert-system-detail"]').trigger('click')
    await flushPromises()

    expect(getDetailMock).toHaveBeenCalledWith(31, { skipErrorToast: true })
    const text = document.body.textContent
    const priv = q('[data-test="sa-privilege"]')
    expect(priv).not.toBeNull()
    expect(priv.textContent).toContain('身分管理員')
    expect(priv.textContent).toContain('身分管理員、資產管理員')
    expect(q('[data-test="sa-priv-manageable"]').textContent).toContain(
      t('systemAlerts.detail.count', { count: '20' })
    )
    expect(q('[data-test="sa-priv-connectable"]')).not.toBeNull()
    const deliveries = q('[data-test="sa-deliveries"]').textContent
    expect(deliveries).toContain('資安 Slack 頻道')
    expect(deliveries).toContain(t('systemAlerts.delivery.delivered'))
    expect(deliveries).toContain(t('systemAlerts.delivery.retrying'))
    expect(q('[data-test="sa-audit-log"]').textContent).toContain('#871')
    expect(text).not.toContain('權限一覽')
  })

  it('非權限類型不顯示權限變化區塊', async () => {
    searchAlertsMock.mockResolvedValue({ data: [{ ...systemAlert, id: 32, reason_code: 'asset_address_changed' }], total: 1 })
    getDetailMock.mockResolvedValue({
      ...privilegeDetail, alert_id: 32, alert_type: 'asset_address_changed', group: 'address_transport',
      params: { changed_fields: 'host' }, deliveries: [],
    })
    const wrapper = mountAlerts()
    await flushPromises()
    await wrapper.get('[data-test="alert-system-detail"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="sa-privilege"]')).toBeNull()
    expect(q('[data-test="sa-tech"]')).not.toBeNull()
    expect(q('[data-test="sa-deliveries"]').textContent).toContain(
      t('systemAlerts.delivery.noDestination')
    )
  })

  it('具分級權限者多一個系統告警目錄分頁，沒有則沒有', async () => {
    const tabs = (w) => w.findAll('.el-tabs__item').map((x) => x.text())
    let wrapper = mountAlerts()
    await flushPromises()
    expect(tabs(wrapper)).not.toContain(t('alerts.tabSystemAlerts'))
    wrapper.unmount()
    setCapabilitiesForTests(['audit:view', 'systemalert:manage'])
    wrapper = mountAlerts()
    await flushPromises()
    expect(tabs(wrapper)).toContain(t('alerts.tabSystemAlerts'))
  })
})

describe('通知通道面板', () => {
  const row = { id: 9, name: 'SOC Webhook', url: 'https://soc.corp.example.internal/hooks/••••••', type: 'webhook', has_secret: false, enabled: true, language: 'zh-TW', min_severity: 'medium' }
  const panelVm = (wrapper) => wrapper.findComponent(NotificationChannelPanel).vm

  beforeEach(() => {
    vi.clearAllMocks()
    searchAlertsMock.mockReset()
    getChannelsMock.mockReset()
    deleteChannelMock.mockReset()
    resetCapabilities()
    setCapabilitiesForTests(['audit:view', 'notification_channel:manage'])
    searchAlertsMock.mockResolvedValue({ data: [], total: 0 })
    getChannelsMock.mockResolvedValue({ data: [row] })
  })

  it('改網址時提示列出遮罩舊網址與新網址', async () => {
    const wrapper = mountChannels()
    await flushPromises()
    panelVm(wrapper).openChannelDialog(row)
    await flushPromises()
    // 還沒改網址：不出現提示
    expect(q('[data-test="channel-url-change-notice"]')).toBeNull()
    panelVm(wrapper).channelForm.url = 'https://soc2.corp.example.internal/hooks/alerts'
    await flushPromises()
    const notice = q('[data-test="channel-url-change-notice"]')
    expect(notice).not.toBeNull()
    expect(q('[data-test="channel-old-url"]').textContent).toBe(row.url)
    expect(q('[data-test="channel-new-url"]').textContent).toBe('https://soc2.corp.example.internal/hooks/alerts')
    expect(notice.textContent).toContain(t('alerts.channelChangeNotice'))
  })

  it('刪除確認含刪除後仍通知的文案', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    deleteChannelMock.mockResolvedValue({})
    const wrapper = mountChannels()
    await flushPromises()
    await panelVm(wrapper).handleDeleteChannel(row)
    await flushPromises()
    const message = confirmSpy.mock.calls[0][0]
    expect(message).toContain(t('alerts.deleteChannelConfirm', { name: row.name }))
    expect(message).toContain(t('alerts.channelDeleteNotice'))
    expect(deleteChannelMock).toHaveBeenCalledWith(9)
    confirmSpy.mockRestore()
  })

  it('表格下方說明推送只篩選一般告警，通道分頁不在告警頁、在獨立頁', async () => {
    const wrapper = mountChannels()
    await flushPromises()
    expect(q('[data-test="channel-push-hint"]').textContent.trim()).toBe(t('alerts.channelPushSystemHint'))
    wrapper.unmount()
    const alertsWrapper = mountAlerts()
    await flushPromises()
    expect(alertsWrapper.findAll('.el-tabs__item').map((x) => x.text())).not.toContain(t('alerts.tabChannels'))
  })
})
