import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Alerts from '../Alerts.vue'

// 本檔掛載後從不卸載，殘留元件在 document 上累積使單測耗時隨測試序單調
// 上升（單獨跑實測 709ms→6962ms，約 10 倍）——全量並行時末幾格逼近逾時上限而轉紅
// （單跑穩綠）。與 Assets.spec.js／AuditLogs.spec.js 同型根因，治法相同：逐測卸載。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（不影響渲染結果驗證）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

// Alerts 掛載全量 ElementPlus（含 el-table/el-dialog/多選 select），
// 容器內單測本就貼近預設 5s 上限，依負載飄移易誤紅——放寬本檔 timeout
vi.setConfig({ testTimeout: 20_000 })

const searchAlertsMock = vi.fn()
const getAlertRulesMock = vi.fn()
const createAlertRuleMock = vi.fn()
const updateAlertRuleMock = vi.fn()
const deleteAlertRuleMock = vi.fn()
const getChannelsMock = vi.fn()
const createChannelMock = vi.fn()
const updateChannelMock = vi.fn()
const deleteChannelMock = vi.fn()
const testChannelMock = vi.fn()
const routerPushMock = vi.fn()

vi.mock('@/api/alerts', () => ({
  searchAlerts: (...args) => searchAlertsMock(...args),
  getAlertRules: (...args) => getAlertRulesMock(...args),
  createAlertRule: (...args) => createAlertRuleMock(...args),
  updateAlertRule: (...args) => updateAlertRuleMock(...args),
  deleteAlertRule: (...args) => deleteAlertRuleMock(...args),
  getChannels: (...args) => getChannelsMock(...args),
  createChannel: (...args) => createChannelMock(...args),
  updateChannel: (...args) => updateChannelMock(...args),
  deleteChannel: (...args) => deleteChannelMock(...args),
  testChannel: (...args) => testChannelMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const sampleAlerts = [
  {
    id: 1,
    rule_id: 1,
    rule_name: '刪除根目錄',
    session_id: 'sess-001',
    user_id: 7,
    asset_id: 3,
    command: 'rm -rf /',
    severity: 'high',
    triggered_at: '2026-06-12T08:00:00Z',
  },
  {
    id: 2,
    rule_id: 2,
    rule_name: '提權變更',
    session_id: 'sess-002',
    user_id: 8,
    asset_id: 4,
    command: 'chmod 777 /etc/passwd',
    severity: 'medium',
    triggered_at: '2026-06-12T08:01:00Z',
    // D6：規則名純淨，阻斷與否由 blocked 欄表達
    blocked: true,
  },
]

const sampleRules = [
  { id: 1, name: '刪除根目錄', pattern: 'rm\\s+-rf\\s+/', severity: 'high', enabled: true },
  { id: 2, name: '格式化磁碟', pattern: 'mkfs', severity: 'high', protocols: 'ssh,k8s', enabled: false },
]

const setUserRoles = (roles) => {
  localStorage.setItem('user', JSON.stringify({ username: 'tester', roles }))
}

const mountAlerts = () =>
  mount(Alerts, {
    global: {
      plugins: [ElementPlus],
    },
  })

describe('Alerts', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    searchAlertsMock.mockResolvedValue({ data: sampleAlerts, total: 2 })
    getAlertRulesMock.mockResolvedValue({ data: sampleRules })
  })

  it('fetches alerts on mount with default pagination params', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAlerts()
    await flushPromises()

    expect(searchAlertsMock).toHaveBeenCalledWith({
      page: 1,
      page_size: 20,
    })
    expect(wrapper.text()).toContain('指令告警')
    expect(wrapper.text()).toContain('rm -rf /')
    expect(wrapper.text()).toContain('刪除根目錄')
  })

  it('renders severity tags with correct types', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAlerts()
    await flushPromises()

    expect(wrapper.find('.el-tag--danger').exists()).toBe(true)
    expect(wrapper.find('.el-tag--warning').exists()).toBe(true)
    expect(wrapper.text()).toContain('高')
    expect(wrapper.text()).toContain('中')
  })

  it('sends severity filter when searching', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAlerts()
    await flushPromises()
    searchAlertsMock.mockClear()

    wrapper.vm.filters.severity = 'high'
    wrapper.vm.handleSearch()
    await flushPromises()

    expect(searchAlertsMock).toHaveBeenCalledWith({
      page: 1,
      page_size: 20,
      severity: 'high',
    })
  })

  it('navigates to session detail when clicking 檢視連線', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAlerts()
    await flushPromises()

    const detailButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('檢視連線'))
    expect(detailButton).toBeTruthy()

    await detailButton.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/sessions/sess-001')
  })

  it('hides rules tab and skips rules fetch for non-admin users', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAlerts()
    await flushPromises()

    const tabLabels = wrapper.findAll('.el-tabs__item').map((tab) => tab.text())
    expect(tabLabels).not.toContain('規則管理')
    expect(getAlertRulesMock).not.toHaveBeenCalled()
  })

  it('shows rules tab and fetches rules for admin users', async () => {
    setUserRoles(['admin'])

    const wrapper = mountAlerts()
    await flushPromises()

    const tabLabels = wrapper.findAll('.el-tabs__item').map((tab) => tab.text())
    expect(tabLabels).toContain('規則管理')
    expect(getAlertRulesMock).toHaveBeenCalled()
    expect(wrapper.text()).toContain('mkfs')
  })

  it('creates a new rule via dialog and refreshes the rule list', async () => {
    setUserRoles(['admin'])
    createAlertRuleMock.mockResolvedValue({ id: 3 })

    const wrapper = mountAlerts()
    await flushPromises()
    getAlertRulesMock.mockClear()

    wrapper.vm.openCreateDialog()
    await flushPromises()

    wrapper.vm.ruleForm.name = '管線執行下載腳本'
    wrapper.vm.ruleForm.pattern = 'curl.*\\|.*sh'
    wrapper.vm.ruleForm.severity = 'medium'
    wrapper.vm.ruleForm.protocols = ['mysql', 'postgres']
    wrapper.vm.ruleForm.enabled = true

    await wrapper.vm.handleSaveRule()
    await flushPromises()

    expect(createAlertRuleMock).toHaveBeenCalledWith({
      name: '管線執行下載腳本',
      pattern: 'curl.*\\|.*sh',
      severity: 'medium',
      action: 'alert',
      protocols: 'mysql,postgres',
      enabled: true,
    })
    expect(wrapper.vm.ruleDialogVisible).toBe(false)
    expect(getAlertRulesMock).toHaveBeenCalled()
  })

  it('keeps dialog open when create fails (e.g. invalid regex 400)', async () => {
    setUserRoles(['admin'])
    createAlertRuleMock.mockRejectedValue(new Error('無效的正規表達式'))

    const wrapper = mountAlerts()
    await flushPromises()

    wrapper.vm.openCreateDialog()
    await flushPromises()

    wrapper.vm.ruleForm.name = '壞規則'
    wrapper.vm.ruleForm.pattern = '([invalid'

    await wrapper.vm.handleSaveRule()
    await flushPromises()

    expect(createAlertRuleMock).toHaveBeenCalled()
    expect(wrapper.vm.ruleDialogVisible).toBe(true)
  })

  it('updates rule via edit dialog with existing values', async () => {
    setUserRoles(['admin'])
    updateAlertRuleMock.mockResolvedValue({})

    const wrapper = mountAlerts()
    await flushPromises()

    wrapper.vm.openEditDialog(sampleRules[1])
    await flushPromises()
    expect(wrapper.vm.ruleForm.name).toBe('格式化磁碟')
    // protocols 字串回填為多選陣列
    expect(wrapper.vm.ruleForm.protocols).toEqual(['ssh', 'k8s'])

    wrapper.vm.ruleForm.severity = 'low'
    await wrapper.vm.handleSaveRule()
    await flushPromises()

    expect(updateAlertRuleMock).toHaveBeenCalledWith(2, {
      name: '格式化磁碟',
      pattern: 'mkfs',
      severity: 'low',
      action: 'alert',
      protocols: 'ssh,k8s',
      enabled: false,
    })
  })

  it('channel edit keeps secret unless cleared explicitly (空 secret 沿用、clear_secret 顯式清除)', async () => {
    setUserRoles(['admin'])
    updateChannelMock.mockResolvedValue({})

    const wrapper = mountAlerts()
    await flushPromises()

    // url 為遮罩值（key-management-envelope G8：後端回應不含全文）
    const row = { id: 9, name: 'ops', url: 'https://hooks.example.com/****t/x', type: 'webhook', has_secret: true, enabled: true }

    // 開啟編輯：has_secret 帶入表單供狀態顯示，hasSecret 不進 payload；
    // url 不回填（遮罩值進 maskedUrl 僅供顯示）
    wrapper.vm.openChannelDialog(row)
    await flushPromises() // 表單掛載後 rules 生效（C6：submit 走 validate）
    expect(wrapper.vm.channelForm.hasSecret).toBe(true)
    expect(wrapper.vm.channelForm.url).toBe('')
    expect(wrapper.vm.channelForm.maskedUrl).toBe('https://hooks.example.com/****t/x')

    // 只改名、不重填 secret/url：payload 帶空 secret 與空 url + clear_secret=false（後端沿用既有值）；
    // risk_acknowledged=false（傳輸閘 D6：首次存檔不預設確認）；skipErrorToast 供 warn 確認流程攔截
    wrapper.vm.channelForm.name = 'ops-renamed'
    await wrapper.vm.handleSaveChannel()
    await flushPromises()
    expect(updateChannelMock).toHaveBeenCalledWith(
      9,
      {
        name: 'ops-renamed',
        url: '',
        secret: '',
        enabled: true,
        type: 'webhook',
        clear_secret: false,
        risk_acknowledged: false,
        // D5：表單恆有語系值，未動時沿用列上的既有設定
        language: 'zh-TW',
      },
      { skipErrorToast: true }
    )

    // 勾選清除簽名：clear_secret=true
    updateChannelMock.mockClear()
    wrapper.vm.openChannelDialog(row)
    await flushPromises()
    wrapper.vm.channelForm.clearSecret = true
    await wrapper.vm.handleSaveChannel()
    await flushPromises()
    expect(updateChannelMock).toHaveBeenCalledWith(9, expect.objectContaining({ clear_secret: true }), expect.anything())
  })

  it('creates a slack channel with type=slack in payload', async () => {
    setUserRoles(['admin'])
    createChannelMock.mockResolvedValue({})

    const wrapper = mountAlerts()
    await flushPromises()

    wrapper.vm.openChannelDialog()
    await flushPromises() // 表單掛載後 rules 生效（C6：submit 走 validate）
    wrapper.vm.channelForm.name = 'ops-slack'
    wrapper.vm.channelForm.type = 'slack'
    wrapper.vm.channelForm.url = 'https://hooks.slack.com/services/x'
    await wrapper.vm.handleSaveChannel()
    await flushPromises()

    expect(createChannelMock).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'ops-slack', type: 'slack', url: 'https://hooks.slack.com/services/x' }),
      expect.anything(),
    )
    // hasSecret 僅供顯示，不得進 payload
    expect(createChannelMock.mock.calls[0][0]).not.toHaveProperty('hasSecret')
  })

  it('toggles rule enabled state via updateAlertRule', async () => {
    setUserRoles(['admin'])
    updateAlertRuleMock.mockResolvedValue({})

    const wrapper = mountAlerts()
    await flushPromises()

    await wrapper.vm.handleToggleEnabled(sampleRules[0], false)
    await flushPromises()

    expect(updateAlertRuleMock).toHaveBeenCalledWith(1, {
      name: '刪除根目錄',
      pattern: 'rm\\s+-rf\\s+/',
      severity: 'high',
      enabled: false,
    })
  })

  it('survives alerts API failure without crashing and stops loading', async () => {
    setUserRoles(['auditor'])
    searchAlertsMock.mockRejectedValue(new Error('network down'))

    const wrapper = mountAlerts()
    await flushPromises()

    expect(wrapper.text()).toContain('指令告警')
    expect(wrapper.vm.alertsLoading).toBe(false)
  })

  // backend-i18n-unification D6：rule_name 去污染後，「已阻斷」改由 blocked 欄的 tag 表達
  it('renders 已阻斷 tag only for alerts whose blocked flag is set', async () => {
    setUserRoles(['auditor'])

    const wrapper = mountAlerts()
    await flushPromises()

    expect(wrapper.text()).toContain('已阻斷')
    // 規則名不得再帶「（已阻斷）」後綴（後端已去污染）
    expect(wrapper.text()).not.toContain('（已阻斷）')
    // 樣本兩筆僅第二筆 blocked：tag 只出現一次
    const blockedTags = wrapper.findAll('.blocked-tag')
    expect(blockedTags).toHaveLength(1)
    expect(blockedTags[0].text()).toBe('已阻斷')
  })

  // backend-i18n-unification D5：per-channel 語系
  it('channel dialog offers the three backend languages and defaults to zh-TW', async () => {
    setUserRoles(['admin'])
    createChannelMock.mockResolvedValue({})

    const wrapper = mountAlerts()
    await flushPromises()

    wrapper.vm.openChannelDialog()
    await flushPromises()
    expect(wrapper.vm.channelForm.language).toBe('zh-TW')
    // 選項以各語言自身文字呈現（不隨介面語言翻譯）；el-dialog／el-select 的
    // 內容分別落在 wrapper 與 teleport 到 body 的 popper，兩處合併後斷言
    const dialogText = wrapper.text() + document.body.textContent
    expect(dialogText).toContain('訊息語言')
    expect(dialogText).toContain('僅影響 Slack')
    for (const label of ['繁體中文', 'English', '日本語']) {
      expect(dialogText, `語系選項缺 ${label}`).toContain(label)
    }

    wrapper.vm.channelForm.name = 'ops-ja'
    wrapper.vm.channelForm.type = 'slack'
    wrapper.vm.channelForm.url = 'https://hooks.slack.com/services/x'
    wrapper.vm.channelForm.language = 'ja-JP'
    await wrapper.vm.handleSaveChannel()
    await flushPromises()

    expect(createChannelMock).toHaveBeenCalledWith(
      expect.objectContaining({ language: 'ja-JP' }),
      expect.anything(),
    )
  })

  it('channel edit prefills language from the row and falls back to zh-TW when absent', async () => {
    setUserRoles(['admin'])

    const wrapper = mountAlerts()
    await flushPromises()

    wrapper.vm.openChannelDialog({ id: 5, name: 'ops-en', type: 'slack', url: '***', enabled: true, language: 'en-US' })
    await flushPromises()
    expect(wrapper.vm.channelForm.language).toBe('en-US')

    // 舊列（後端尚未回 language）不得把 undefined 送進 payload
    wrapper.vm.openChannelDialog({ id: 6, name: 'legacy', type: 'webhook', url: '***', enabled: true })
    await flushPromises()
    expect(wrapper.vm.channelForm.language).toBe('zh-TW')
  })

  it('shows empty state when no alerts exist', async () => {
    setUserRoles(['auditor'])
    searchAlertsMock.mockResolvedValue({ data: [], total: 0 })

    const wrapper = mountAlerts()
    await flushPromises()

    expect(wrapper.text()).toContain('尚無告警記錄')
  })
})
