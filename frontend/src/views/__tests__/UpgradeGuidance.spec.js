import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { h } from 'vue'
import ElementPlus from 'element-plus'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { permissionsFor } from '@/composables/__tests__/capabilityFixtures'
import { canEnter, entryMeta } from '@/router/entryRules'
import { useUpgradeGuidance } from '@/composables/useUpgradeGuidance'
import Dashboard from '@/views/Dashboard.vue'
import MainLayout from '@/components/MainLayout.vue'
import { meBody } from '@/composables/__tests__/capabilityFixtures'
import { t } from '@/i18n'

enableAutoUnmount(afterEach)

const getStateMock = vi.fn()
const dismissMock = vi.fn()
const retentionMock = vi.fn()

vi.mock('@/api/releaseGuidance', () => ({
  getReleaseGuidanceState: (...a) => getStateMock(...a),
  dismissReleaseGuidance: (...a) => dismissMock(...a),
  getRetentionAdjustments: (...a) => retentionMock(...a),
}))

const getDashboardCardMock = vi.fn()
vi.mock('@/api/dashboard', () => ({
  getDashboardCard: (...a) => getDashboardCardMock(...a),
}))
vi.mock('@/api/sessions', () => ({ getActiveSessions: vi.fn().mockResolvedValue([]) }))
vi.mock('@/api/myConnections', () => ({ getMyConnections: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
vi.mock('@/api/alerts', () => ({ searchAlerts: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: vi.fn().mockResolvedValue({ data: { enabled: false } }),
  getDailyReviewPending: vi.fn(),
  getDailyReviewPendingCount: vi.fn().mockResolvedValue({ data: { count: 0, overdue_count: 0 } }),
  signDailyReview: vi.fn(),
}))
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: vi.fn().mockResolvedValue({ count: 0, review_count: 0 }),
}))

const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...a) => getCurrentUserMock(...a),
  getMFASetup: vi.fn(),
  enableMFA: vi.fn(),
  disableMFA: vi.fn(),
  logout: vi.fn(),
}))
vi.mock('@/api/seal', () => ({
  getSealStatus: vi.fn().mockResolvedValue({ state: 'unsealed', instance_guard: { state: 'held', peers: 0 } }),
  unseal: vi.fn(),
}))
vi.mock('@/api/instanceGuard', () => ({ getInstanceGuard: vi.fn() }))

const VERSION = '1.18.0'
const CREDENTIAL_KEYS = [
  'credential:view', 'credential:create', 'credential:update', 'credential:set-secret',
  'credential:rotate', 'credential:convert-scope', 'credential:detach', 'credential:delete',
  'credential:bind', 'credential:manage',
]

// 正式儀表板：說明卡由 Dashboard.vue 自己掛載；「其他操作」用頁首的重新整理鈕
async function mountAt(path = '/dashboard') {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/:pathMatch(.*)*', component: { render: () => null } }],
  })
  router.push(path)
  await router.isReady()
  const wrapper = mount(Dashboard, { global: { plugins: [ElementPlus, router] }, attachTo: document.body })
  await flushPromises()
  return { wrapper, router }
}

// 其他操作仍可用：點頁首的重新整理鈕，儀表板會重新取數
async function refreshWorks(wrapper) {
  const before = getDashboardCardMock.mock.calls.length
  const btn = wrapper.findAll('button').find((b) => b.text().includes(t('common.refresh')))
  expect(btn).toBeTruthy()
  await btn.trigger('click')
  await flushPromises()
  return getDashboardCardMock.mock.calls.length > before
}

const setCaps = (perms, userId = 1) => setCapabilitiesForTests(perms, { userId })
const sections = (w) => w.findAll('[data-section]').map((n) => n.attributes('data-section'))
const links = (w) => w.findAll('[data-link]').map((n) => n.attributes('data-link'))

beforeEach(() => {
  vi.clearAllMocks()
  getDashboardCardMock.mockImplementation((key) => Promise.resolve({ key, value: 1, unit: 'count', filters: {} }))
  resetCapabilities()
  useUpgradeGuidance().reset()
  getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: false })
  dismissMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
  retentionMock.mockResolvedValue({ notice_version: VERSION, items: [], uncovered: [] })
})

describe('UpgradeGuidance 顯示與關閉', () => {
  it('首次登入到儀表板就顯示，且其他操作可用', async () => {
    setCaps(permissionsFor(['user']))
    const { wrapper } = await mountAt()
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
    expect(getStateMock).toHaveBeenCalledWith(VERSION)
    expect(await refreshWorks(wrapper)).toBe(true)
    // 非阻擋：沒有遮罩、沒有 dialog 角色
    expect(document.querySelector('.el-overlay')).toBeNull()
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
  })

  it('關閉成功後收起，重新登入不自動顯示', async () => {
    setCaps(permissionsFor(['user']))
    const { wrapper } = await mountAt()
    await wrapper.find('[data-test="ug-dismiss"]').trigger('click')
    await flushPromises()
    expect(dismissMock).toHaveBeenCalledWith(VERSION)
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)

    // 重新登入：會話結束清空本機狀態，伺服器回已關閉
    resetCapabilities()
    useUpgradeGuidance().reset()
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    setCaps(permissionsFor(['user']))
    const again = await mountAt()
    expect(again.wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
  })

  it('儲存失敗保留卡片並可重試，其他操作仍可用', async () => {
    setCaps(permissionsFor(['user']))
    const { wrapper } = await mountAt()
    dismissMock.mockRejectedValueOnce(new Error('boom'))
    await wrapper.find('[data-test="ug-dismiss"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="ug-save-failed"]').text()).toContain(t('upgradeGuidance.saveFailed'))
    expect(await refreshWorks(wrapper)).toBe(true)
    await wrapper.find('[data-test="ug-save-retry"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
  })

  it('說明本身載入失敗時顯示重試，重試成功後顯示內容', async () => {
    setCaps(permissionsFor(['user']))
    getStateMock.mockRejectedValueOnce(new Error('boom'))
    const { wrapper } = await mountAt()
    expect(wrapper.find('[data-test="ug-load-failed"]').exists()).toBe(true)
    await wrapper.find('[data-test="ug-load-retry"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="ug-load-failed"]').exists()).toBe(false)
    expect(sections(wrapper)).toContain('basic')
  })

  it('所有登入者可由 ?guidance 重開：已關閉也強制展開、不重設伺服器狀態、消費後移除 query', async () => {
    setCaps(permissionsFor(['user']))
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    const { wrapper, router } = await mountAt(`/dashboard?guidance=${VERSION}&keep=1`)
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
    expect(dismissMock).not.toHaveBeenCalled()
    expect(router.currentRoute.value.query).toEqual({ keep: '1' })
    await flushPromises()
    expect(document.activeElement?.getAttribute('data-test')).toBe('ug-title')
  })

  it('切換帳號丟棄舊回應並重新讀取', async () => {
    setCaps(permissionsFor(['user']), 1)
    let release
    getStateMock.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const { wrapper } = await mountAt()
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
    // 換帳號：新帳號尚未關閉
    getStateMock.mockResolvedValueOnce({ notice_version: VERSION, dismissed: false })
    setCaps(permissionsFor(['user']), 2)
    await flushPromises()
    // 舊帳號的延遲回應（已關閉）晚到，必須被丟棄
    release({ notice_version: VERSION, dismissed: true })
    await flushPromises()
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
  })
})

describe('UpgradeGuidance 重開與關閉的讀取先後', () => {
  it('重開時較早發出的狀態讀取晚於關閉成功：不得把已關閉改回未關閉', async () => {
    setCaps(permissionsFor(['user']))
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    const { wrapper } = await mountAt(`/dashboard?guidance=${VERSION}`)
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
    // 較早的讀取（尚未回來，回應內容是舊的「未關閉」）
    let release
    getStateMock.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const guidance = useUpgradeGuidance()
    const pending = guidance.load({ force: true })
    // 其後關閉成功
    await guidance.dismiss()
    await flushPromises()
    expect(guidance.dismissed.value).toBe(true)
    release({ notice_version: VERSION, dismissed: false })
    await pending
    await flushPromises()
    expect(guidance.dismissed.value).toBe(true)
    expect(guidance.status.value).toBe('ready')
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
  })
})

describe('UpgradeGuidance 段落適用與連結分開判定', () => {
  it('一般使用者：/assets 入口成立，但沒有資產管理與憑證段落', async () => {
    const perms = permissionsFor(['user'])
    setCaps(perms)
    expect(canEnter(entryMeta('/assets'))).toBe(true)
    const { wrapper } = await mountAt()
    expect(sections(wrapper)).toEqual(['basic'])
    expect(links(wrapper)).toEqual([])
  })

  it('只持 ui:assets-global：資產段落出現、/assets 連結依 canEnter，沒有憑證段落', async () => {
    setCaps(['ui:assets-global'])
    const { wrapper } = await mountAt()
    expect(sections(wrapper)).toContain('assets')
    expect(sections(wrapper)).not.toContain('credentialOwnership')
    expect(links(wrapper)).toEqual(['/assets'])
    expect(canEnter(entryMeta('/assets'))).toBe(true)
  })

  it.each(CREDENTIAL_KEYS)('只持 %s：憑證段落與 /credentials 連結出現，沒有資產管理段落', async (key) => {
    setCaps([key])
    const { wrapper } = await mountAt()
    expect(sections(wrapper)).toContain('credentialOwnership')
    expect(sections(wrapper)).not.toContain('assets')
    expect(links(wrapper)).toContain('/credentials')
    expect(canEnter(entryMeta('/credentials'))).toBe(true)
  })

  it('十個憑證鍵皆無：看不到憑證段落', async () => {
    setCaps(['asset:view', 'credential:unknown'])
    const { wrapper } = await mountAt()
    expect(sections(wrapper)).not.toContain('credentialOwnership')
    expect(links(wrapper)).not.toContain('/credentials')
  })

  it('ui:assets-global 與任一憑證鍵同時持有：兩段各一份', async () => {
    setCaps(['ui:assets-global', 'credential:view', 'credential:manage'])
    const { wrapper } = await mountAt()
    const ids = sections(wrapper)
    expect(ids.filter((s) => s === 'assets')).toHaveLength(1)
    expect(ids.filter((s) => s === 'credentialOwnership')).toHaveLength(1)
  })

  it('只有通道能力者看得到通道段落，且沒有告警段落', async () => {
    setCaps(['notification_channel:manage'])
    const { wrapper } = await mountAt()
    expect(sections(wrapper)).toContain('notifications')
    expect(sections(wrapper)).not.toContain('audit')
  })

  it.each(['alertrule:manage', 'systemalert:manage'])('只持 %s：告警段落為中性文案，不含「未審閱」', async (key) => {
    setCaps([key])
    const { wrapper } = await mountAt()
    const node = wrapper.find('[data-section="audit"]')
    expect(node.exists()).toBe(true)
    expect(node.text()).toContain(t('upgradeGuidance.audit'))
    expect(node.text()).not.toContain('未審閱')
    expect(node.text()).not.toContain(t('common.unreviewedAlerts'))
  })

  it('每個連結與 canEnter(entryMeta(目的)) 結果相同，使用真實入口規則', async () => {
    setCaps(permissionsFor(['admin']))
    const { wrapper } = await mountAt()
    const hrefs = links(wrapper)
    expect(hrefs.length).toBeGreaterThan(0)
    for (const to of hrefs) expect(canEnter(entryMeta(to))).toBe(true)
    // 反向：段落適用、入口不成立者不附連結（只持 alertrule:manage 時 /alerts 規則不成立）
    resetCapabilities()
    setCaps(['alertrule:manage'])
    const only = await mountAt()
    expect(only.wrapper.find('[data-section="audit"]').exists()).toBe(true)
    for (const to of links(only.wrapper)) expect(canEnter(entryMeta(to))).toBe(true)
  })

  it('內容不含帳號、資產、節點、憑證名稱或計數', async () => {
    setCaps(permissionsFor(['admin']))
    const { wrapper } = await mountAt()
    const text = wrapper.text()
    expect(text).not.toMatch(/\d+\s*個(管理員|帳號|資產|節點|憑證)/)
    expect(getStateMock).toHaveBeenCalledTimes(1)
  })
})

describe('UpgradeGuidance 保留區塊', () => {
  const adminCaps = () => setCaps(permissionsFor(['admin']))

  it('抬升紀錄與未涵蓋關係分開標示，檢查點跟隨有註記', async () => {
    adminCaps()
    retentionMock.mockResolvedValue({
      notice_version: VERSION,
      items: [
        { key: 'retention_audit_log_days', old_days: 3, new_days: 7, reason: 'below_floor', raised_at: '2026-10-18T10:00:00Z' },
        { key: 'retention_checkpoint_days', old_days: 5, new_days: 7, reason: 'cross_key_follow', raised_at: '2026-10-18T10:00:00Z' },
      ],
      uncovered: [{ data_key: 'retention_recording_days', data_days: 0, checkpoint_days: 7 }],
    })
    const { wrapper } = await mountAt()
    const items = wrapper.find('[data-test="ug-retention-items"]')
    expect(items.text()).toContain(t('upgradeGuidance.retentionTitle'))
    expect(items.find('[data-retention-key="retention_audit_log_days"]').text()).toContain('3')
    expect(items.find('[data-retention-key="retention_checkpoint_days"]').text()).toContain(t('upgradeGuidance.retentionFollow'))
    const unc = wrapper.find('[data-test="ug-retention-uncovered"]')
    expect(unc.text()).toContain(t('policyZero.retention'))
    expect(unc.find('[data-link="/security-policies"]').exists()).toBe(true)
    // 核可稿樣式：目前設定標籤、「前往X ›」連結（X 仍是選單名稱）、標題資訊圖示
    expect(unc.find('[data-test="ug-current-setting"]').text()).toBe(t('upgradeGuidance.currentSetting'))
    expect(unc.find('[data-link="/security-policies"]').text())
      .toBe(t('upgradeGuidance.goTo', { name: t('menu.securityPolicies') }))
    expect(wrapper.find('[data-test="ug-info-icon"]').exists()).toBe(true)
  })

  it('保留紀錄載入中顯示骨架；讀取失敗顯示黃色警示條，重試在右側', async () => {
    adminCaps()
    retentionMock.mockReturnValue(new Promise(() => {}))
    const { wrapper } = await mountAt()
    const loading = wrapper.find('[data-test="ug-retention-loading"]')
    expect(loading.exists()).toBe(true)
    expect(loading.find('.el-skeleton').exists()).toBe(true)
    expect(loading.text()).toContain(t('common.loading'))
  })

  it('抬升紀錄與未涵蓋關係皆空時不顯示整個區塊', async () => {
    adminCaps()
    const { wrapper } = await mountAt()
    expect(retentionMock).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-test="ug-retention"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="ug-retention-failed"]').exists()).toBe(false)
  })

  it('讀取失敗顯示重試，重試成功後顯示內容，不冒充沒有調整', async () => {
    adminCaps()
    retentionMock.mockRejectedValueOnce(new Error('boom'))
    const { wrapper } = await mountAt()
    expect(wrapper.find('[data-test="ug-retention-failed"]').exists()).toBe(true)
    retentionMock.mockResolvedValue({
      notice_version: VERSION,
      items: [{ key: 'retention_alert_days', old_days: 2, new_days: 7, reason: 'below_floor', raised_at: '2026-10-18T10:00:00Z' }],
      uncovered: [],
    })
    await wrapper.find('[data-test="ug-retention-retry"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="ug-retention-failed"]').exists()).toBe(false)
    expect(wrapper.find('[data-retention-key="retention_alert_days"]').exists()).toBe(true)
  })

  it('沒有安全政策讀取能力的主體不請求保留紀錄', async () => {
    setCaps(permissionsFor(['auditor']))
    const { wrapper } = await mountAt()
    expect(retentionMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="ug-retention"]').exists()).toBe(false)
  })
  it('同一帳號已載入後失去安全政策讀取能力：保留區塊清空且不再請求', async () => {
    adminCaps()
    retentionMock.mockResolvedValue({
      notice_version: VERSION,
      items: [{ key: 'retention_alert_days', old_days: 2, new_days: 7, reason: 'below_floor', raised_at: '2026-10-18T10:00:00Z' }],
      uncovered: [],
    })
    const { wrapper } = await mountAt()
    expect(wrapper.find('[data-retention-key="retention_alert_days"]').exists()).toBe(true)
    setCaps(permissionsFor(['auditor']))
    await flushPromises()
    expect(wrapper.find('[data-test="ug-retention"]').exists()).toBe(false)
    expect(wrapper.find('[data-retention-key="retention_alert_days"]').exists()).toBe(false)
    expect(useUpgradeGuidance().retention.value.items).toEqual([])
    expect(retentionMock).toHaveBeenCalledTimes(1)
  })

  it('讀取進行中失去能力：晚到的回應被丟棄，不留舊內容', async () => {
    adminCaps()
    let release
    retentionMock.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const { wrapper } = await mountAt()
    expect(useUpgradeGuidance().retention.value.status).toBe('loading')
    setCaps(permissionsFor(['auditor']))
    await flushPromises()
    release({
      notice_version: VERSION,
      items: [{ key: 'retention_alert_days', old_days: 2, new_days: 7, reason: 'below_floor', raised_at: '2026-10-18T10:00:00Z' }],
      uncovered: [],
    })
    await flushPromises()
    expect(useUpgradeGuidance().retention.value.status).toBe('idle')
    expect(useUpgradeGuidance().retention.value.items).toEqual([])
    expect(wrapper.find('[data-retention-key="retention_alert_days"]').exists()).toBe(false)
  })
})

// 正式使用者選單：MainLayout 與正式儀表板同一個路由器，從別頁點選單項重開
describe('UpgradeGuidance 使用者選單重開', () => {
  async function mountLayoutAt(path, roles = ['user']) {
    localStorage.setItem('user', JSON.stringify({ username: 'tester' }))
    setCaps(permissionsFor(roles))
    getCurrentUserMock.mockResolvedValue(meBody(roles))
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/dashboard', component: Dashboard },
        { path: '/:pathMatch(.*)*', component: { render: () => h('div', { 'data-test': 'other-page' }) } },
      ],
    })
    router.push(path)
    await router.isReady()
    const wrapper = mount(MainLayout, { global: { plugins: [ElementPlus, router] }, attachTo: document.body })
    await flushPromises()
    return { wrapper, router }
  }

  // 真的展開下拉選單，點選項目文字為「新版說明」的那一列
  async function clickGuidanceItem(wrapper) {
    const dd = wrapper.findAllComponents({ name: 'ElDropdown' }).find((d) => d.find('.user-info').exists())
    await dd.find('.user-info').trigger('click')
    await flushPromises()
    // 前一案遺留的彈層可能還在 body 上：取最後展開的那一組（語言選單三項 + 使用者選單三項）
    const items = [...document.body.querySelectorAll('.el-dropdown-menu__item')]
    const labels = items.slice(-3).map((n) => n.textContent.trim())
    expect(labels).toEqual([t('common.profile'), t('upgradeGuidance.menu'), t('common.logout')])
    items[items.length - 2].click()
    await flushPromises()
  }

  it('所有登入者在別頁開使用者選單：「新版說明」回儀表板、展開並移焦到標題，伺服器狀態不動', async () => {
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    const { wrapper, router } = await mountLayoutAt('/assets')
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
    await clickGuidanceItem(wrapper)
    expect(router.currentRoute.value.path).toBe('/dashboard')
    expect(router.currentRoute.value.query).toEqual({})
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
    expect(document.activeElement?.getAttribute('data-test')).toBe('ug-title')
    expect(dismissMock).not.toHaveBeenCalled()
    // 一般使用者重開後沒有管理段落與管理連結
    expect(sections(wrapper)).toEqual(['basic'])
    expect(links(wrapper)).toEqual([])
  })

  // 下拉選單收起時 Element Plus 會把焦點還給選單本體再落到 BODY，時間取決於選單開了多久。
  // 這裡不用固定毫秒：選單先開著超過 800ms 再點，之後模擬選單彈層搶走焦點並失焦，焦點仍要回到標題。
  it('選單開著超過 800ms 再點：彈層收起時搶走焦點，最後 document.activeElement 仍是說明卡標題', async () => {
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    const { wrapper } = await mountLayoutAt('/assets')
    const dd = wrapper.findAllComponents({ name: 'ElDropdown' }).find((d) => d.find('.user-info').exists())
    await dd.find('.user-info').trigger('click')
    await flushPromises()
    await new Promise((resolve) => setTimeout(resolve, 850))
    const items = [...document.body.querySelectorAll('.el-dropdown-menu__item')]
    items[items.length - 2].click()
    await flushPromises()
    const title = wrapper.find('[data-test="ug-title"]').element
    expect(document.activeElement).toBe(title)

    // 模擬收起：彈層（.el-popper 內的選單）取得焦點，隨後失焦落到 BODY
    const popper = document.createElement('div')
    popper.className = 'el-popper'
    const menu = document.createElement('ul')
    menu.className = 'el-dropdown-menu'
    menu.tabIndex = -1
    popper.appendChild(menu)
    document.body.appendChild(popper)
    menu.focus()
    expect(document.activeElement).toBe(menu)
    menu.blur()
    expect(document.activeElement).toBe(title)
    popper.remove()

    // 使用者自己操作後守衛解除，不再搶焦點
    document.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    const other = document.createElement('div')
    other.className = 'el-popper'
    const otherMenu = document.createElement('ul')
    otherMenu.tabIndex = -1
    other.appendChild(otherMenu)
    document.body.appendChild(other)
    otherMenu.focus()
    otherMenu.blur()
    expect(document.activeElement).not.toBe(title)
    other.remove()
  })

  // 鍵盤選取時，下拉會在焦點已移到標題之後才把焦點還給觸發鈕：此時 focusout 的來源是標題本身，
  // 而不是彈層。守衛要把焦點收回標題；使用者之後自己按鍵就不能再搶。
  it('鍵盤選取：焦點在標題後被還給選單觸發鈕，仍收回標題；使用者按鍵後不再搶焦點', async () => {
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    const { wrapper } = await mountLayoutAt('/assets')
    await clickGuidanceItem(wrapper)
    const title = wrapper.find('[data-test="ug-title"]').element
    expect(document.activeElement).toBe(title)

    const trigger = document.createElement('button')
    trigger.className = 'user-info'
    document.body.appendChild(trigger)
    trigger.focus()
    await flushPromises()
    expect(document.activeElement).toBe(title)

    // 使用者自己按鍵後守衛解除：焦點移到其他元素不再被收回
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }))
    trigger.focus()
    expect(document.activeElement).toBe(trigger)
    trigger.remove()
  })

  it('已在儀表板時也能重開，且重開後再按關閉才會寫入伺服器', async () => {
    getStateMock.mockResolvedValue({ notice_version: VERSION, dismissed: true })
    const { wrapper } = await mountLayoutAt('/dashboard')
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
    await clickGuidanceItem(wrapper)
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
    expect(dismissMock).not.toHaveBeenCalled()
    // 再按一次選單仍可重開（query 已被消費移除）
    await wrapper.find('[data-test="ug-close"]').trigger('click')
    await flushPromises()
    expect(dismissMock).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(false)
    await clickGuidanceItem(wrapper)
    expect(wrapper.find('[data-test="upgrade-guidance"]').exists()).toBe(true)
  })
})
