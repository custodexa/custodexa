import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { applyPreviewResponse, beginPreviewRequest, cancelPreview } from '@/composables/useRolePreview'
import Dashboard from '../Dashboard.vue'
import { t } from '@/i18n'

enableAutoUnmount(afterEach)

const getDashboardCardMock = vi.fn()
vi.mock('@/api/dashboard', () => ({
  getDashboardCard: (...args) => getDashboardCardMock(...args),
}))
vi.mock('@/api/releaseGuidance', () => ({
  getReleaseGuidanceState: vi.fn().mockResolvedValue({ data: {} }),
  dismissReleaseGuidance: vi.fn(),
  getRetentionAdjustments: vi.fn(),
}))
vi.mock('@/api/sessions', () => ({ getActiveSessions: vi.fn().mockResolvedValue([]) }))
vi.mock('@/api/myConnections', () => ({ getMyConnections: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
vi.mock('@/api/alerts', () => ({ searchAlerts: vi.fn().mockResolvedValue({ data: [], total: 0 }) }))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: vi.fn().mockResolvedValue({ data: { enabled: false } }),
  getDailyReviewPending: vi.fn(),
  signDailyReview: vi.fn(),
}))

const enterPreview = (permissions) =>
  applyPreviewResponse(beginPreviewRequest(), {
    role: { id: 9, name: 'R9' },
    previewable: true,
    permissions,
    entry_states: [],
  })
const mountDashboard = () =>
  mount(Dashboard, {
    global: {
      plugins: [ElementPlus],
      mocks: { $router: { push: vi.fn() } },
      stubs: { UpgradeGuidanceCard: true },
    },
  })
const requested = () => getDashboardCardMock.mock.calls.map((c) => c[0])

describe('儀表板在預覽中的請求閘', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetCapabilities()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    getDashboardCardMock.mockImplementation((key) => Promise.resolve({ key, value: 5, unit: 'count', filters: {} }))
  })
  afterEach(() => {
    cancelPreview()
    vi.restoreAllMocks()
  })

  it('預覽角色有、本人沒有的權限：卡片不發請求並顯示說明；本人有的照常取數', async () => {
    // 本人只有 session:view；預覽角色另有 asset:view、audit:view
    setCapabilitiesForTests(['session:view'])
    enterPreview(['asset:view', 'audit:view', 'session:view'])
    const w = mountDashboard()
    await flushPromises()

    expect(requested()).not.toContain('assets')
    expect(requested()).not.toContain('today-alerts')
    expect(requested()).toContain('active-sessions')

    const assetsCard = w.get('[data-card="assets"]')
    expect(assetsCard.get('[data-test="stat-self-hidden"]').text()).toBe(t('rolePreview.selfCannotSee.title'))
    expect(assetsCard.get('.stat-value').text()).not.toBe(t('dashboard.valueUnavailable'))
    expect(w.get('[data-card="active-sessions"]').find('[data-test="stat-self-hidden"]').exists()).toBe(false)
  })

  it('離開預覽後不留說明', async () => {
    setCapabilitiesForTests(['session:view'])
    enterPreview(['asset:view', 'session:view'])
    const w = mountDashboard()
    await flushPromises()
    expect(w.find('[data-test="stat-self-hidden"]').exists()).toBe(true)
    cancelPreview()
    await flushPromises()
    expect(w.find('[data-card="assets"]').exists()).toBe(false)
    expect(w.find('[data-test="stat-self-hidden"]').exists()).toBe(false)
  })
})
