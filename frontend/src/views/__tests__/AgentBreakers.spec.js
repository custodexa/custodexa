import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AgentBreakers from '../AgentBreakers.vue'
import i18n from '@/i18n'
import { formatDateTime } from '@/utils/format'
import AgentBreakerEvents from '@/components/agent/AgentBreakerEvents.vue'
import BreakerReleaseForm from '@/components/agent/BreakerReleaseForm.vue'
const api = vi.hoisted(() => ({ asset: vi.fn(), me: vi.fn(), mine: vi.fn(), user: vi.fn(), release: vi.fn(), events: vi.fn(), tokens: vi.fn(), route: { query: { user_id: '5' } } }))
vi.mock('@/api/assets', () => ({ getAsset: api.asset }))
vi.mock('@/api/auth', () => ({ getCurrentUser: api.me }))
vi.mock('@/api/user', () => ({ getUserDetail: api.user }))
vi.mock('@/api/agents', () => ({ getMyAgents: api.mine, getAgentBreakerEvents: api.events, getAgentTokens: api.tokens, listAgentPrincipals: vi.fn().mockResolvedValue({ data: [], total: 0 }), releaseAgentBreaker: api.release }))
vi.mock('vue-router', () => ({ useRoute: () => api.route }))
enableAutoUnmount(afterEach)
const principal = { id: 5, username: 'worker', kind: 'agent', owner_user_id: 1, breaker_pending_at: '2026-09-22T00:00:00Z' }
// /auth/me returns roles and id, without kind; this HTTP route rejects agent credentials.
const actor = { id: 1, roles: ['user'] }
const global = { plugins: [ElementPlus] }
beforeEach(() => { vi.clearAllMocks(); api.asset.mockResolvedValue({ name: 'cache-host', protocol: 'ssh' }); api.events.mockResolvedValue({ data: [], total: 0, breaker_pending_at: principal.breaker_pending_at }); api.tokens.mockResolvedValue({ data: [] }); api.me.mockResolvedValue(actor); api.mine.mockResolvedValue({ data: [principal] }); api.user.mockResolvedValue({ data: principal }); api.release.mockResolvedValue(undefined) })
const open = async () => { const w = mount(AgentBreakers, { global }); await flushPromises(); return w }
describe('AgentBreakers 解除表單', () => {
  it('未填原因送出被擋', async () => { const w = await open(); expect(w.get('[data-test="release-submit"]').attributes('disabled')).toBeDefined(); await w.get('form').trigger('submit'); expect(api.release).not.toHaveBeenCalled(); await w.get('textarea').setValue('   '); await w.get('form').trigger('submit'); expect(api.release).not.toHaveBeenCalled() })
  it('送出前載明兩項後果', async () => { const w = await open(); expect(w.text()).toContain('解除後不會自動恢復已停用的鑰匙，須重新發一把'); expect(w.text()).toContain('自動停用當下已換發的連線票證與既有連線已失效'); expect(api.release).not.toHaveBeenCalled(); await w.get('textarea').setValue(' 已核對任務 '); await w.get('[data-test="release-submit"]').trigger('click'); await flushPromises(); expect(api.release).toHaveBeenCalledWith(5, '已核對任務'); expect(w.text()).toContain('已解除未處置旗標'); expect(w.find('[data-test="release-submit"]').exists()).toBe(false); expect(api.user).not.toHaveBeenCalled() })
  it('非負責人非管理者不見解除動作', async () => { const w = mount(BreakerReleaseForm, { props: { principal, actor: { ...actor, id: 2, roles: ['auditor'] } }, global }); expect(w.find('form').exists()).toBe(false); await w.vm.submit(); expect(api.release).not.toHaveBeenCalled(); api.mine.mockResolvedValue({ data: [] }); const page = await open(); expect(page.find('form').exists()).toBe(false); expect(api.user).not.toHaveBeenCalled() })
  it('管理者沿主體讀取端點取得表單，解除失敗保留原因', async () => { api.me.mockResolvedValue({ data: { ...actor, id: 3, roles: ['admin'] } }); const w = await open(); expect(api.user).toHaveBeenCalledWith(5); expect(api.mine).not.toHaveBeenCalled(); api.release.mockRejectedValue({ response: { status: 403, data: { code: 'AUTH_PERMISSION_DENIED' } } }); await w.get('textarea').setValue('確認後解除'); await w.get('[data-test="release-submit"]').trigger('click'); await flushPromises(); expect(w.get('textarea').element.value).toBe('確認後解除'); expect(w.find('[role="status"]').exists()).toBe(false) })
})

describe('AgentBreakers 事件序列', () => {
  it('事件序列逐筆呈現', async () => {
    api.events.mockResolvedValue({ data: ['never_visible', 'revoked', 'retired', 'never_visible'].map((c, i) => ({ id: i, asset_ref: i === 3 ? 1 : i + 1, class: c, endpoint: 'GET /assets/:id', created_at: '2026-09-22T00:00:00Z' })), total: 24, breaker_pending_at: principal.breaker_pending_at })
    api.tokens.mockResolvedValue({ data: [{ id: 8, name: 'stopped', suspended_at: principal.breaker_pending_at, suspended_reason: 'agent_breaker_tripped' }] })
    const w = await open(); expect(w.findAll('[data-test="probe-event"]')).toHaveLength(4); expect(w.get('[data-test="breaker-targets-stat"]').text()).toBe('1'); expect(w.text()).toContain('系統自動停用；停用於')
    w.getComponent(AgentBreakerEvents).vm.changePage(2); await flushPromises(); expect(api.events).toHaveBeenLastCalledWith(5, { offset: 20, limit: 20 })
  })
  it('未處置狀態可見', async () => { const w = await open(); expect(w.text()).toContain('自動停用待處置') })
  it('文案不斷言成因', async () => { const w = await open(); expect(w.text()).not.toMatch(/惡意|攻擊|逃避/); expect(w.text()).toContain('不是目前時間窗的自動停用計數') })
  it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 6 三語 DOM 與事件／解除同層對照：%s', async locale => { i18n.global.locale.value = locale; const w = await open(); expect(w.find('[data-test="breaker-events"]').exists()).toBe(true); expect(w.find('[data-test="breaker-release"]').exists()).toBe(true); expect(w.text()).not.toMatch(/agentBreaker\.|agentPrincipals\./); expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0) })
})

it('稽核者兼負責人仍可解除，沿既有鑰匙讀取權確認', async () => {
  api.me.mockResolvedValue({ id: 1, roles: ['auditor'] }); api.tokens.mockResolvedValue({ data: [] })
  const w = await open(); expect(api.tokens).toHaveBeenCalledWith(5); expect(api.user).not.toHaveBeenCalled(); expect(api.mine).not.toHaveBeenCalled()
  expect(w.find('[data-test="release-submit"]').exists()).toBe(true)
})
it('非負責人稽核者只讀事件，鑰匙 403 不授予解除', async () => {
  api.me.mockResolvedValue({ id: 9, roles: ['auditor'] }); api.tokens.mockRejectedValue({ response: { status: 403, data: { code: 'AUTH_PERMISSION_DENIED' } } })
  const w = await open(); expect(w.find('[data-test="breaker-events"]').exists()).toBe(true); expect(w.find('[data-test="release-submit"]').exists()).toBe(false)
  expect(api.user).not.toHaveBeenCalled(); expect(api.release).not.toHaveBeenCalled()
})

it('polish 9：白話標題、資產名與協議；HTTP 路徑收進細節', async () => {
  api.events.mockResolvedValue({ data: [{ id: 1, asset_ref: 12, class: 'never_visible', endpoint: 'GET /api/v1/assets/:id' }], total: 1 })
  const w = await open()
  expect(w.get('h1').text()).toBe('自動停用處置')
  const event = w.get('[data-test="probe-event"]')
  expect(event.get('[data-test="probe-target"]').text()).toContain('cache-host · 終端（SSH）')
  expect(event.get('[data-test="probe-target"]').text()).not.toContain('GET')
  expect(event.get('details').text()).toContain('GET /api/v1/assets/:id')
  expect(event.get('details').attributes('open')).toBeUndefined()
  expect(api.asset).toHaveBeenCalledWith(12, { skipErrorToast: true })
})

it('polish2：頁頂優先使用既有 owner_username，不重查負責人', async () => {
  api.me.mockResolvedValue({ id: 3, username: 'admin', roles: ['admin'] })
  api.user.mockResolvedValue({ data: { ...principal, owner_username: 'responsible' } })
  const w = await open()
  expect(w.getComponent({ name: 'PrincipalBadge' }).text()).toContain('負責人：responsible')
  expect(api.user).toHaveBeenCalledTimes(1)
})
it('polish2：管理者以既有單筆讀取補姓名，本人沿認證姓名', async () => {
  api.me.mockResolvedValue({ id: 3, username: 'admin', roles: ['admin'] })
  api.user.mockImplementation(id => Promise.resolve({ data: id === 5 ? principal : { id: 1, username: 'responsible' } }))
  const admin = await open()
  expect(admin.getComponent({ name: 'PrincipalBadge' }).props('ownerName')).toBe('responsible')
  expect(api.user).toHaveBeenCalledWith(1)
  api.user.mockClear(); api.me.mockResolvedValue({ ...actor, username: 'my-name' })
  const owner = await open()
  expect(owner.getComponent({ name: 'PrincipalBadge' }).props('ownerName')).toBe('my-name')
  expect(api.user).not.toHaveBeenCalled()
})

it('待處置首屏標頭與成因皆有本次停用時刻', async () => {
  const w = await open()
  const time = w.get('[data-test="breaker-pending-at"]')
  expect(time.element.closest('.breaker-head')).not.toBeNull()
  expect(time.attributes('datetime')).toBe(principal.breaker_pending_at)
  expect(time.text()).toContain(formatDateTime(principal.breaker_pending_at))
  expect(w.get('[data-test="breaker-brief"]').text()).toContain(formatDateTime(principal.breaker_pending_at))
})
it('沒有待處置時不呈現停用時刻與成因', async () => {
  api.mine.mockResolvedValue({ data: [{ ...principal, breaker_pending_at: null }] })
  api.events.mockResolvedValue({ data: [], total: 0, breaker_pending_at: null })
  const w = await open()
  expect(w.find('[data-test="breaker-pending-at"]').exists()).toBe(false)
  expect(w.get('[data-test="breaker-brief"]').text()).not.toContain(formatDateTime(principal.breaker_pending_at))
})
