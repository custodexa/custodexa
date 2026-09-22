import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Alerts from '../Alerts.vue'
vi.mock('@/api/alerts', async original => ({ ...(await original()), searchAlerts: vi.fn().mockResolvedValue({ data: [{ id: 1, kind: 'agent_breaker_tripped', user_id: 7, session_id: null, severity: 'high', triggered_at: '2026-09-22T00:00:00Z' }, { id: 2, kind: 'command', user_id: 8, session_id: 4, command: 'pwd', severity: 'low', triggered_at: '2026-09-22T00:00:00Z' }], total: 2 }), getAlertRules: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
describe('Alerts agent 入口', () => {
  it('熔斷告警帶處置入口', async () => { localStorage.setItem('user', JSON.stringify({ roles: ['auditor'] })); const w = mount(Alerts, { global: { plugins: [ElementPlus], stubs: { teleport: true, 'router-link': { template: '<a><slot /></a>' } } } }); await flushPromises(); const links = w.findAll('[data-test="breaker-entry"]'); expect(links).toHaveLength(1); expect(links[0].attributes('href')).toBe('/agent-breakers?user_id=7'); expect(links[0].text()).toBe('前往熔斷處置'); localStorage.clear() })
})
