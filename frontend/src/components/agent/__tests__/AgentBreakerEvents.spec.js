import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AgentBreakerEvents from '../AgentBreakerEvents.vue'
const api = vi.hoisted(() => ({ events: vi.fn(), asset: vi.fn() }))
vi.mock('@/api/agents', () => ({ getAgentBreakerEvents: api.events, getAgentTokens: vi.fn() }))
vi.mock('@/api/assets', () => ({ getAsset: api.asset }))
enableAutoUnmount(afterEach)
const pendingAt = '2026-09-23T01:00:00Z'
const events = [
  { id: 1, asset_ref: 1, class: 'never_visible', created_at: '2026-09-23T00:59:59Z' },
  { id: 2, asset_ref: 1, class: 'never_visible', created_at: pendingAt },
  { id: 3, asset_ref: 1, class: 'never_visible', created_at: '2026-09-23T01:00:01Z' },
  { id: 4, asset_ref: 1, class: 'revoked', created_at: '2026-09-23T01:00:02Z' },
]
beforeEach(() => {
  api.asset.mockResolvedValue({ name: 'audit-db', protocol: 'mysql' })
  api.events.mockResolvedValue({ data: events, total: 4, breaker_pending_at: pendingAt })
})
async function open() {
  const w = mount(AgentBreakerEvents, { props: { userId: 31 }, global: { plugins: [ElementPlus] } })
  await flushPromises(); return w
}
describe('本次待處置事件才使用琥珀', () => {
  it('同時刻與較新的門檻事件琥珀，其他分類中性', async () => {
    const w = await open(); const tags = w.findAll('[data-test="probe-class"]')
    expect(w.findAllComponents({ name: 'ElTag' })[1].props('type')).toBe('warning')
    expect(w.findAllComponents({ name: 'ElTag' })[2].props('type')).toBe('warning')
    expect(tags[3].classes()).toContain('ot-tag-neutral')
    expect(w.get('[data-test="probe-target"]').text()).toContain('資料庫（MYSQL）')
  })
  it('待處置之前的門檻事件中性', async () => {
    const w = await open(); const tag = w.get('[data-test="probe-class"]')
    expect(tag.classes()).toContain('ot-tag-neutral')
    expect(w.findAllComponents({ name: 'ElTag' })[0].props('type')).not.toBe('warning')
  })
  it('解除後歷史事件全部中性', async () => {
    api.events.mockResolvedValue({ data: events, total: 4, breaker_pending_at: null })
    const w = await open(); const tags = w.findAll('[data-test="probe-class"]')
    expect(tags.every(tag => tag.classes().includes('ot-tag-neutral'))).toBe(true)
    expect(w.findAllComponents({ name: 'ElTag' }).every(tag => tag.props('type') !== 'warning')).toBe(true)
  })
})
