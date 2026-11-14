import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import TimelineEvents from '../TimelineEvents.vue'

enableAutoUnmount(afterEach)

const FROM = '2026-11-13T00:00:00+08:00'
const TO = '2026-11-13T23:59:59+08:00'

class IntersectionObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
beforeEach(() => {
  globalThis.IntersectionObserver = IntersectionObserverStub
})

const event = (over = {}) => ({
  id: 'audit:1',
  ts: '2026-11-13T05:58:04Z',
  type: 'audit',
  summary_code: 'timeline.audit.op',
  params: { action: 'create', resource: 'asset' },
  refs: {},
  actor: { id: 57, name: 'ops-chen' },
  client_ip: '203.0.113.15',
  ...over,
})

const mountEvents = async (events, props = {}) => {
  const w = mount(TimelineEvents, {
    props: { events, from: FROM, to: TO, ...props },
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub } },
  })
  await flushPromises()
  return w
}

describe('調查時間軸：經由 API token 的事件', () => {
  it('以人調查（後端的事件不帶 actor）：操作者取調查對象的名稱', async () => {
    const w = await mountEvents([
      event({ actor: undefined, api_token_id: 41, api_token_name: 'terraform-prod-apply' }),
    ], { subject: 'user', subjectName: 'ops-chen' })
    expect(w.get('[data-test="event-via"]').text()).toBe('操作者：ops-chen（經由 API token terraform-prod-apply）')
  })

  it('以資產調查（操作者在對造欄）：操作者取對造的使用者名稱', async () => {
    const w = await mountEvents([
      event({ actor: undefined, counterpart: { kind: 'user', id: 57, name: 'ops-chen' }, api_token_id: 41, api_token_name: 'terraform-prod-apply' }),
    ], { subject: 'asset', subjectName: 'prod-web-12' })
    expect(w.get('[data-test="event-via"]').text()).toBe('操作者：ops-chen（經由 API token terraform-prod-apply）')
  })

  it('以人調查：經由 API token 的事件註明哪一把，親自操作的不加', async () => {
    const w = await mountEvents([
      event({ api_token_id: 41, api_token_name: 'terraform-prod-apply' }),
      event({ id: 'audit:2', ts: '2026-11-13T05:41:10Z' }),
    ], { subject: 'user' })
    const via = w.findAll('[data-test="event-via"]')
    expect(via).toHaveLength(1)
    expect(via[0].text()).toBe('操作者：ops-chen（經由 API token terraform-prod-apply）')
  })

  it('以來源位址調查：操作者行直接換成含 API token 的說法', async () => {
    const w = await mountEvents([event({ api_token_id: 41, api_token_name: 'terraform-prod-apply' })], { subject: 'ip' })
    expect(w.find('[data-test="event-via"]').exists()).toBe(false)
    expect(w.get('[data-test="event-party"]').text()).toContain('操作者：ops-chen（經由 API token terraform-prod-apply）')
  })
})
