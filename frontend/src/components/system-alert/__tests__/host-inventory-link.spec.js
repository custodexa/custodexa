import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SystemAlertDetailDrawer from '@/components/system-alert/SystemAlertDetailDrawer.vue'
import { t } from '@/i18n'

// 告警詳情的「查看這台的主機帳號盤點」連結。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getDetailMock = vi.fn()
vi.mock('@/api/systemAlerts', () => ({
  getSystemAlertDetail: (...args) => getDetailMock(...args),
}))

const RouterLinkStub = { props: ['to'], template: '<a :data-to="JSON.stringify(to)"><slot /></a>' }
const base = {
  alert_id: 5, alert_type: 'unmanaged_privileged_account', group: 'privilege', severity: 'high',
  triggered_at: '2026-11-02T08:42:00Z', actor: 'alice', target_kind: 'asset', target_id: '7',
  params: { new_count: '2', identity_mode: 'default_account' }, deliveries: [],
}
const q = (sel) => document.body.querySelector(sel)

async function show(detail) {
  getDetailMock.mockResolvedValue(detail)
  mount(SystemAlertDetailDrawer, {
    props: { modelValue: true, alertId: 5 },
    attachTo: document.body,
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub } },
  })
  await flushPromises()
}

describe('告警詳情：主機帳號盤點連結', () => {
  beforeEach(() => getDetailMock.mockReset())

  it('資產目標且識別為正整數：連到 /assets?inventory=<id>', async () => {
    await show(base)
    const a = q('[data-test="sa-view-host-inventory"]')
    expect(a).not.toBeNull()
    expect(a.textContent).toContain(t('systemAlerts.detail.viewHostInventory'))
    expect(JSON.parse(a.getAttribute('data-to'))).toEqual({ path: '/assets', query: { inventory: '7' } })
  })

  it('目標不是資產：沒有連結', async () => {
    await show({ ...base, target_kind: 'user' })
    expect(q('[data-test="sa-view-host-inventory"]')).toBeNull()
  })

  it('識別不是正整數：沒有連結', async () => {
    await show({ ...base, target_id: '7/../x' })
    expect(q('[data-test="sa-view-host-inventory"]')).toBeNull()
    await show({ ...base, target_id: '0' })
    expect(q('[data-test="sa-view-host-inventory"]')).toBeNull()
  })

  it('其他告警類型：沒有連結', async () => {
    await show({ ...base, alert_type: 'notification_channel_changed' })
    expect(q('[data-test="sa-view-host-inventory"]')).toBeNull()
  })
})
