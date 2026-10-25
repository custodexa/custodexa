import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SystemAlertDetailDrawer from '@/components/system-alert/SystemAlertDetailDrawer.vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'

// 系統告警明細抽屜：目標、宣告參數、來源位址與各目的地的投遞時間。
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

const RouterLinkStub = { props: ['to'], template: '<a><slot /></a>' }

const channelDetail = {
  alert_id: 41,
  alert_type: 'notification_channel_changed',
  group: 'notification',
  severity: 'high',
  triggered_at: '2026-10-15T08:42:00Z',
  actor: '張家豪',
  target_kind: 'notification_channel',
  target_id: '9',
  client_ip: '203.0.113.7',
  params: {
    change: 'updated',
    changed_fields: 'url',
    url_before: 'https://old.example.test/****ABCD',
    url_after: 'https://new.example.test/****EFGH',
  },
  correlation_id: 'c0ffee00c0ffee00c0ffee00c0ffee00',
  audit_log_id: 902,
  deliveries: [
    { dest_type: 'slack', dest_name: '資安 Slack 頻道', state: 'delivered', attempts: 1,
      delivered_at: '2026-10-15T08:42:05Z', next_attempt_at: '2026-10-15T08:42:00Z' },
    { dest_type: 'webhook', dest_name: 'SOC Webhook', state: 'retrying', attempts: 2,
      next_attempt_at: '2026-10-15T08:43:00Z' },
    { dest_type: 'webhook', dest_name: '壞掉的通道', state: 'abandoned', attempts: 0,
      next_attempt_at: '2026-10-15T08:42:00Z' },
  ],
}

const q = (sel) => document.body.querySelector(sel)
const qa = (sel) => [...document.body.querySelectorAll(sel)]

const mountDrawer = () =>
  mount(SystemAlertDetailDrawer, {
    props: { modelValue: true, alertId: 41 },
    attachTo: document.body,
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub } },
  })

describe('系統告警明細抽屜', () => {
  beforeEach(() => {
    getDetailMock.mockReset()
  })

  it('顯示目標種類與識別、逐列的宣告參數與來源位址', async () => {
    getDetailMock.mockResolvedValue(channelDetail)
    mountDrawer()
    await flushPromises()

    expect(getDetailMock).toHaveBeenCalledWith(41, { skipErrorToast: true })
    expect(q('[data-test="sa-target"]').textContent).toContain(
      `${t('systemAlerts.targetKinds.notification_channel')} #9`
    )
    const params = qa('[data-test="sa-param"]').map((el) => el.textContent.replace(/\s+/g, ' ').trim())
    expect(params).toEqual([
      'change: updated',
      'changed_fields: url',
      'url_after: https://new.example.test/****EFGH',
      'url_before: https://old.example.test/****ABCD',
    ])
    expect(q('[data-test="sa-client-ip"]').textContent).toContain('203.0.113.7')
    expect(q('[data-test="sa-actor"]').textContent).toContain('張家豪')
    expect(q('[data-test="sa-occurred-at"]').textContent).toContain(t('systemAlerts.detail.occurredAt'))
  })

  it('目標為角色時顯示角色種類名稱與識別', async () => {
    getDetailMock.mockResolvedValue({
      ...channelDetail, alert_type: 'management_role_granted', target_kind: 'role', target_id: '12',
      params: { path: 'role_definition', recipient: 'ops-view', role_name: 'ops-view' },
    })
    mountDrawer()
    await flushPromises()

    expect(q('[data-test="sa-target"]').textContent).toContain(`${t('systemAlerts.targetKinds.role')} #12`)
    expect(t('systemAlerts.targetKinds.role')).not.toBe('systemAlerts.targetKinds.role')
  })

  it('每個目的地顯示投遞時間：已送達給送達時刻、重送中給下次嘗試時刻、放棄不給時間', async () => {
    getDetailMock.mockResolvedValue(channelDetail)
    mountDrawer()
    await flushPromises()

    const rows = [...q('[data-test="sa-deliveries"]').children]
    expect(rows).toHaveLength(3)
    expect(rows[0].querySelector('[data-test="sa-delivery-time"]').textContent).toBe(
      t('systemAlerts.detail.deliveredAt', { time: formatDateTime('2026-10-15T08:42:05Z') })
    )
    expect(rows[1].querySelector('[data-test="sa-delivery-time"]').textContent).toBe(
      t('systemAlerts.detail.nextAttemptAt', { time: formatDateTime('2026-10-15T08:43:00Z') })
    )
    expect(rows[2].querySelector('[data-test="sa-delivery-time"]')).toBeNull()
  })

  it('沒有參數、沒有來源位址、目標識別為空時退回「無」與只顯示種類', async () => {
    getDetailMock.mockResolvedValue({
      ...channelDetail, alert_type: 'recording_failclose_disabled', target_kind: 'system_setting', target_id: '',
      client_ip: '', params: {}, deliveries: [],
    })
    mountDrawer()
    await flushPromises()

    expect(q('[data-test="sa-target"]').textContent.trim()).toBe(t('systemAlerts.targetKinds.system_setting'))
    expect(qa('[data-test="sa-param"]')).toHaveLength(0)
    expect(q('[data-test="sa-params"]').textContent).toContain(t('systemAlerts.detail.none'))
    expect(q('[data-test="sa-client-ip"]')).toBeNull()
  })

  it('提示框說明會送到每一個啟用中的通知通道', async () => {
    getDetailMock.mockResolvedValue(channelDetail)
    mountDrawer()
    await flushPromises()
    const notice = t('systemAlerts.detail.notice')
    expect(notice).toContain('每一個啟用中的通知通道')
    expect(notice).not.toContain('通知安全人員')
    expect(document.body.textContent).toContain(notice)
  })
})
