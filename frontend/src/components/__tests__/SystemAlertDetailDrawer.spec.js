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
  describe('管理類發放與自我授權的呈現', () => {
    const grantDetail = (over = {}) => ({
      alert_id: 167,
      alert_type: 'management_role_granted',
      group: 'identity_privilege',
      severity: 'medium',
      triggered_at: '2026-10-25T08:00:00Z',
      actor: 'ops-ida',
      target_kind: 'user',
      target_id: '192',
      client_ip: '203.0.113.7',
      params: { path: 'replace', recipient: 'ops-lee', role_name: 'asset_admin', scope_summary: 'global' },
      correlation_id: 'c0ffee00c0ffee00c0ffee00c0ffee00',
      audit_log_id: 902,
      deliveries: [],
      ...over,
    })
    const grantText = () => q('[data-test="sa-grant"]').textContent.replace(/\s+/g, ' ')

    it('受領人、中文角色名與範圍；不套用操作者自己的前後對照', async () => {
      getDetailMock.mockResolvedValue(grantDetail())
      mountDrawer()
      await flushPromises()

      const text = grantText()
      expect(text).toContain('發放內容')
      expect(text).toContain('ops-lee')
      expect(text).toContain('資產管理員')
      expect(text).toContain('全系統')
      expect(text).not.toContain('asset_admin')
      expect(text).not.toContain('之前')
      expect(q('[data-test="sa-privilege"]')).toBeNull()
      expect(document.body.textContent).not.toContain('ops-ida 的權限變化')
      expect(document.body.textContent).not.toContain('之前')
    })

    it('節點範圍：列出路徑、總數；已刪除的節點只顯示編號', async () => {
      getDetailMock.mockResolvedValue(
        grantDetail({
          params: { path: 'replace', recipient: 'ops-lee', role_name: 'asset_admin', scope_summary: 'nodes',
            scope_node_ids: '158,167', scope_node_count: '2' },
          scope_nodes: [{ id: 158, path: 'SIT / ELK' }, { id: 167, path: '' }],
        })
      )
      mountDrawer()
      await flushPromises()

      const scope = q('[data-test="sa-grant-scope"]').textContent.replace(/\s+/g, ' ')
      expect(scope).toContain('SIT / ELK')
      expect(scope).toContain('節點 #167（已刪除）')
      expect(scope).toContain('共 2 個節點')
      expect(scope).not.toContain('全系統')
    })

    it('舊告警沒有節點資訊且不是全域時不顯示範圍列', async () => {
      getDetailMock.mockResolvedValue(
        grantDetail({ params: { path: 'replace', recipient: 'ops-lee', role_name: 'asset_admin', scope_summary: 'nodes' } })
      )
      mountDrawer()
      await flushPromises()
      expect(q('[data-test="sa-grant-scope"]')).toBeNull()
    })

    it('群組目標：受領對象為「使用者群組 {名}」，技術細節目標顯示名稱', async () => {
      getDetailMock.mockResolvedValue(
        grantDetail({ target_kind: 'user_group', target_id: '7', params: { path: 'group_roles', recipient: 'prod-assets', role_name: 'asset_admin' } })
      )
      mountDrawer()
      await flushPromises()
      expect(q('[data-test="sa-grant-recipient"]').textContent.trim()).toBe('使用者群組 prod-assets')
      expect(q('[data-test="sa-target"]').textContent.trim()).toBe('prod-assets（使用者群組 #7）')
    })

    it('自我授權：角色清單逐一顯示中文名稱', async () => {
      getDetailMock.mockResolvedValue({
        alert_id: 168, alert_type: 'self_privilege_increased', group: 'identity_privilege', severity: 'high',
        triggered_at: '2026-10-25T08:00:00Z', actor: 'ops-ida', target_kind: 'user', target_id: '19',
        params: { path: 'replace', roles_before: 'identity_admin', roles_after: 'auditor,identity_admin' },
        deliveries: [],
      })
      mountDrawer()
      await flushPromises()

      const roles = q('[data-test="sa-priv-roles"]').textContent.replace(/\s+/g, ' ')
      expect(roles).toContain('身分管理員')
      expect(roles).toContain('稽核人員、身分管理員')
      expect(roles).not.toContain('identity_admin')
      expect(q('[data-test="sa-privilege"]').textContent).toContain('ops-ida 的權限變化')
    })

    it('技術細節的目標顯示「名稱（使用者 #id）」；名稱不可得時維持種類加編號', async () => {
      getDetailMock.mockResolvedValue(grantDetail())
      mountDrawer()
      await flushPromises()
      expect(q('[data-test="sa-target"]').textContent.trim()).toBe('ops-lee（使用者 #192）')
    })
  })
})
