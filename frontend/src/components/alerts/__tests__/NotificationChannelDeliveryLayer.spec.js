// 通知投遞層的前端：Slack 應用程式表單、改網址與改型別的規則、測試對話框、投遞紀錄抽屜、
// 送達狀況欄、停用與刪除確認。斷言以「實際發出的請求」為準（API 替身的呼叫次數與本文）。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import NotificationChannelPanel from '../NotificationChannelPanel.vue'
import ChannelTestDialog from '../ChannelTestDialog.vue'
import ChannelDeliveryDrawer from '../ChannelDeliveryDrawer.vue'
import { t } from '@/i18n'
import { SLACK_APP_DEFAULT_URL, maskChannelUrl } from '@/constants/notification-channels'
import { formatLogTime } from '../channelDelivery'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const api = {
  getChannels: vi.fn(),
  createChannel: vi.fn(),
  updateChannel: vi.fn(),
  deleteChannel: vi.fn(),
  testChannel: vi.fn(),
  getChannelDeliveries: vi.fn(),
}
vi.mock('@/api/alerts', () => ({
  getChannels: (...a) => api.getChannels(...a),
  createChannel: (...a) => api.createChannel(...a),
  updateChannel: (...a) => api.updateChannel(...a),
  deleteChannel: (...a) => api.deleteChannel(...a),
  testChannel: (...a) => api.testChannel(...a),
  getChannelDeliveries: (...a) => api.getChannelDeliveries(...a),
}))

const DEFAULT_MASKED = maskChannelUrl(SLACK_APP_DEFAULT_URL)

const slackAppRow = {
  id: 3, name: 'sec-oncall', type: 'slack_app', url: DEFAULT_MASKED, target: 'C07QX4M2B9A', has_secret: true,
  enabled: true, language: 'zh-TW', min_severity: 'medium', destination_changed_at: null,
  health: { last_delivered_at: '2026-11-20T09:12:00Z', last_failed_at: '2026-11-19T14:03:00Z', last_failure_code: 'slack_rate', last_failure_reason: 'platform error: ratelimited', abandoned_7d: 1 },
}
const webhookRow = {
  id: 1, name: 'soc-webhook', type: 'webhook', url: 'https://soc.example.com/****hook', target: '', has_secret: true,
  enabled: true, language: 'zh-TW', min_severity: 'low', destination_changed_at: null,
  health: { last_delivered_at: '2026-11-20T09:12:00Z', last_failed_at: null, last_failure_code: '', last_failure_reason: '', abandoned_7d: 0 },
}
const slackRow = {
  id: 2, name: 'ops-slack', type: 'slack', url: 'https://hooks.slack.com/****Q2xd', target: '', has_secret: false,
  enabled: true, language: 'zh-TW', min_severity: 'low', destination_changed_at: null,
  health: { last_delivered_at: '2026-11-16T01:12:00Z', last_failed_at: '2026-11-20T09:05:00Z', last_failure_code: 'http_404', last_failure_reason: 'HTTP 404', abandoned_7d: 12 },
}

const mountPanel = async (rows = [webhookRow, slackRow, slackAppRow]) => {
  api.getChannels.mockResolvedValue({ data: rows })
  const w = mount(NotificationChannelPanel, { attachTo: document.body, global: { plugins: [ElementPlus] } })
  await w.vm.refresh()
  await flushPromises()
  return w
}
const body = () => document.body.textContent
const q = (sel) => document.body.querySelector(sel)
// el-input 把 data-test 掛在 input 或外層，兩種都接受
const inputValue = (sel) => {
  const el = q(sel)
  return el.tagName === 'INPUT' ? el.value : el.querySelector('input').value
}
// 表單驗證未過的欄位與訊息（就近紅字的內容）
const formErrors = async (w) => {
  try {
    await w.vm.channelFormRef.validate()
    return {}
  } catch (fields) {
    return Object.fromEntries(Object.entries(fields || {}).map(([k, v]) => [k, v.map((x) => x.message)]))
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.updateChannel.mockResolvedValue({})
  api.createChannel.mockResolvedValue({})
  api.getChannelDeliveries.mockResolvedValue({ data: [], total: 0 })
})

describe('Slack 應用程式的通道表單', () => {
  it('編輯時 token 不回填，只顯示是否已設定；頻道 ID 回填；只改頻道時不必重填 token', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(slackAppRow)
    await flushPromises()
    expect(w.vm.channelForm.secret).toBe('')
    expect(w.vm.channelForm.url).toBe('')
    expect(w.vm.channelForm.target).toBe('C07QX4M2B9A')
    expect(inputValue('[data-test="channel-token-input"]')).toBe('')
    expect(body()).toContain(t('alerts.tokenSetFull'))
    expect(body()).toContain(t('alerts.slackAddressCurrentDefault'))

    // 只改頻道：出現新舊頻道都會收到變更通知的提示，token 留空照樣送出
    w.vm.channelForm.target = 'C09NEWCHAN01'
    await flushPromises()
    expect(q('[data-test="channel-target-change-notice"]')).not.toBeNull()
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    const [id, payload] = api.updateChannel.mock.calls[0]
    expect(id).toBe(3)
    expect(payload).toMatchObject({ type: 'slack_app', target: 'C09NEWCHAN01', secret: '', url: '', clear_secret: false })
  })

  it('改了 Slack 位址時 token 變必填：沒填就按儲存不發出請求，填了才送', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(slackAppRow)
    await flushPromises()
    w.vm.channelForm.url = 'https://slack-relay.example.com/api'
    await flushPromises()
    expect(q('[data-test="channel-url-change-token-notice"]')).not.toBeNull()
    expect(w.vm.tokenRequired).toBe(true)

    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(0)
    expect((await formErrors(w)).secret).toEqual([t('alerts.urlChangedTokenError')])

    w.vm.channelForm.secret = 'xoxb-test'
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    expect(api.updateChannel.mock.calls[0][1]).toMatchObject({ url: 'https://slack-relay.example.com/api', secret: 'xoxb-test' })
  })

  it('改型別：提示原本的秘密不沿用，網址清空並必填（Slack 應用程式預先帶入官方位址）', async () => {
    const w = await mountPanel()
    // webhook → Slack 應用程式
    w.vm.openChannelDialog(webhookRow)
    await flushPromises()
    w.vm.channelForm.type = 'slack_app'
    w.vm.onTypeChange('slack_app')
    await flushPromises()
    expect(q('[data-test="channel-type-change-notice"]').textContent).toContain(t('alerts.typeToSlackApp'))
    expect(w.vm.channelForm.url).toBe(SLACK_APP_DEFAULT_URL)
    expect(w.vm.channelForm.secret).toBe('')
    // token 與頻道沒填：不送出
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(0)
    // 網址清空：不送出，欄位紅字
    w.vm.channelForm.secret = 'xoxb-test'
    w.vm.channelForm.target = 'C0AUDIT01'
    w.vm.channelForm.url = ''
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(0)
    expect((await formErrors(w)).url).toEqual([t('alerts.typeChangeUrlRequired')])
    w.vm.channelForm.url = SLACK_APP_DEFAULT_URL
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    expect(api.updateChannel.mock.calls[0][1]).toMatchObject({ type: 'slack_app', url: SLACK_APP_DEFAULT_URL, secret: 'xoxb-test', target: 'C0AUDIT01' })
  })

  it('Slack 應用程式改成 webhook：網址清空並必填、空網址不送出；簽名密鑰非必填', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(slackAppRow)
    await flushPromises()
    w.vm.channelForm.type = 'webhook'
    w.vm.onTypeChange('webhook')
    await flushPromises()
    expect(q('[data-test="channel-type-change-notice"]').textContent).toContain(t('alerts.typeFromSlackApp'))
    expect(w.vm.channelForm.url).toBe('')
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(0)

    w.vm.channelForm.url = 'https://hooks.example.com/new'
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    const payload = api.updateChannel.mock.calls[0][1]
    expect(payload).toMatchObject({ type: 'webhook', url: 'https://hooks.example.com/new', secret: '' })
    expect(payload).not.toHaveProperty('target')
  })

  it('新增 Slack 應用程式：token 與頻道格式不對就近紅字、不送出；格式正確時送出 target 並提示先測試', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog()
    await flushPromises()
    w.vm.channelForm.name = 'audit-team'
    w.vm.channelForm.type = 'slack_app'
    w.vm.onTypeChange('slack_app')
    await flushPromises()
    expect(q('[data-test="channel-slack-app-how"]')).not.toBeNull()
    w.vm.channelForm.secret = 'xapp-1-abc'
    w.vm.channelForm.target = '#audit-team'
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.createChannel).toHaveBeenCalledTimes(0)
    const errors = await formErrors(w)
    expect(errors.secret).toEqual([t('alerts.botTokenFormatError')])
    expect(errors.target).toEqual([t('alerts.targetChannelError')])

    w.vm.channelForm.secret = 'xoxb-test'
    w.vm.channelForm.target = 'C08AUD1T5EE'
    const success = vi.spyOn((await import('element-plus')).ElMessage, 'success')
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.createChannel).toHaveBeenCalledTimes(1)
    // 網址留空＝後端帶入官方位址
    expect(api.createChannel.mock.calls[0][0]).toMatchObject({ type: 'slack_app', url: '', secret: 'xoxb-test', target: 'C08AUD1T5EE' })
    expect(success).toHaveBeenCalledWith(t('alerts.channelCreatedTestHint'))
    success.mockRestore()
  })

  it('改網址且有未送達的通知：筆數取自投遞紀錄回應的 pending_counts，不從列表推算', async () => {
    api.getChannelDeliveries.mockResolvedValue({
      // 第一頁內容與筆數無關：故意放一筆已放棄的紀錄，筆數仍以 pending_counts 為準
      data: [{ id: 4, category: 'system_event', state: 'abandoned' }],
      total: 1,
      pending_counts: { general: 7, system_security_alert: 3 },
    })
    const w = await mountPanel()
    w.vm.openChannelDialog(slackRow)
    await flushPromises()
    expect(q('[data-test="channel-pending-notice"]')).toBeNull()
    w.vm.channelForm.url = 'https://hooks.slack.com/services/new'
    await flushPromises()
    await flushPromises()
    expect(q('[data-test="channel-pending-notice"]').textContent).toContain(
      t('alerts.pendingStillOldDest', { n_general: 7, n_snapshot: 3 })
    )
  })

  it.each([
    [{ general: 0, system_security_alert: 2 }, 'alerts.pendingSnapshotOnly', { n_snapshot: 2 }],
    [{ general: 4, system_security_alert: 0 }, 'alerts.pendingNewUrlOnly', { n_general: 4 }],
  ])('pending_counts=%o 時藍框只寫有筆數的那一類', async (counts, key, params) => {
    api.getChannelDeliveries.mockResolvedValue({ data: [], total: 0, pending_counts: counts })
    const w = await mountPanel()
    w.vm.openChannelDialog(slackRow)
    await flushPromises()
    w.vm.channelForm.url = 'https://hooks.slack.com/services/new'
    await flushPromises()
    await flushPromises()
    expect(q('[data-test="channel-pending-notice"] .el-alert__title').textContent.trim()).toBe(t(key, params))
  })

  it('兩類都是 0 時不出現藍框', async () => {
    api.getChannelDeliveries.mockResolvedValue({ data: [], total: 0, pending_counts: { general: 0, system_security_alert: 0 } })
    const w = await mountPanel()
    w.vm.openChannelDialog(slackRow)
    await flushPromises()
    w.vm.channelForm.url = 'https://hooks.slack.com/services/new'
    await flushPromises()
    await flushPromises()
    expect(q('[data-test="channel-pending-notice"]')).toBeNull()
  })
})

describe('通道列表', () => {
  it('「已停用」「尚未投遞」用中性灰標籤；其他狀態維持語意色', async () => {
    const disabled = { ...webhookRow, id: 5, name: 'legacy-hook', enabled: false }
    const fresh = { ...slackAppRow, id: 6, name: 'audit-team', health: { last_delivered_at: null, last_failed_at: null, abandoned_7d: 0 } }
    await mountPanel([webhookRow, disabled, fresh])
    const tags = [...document.querySelectorAll('[data-test="channel-health-tag"]')]
    expect(tags.map((n) => n.textContent.trim())).toEqual([t('alerts.health.ok'), t('alerts.health.disabled'), t('alerts.health.none')])
    expect(tags[0].classList.contains('ot-tag-neutral')).toBe(false)
    expect(tags[1].classList.contains('ot-tag-neutral')).toBe(true)
    expect(tags[2].classList.contains('ot-tag-neutral')).toBe(true)
  })

  it('欄寬總和放得進 1280 寬的表格（約 978px），四個動作排成兩行不必水平捲動', async () => {
    const w = await mountPanel()
    const cols = w.findAllComponents({ name: 'ElTableColumn' })
    const sum = cols.reduce((n, c) => n + Number(c.props('width') || c.props('minWidth') || 0), 0)
    expect(cols.length).toBe(9)
    expect(sum).toBeLessThanOrEqual(975)
    expect(document.querySelectorAll('.row-actions').length).toBeGreaterThan(0)
  })

  it('原因句以代碼為準：連線錯誤的原文是空字串、平台錯誤的原文是「HTTP 200, platform error: x」', async () => {
    const connect = { ...webhookRow, id: 7, name: 'conn', health: { last_delivered_at: null, last_failed_at: '2026-11-20T09:05:00Z', last_failure_code: 'connect', last_failure_reason: '', abandoned_7d: 0 } }
    const platform = { ...slackAppRow, id: 8, name: 'plat', health: { last_delivered_at: null, last_failed_at: '2026-11-20T09:05:00Z', last_failure_code: 'slack_channel', last_failure_reason: 'HTTP 200, platform error: channel_not_found', abandoned_7d: 0 } }
    const other = { ...slackAppRow, id: 9, name: 'oth', health: { last_delivered_at: null, last_failed_at: '2026-11-20T09:05:00Z', last_failure_code: 'slack_other', last_failure_reason: 'HTTP 200, platform error: weird_code', abandoned_7d: 0 } }
    await mountPanel([connect, platform, other])
    const reasons = [...document.querySelectorAll('[data-test="channel-health-reason"]')].map((n) => n.textContent.trim())
    expect(reasons).toEqual([
      t('alerts.deliveryReason.connect'),
      t('alerts.deliveryReason.slackChannel'),
      t('alerts.deliveryReason.slackOther', { code: 'weird_code' }),
    ])
  })

  it('Slack 應用程式的位址是基底或舊的完整方法網址時都顯示「Slack 官方位址」', async () => {
    const legacy = { ...slackAppRow, id: 4, name: 'legacy-app', url: maskChannelUrl('https://slack.com/api/chat.postMessage') }
    await mountPanel([slackAppRow, legacy])
    const cells = [...document.querySelectorAll('[data-test="channel-dest-cell"]')].map((n) => n.textContent)
    expect(cells).toHaveLength(2)
    for (const c of cells) expect(c).toContain(t('alerts.destSlackDefault'))
  })

  it('類型、目的地、簽名／token 與送達狀況欄', async () => {
    await mountPanel()
    const text = body()
    expect(text).toContain(t('alerts.channelTypeSlackAppShort'))
    expect(text).toContain(t('alerts.destChannel', { target: 'C07QX4M2B9A' }))
    expect(text).toContain(t('alerts.destSlackDefault'))
    expect(text).toContain(t('alerts.tokenSet'))
    const tags = [...document.querySelectorAll('[data-test="channel-health-tag"]')].map((n) => n.textContent.trim())
    expect(tags).toEqual([t('alerts.health.ok'), t('alerts.health.failing'), t('alerts.health.abandoned')])
    expect(text).toContain(t('alerts.deliveryReason.http404'))
    expect(text).toContain(t('alerts.deliveryReason.slackRate'))
    expect(document.querySelectorAll('.el-table__row.is-failing')).toHaveLength(1)
    expect(text).toContain(t('alerts.retryPolicyHint'))
  })

  it('改過目的地、還沒有新通知送出時標「尚未投遞」並寫從何時起算；網址解不開時請重新輸入', async () => {
    const changed = { ...slackRow, url: '****', destination_changed_at: '2026-11-20T09:40:00Z', health: { last_delivered_at: null, last_failed_at: null, abandoned_7d: 0 } }
    await mountPanel([changed])
    expect(q('[data-test="channel-health-tag"]').textContent.trim()).toBe(t('alerts.health.none'))
    expect(body()).toContain(t('alerts.health.noneSinceChange'))
    expect(q('[data-test="channel-health-since"]')).not.toBeNull()
    expect(body()).toContain(t('alerts.destUnreadable'))
  })

  it('關閉啟用先確認，按取消不送出且開關維持開啟；刪除確認框多兩句', async () => {
    const w = await mountPanel()
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValueOnce('cancel')
    const row = { ...slackAppRow }
    await w.vm.handleChannelToggle(row, false)
    await flushPromises()
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(confirm.mock.calls[0][0]).toBe(t('alerts.disableChannelConfirm', { name: 'sec-oncall' }))
    expect(api.updateChannel).toHaveBeenCalledTimes(0)
    expect(row.enabled).toBe(true)

    // 開啟不需確認
    confirm.mockClear()
    await w.vm.handleChannelToggle({ ...row, enabled: false }, true)
    expect(confirm).toHaveBeenCalledTimes(0)
    expect(api.updateChannel).toHaveBeenCalledTimes(1)

    confirm.mockRejectedValueOnce('cancel')
    await w.vm.handleDeleteChannel(row)
    const message = confirm.mock.calls.at(-1)[0]
    expect(message).toContain(t('alerts.channelDeleteCancelNotice'))
    expect(message).toContain(t('alerts.channelDeleteLogNotice'))
    expect(api.deleteChannel).toHaveBeenCalledTimes(0)
    confirm.mockRestore()
  })
})

describe('測試對話框', () => {
  const mountDialog = (channel) =>
    mount(ChannelTestDialog, { props: { modelValue: true, channel }, attachTo: document.body, global: { plugins: [ElementPlus] } })

  it('webhook 有三個內容格式選項，送出的本文只有 shape', async () => {
    api.testChannel.mockResolvedValue({ success: true, status_code: 200 })
    const w = mountDialog(webhookRow)
    await flushPromises()
    expect(document.querySelectorAll('[data-test^="channel-test-shape-"]')).toHaveLength(3)
    w.vm.shape = 'system_event'
    await w.vm.send()
    await flushPromises()
    expect(api.testChannel).toHaveBeenCalledWith(1, { shape: 'system_event' })
    expect(Object.keys(api.testChannel.mock.calls[0][1])).toEqual(['shape'])
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testOkWebhook', { status: 200 }))
  })

  it.each([slackRow, slackAppRow])('Slack 兩型（%s）沒有內容選項，不帶本文', async (row) => {
    api.testChannel.mockResolvedValue({ success: true, status_code: 200 })
    const w = mountDialog(row)
    await flushPromises()
    expect(document.querySelectorAll('[data-test^="channel-test-shape-"]')).toHaveLength(0)
    expect(body()).toContain(t('alerts.testOnceHint'))
    await w.vm.send()
    await flushPromises()
    expect(api.testChannel).toHaveBeenCalledWith(row.id)
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testOkSlack'))
  })

  it('結果留在對話框：連不上給說明與「編輯通道」；平台錯誤碼依對照給句子；404 依型別', async () => {
    api.testChannel.mockRejectedValueOnce({ response: { status: 502, data: { code: 'INTERNAL_CHANNEL_TEST_CONN_FAILED' } } })
    const w = mountDialog(slackAppRow)
    await flushPromises()
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testErr.unreachable.title'))
    expect(q('[data-test="channel-test-edit"]')).not.toBeNull()
    await q('[data-test="channel-test-edit"]').click()
    expect(w.emitted('edit')[0][0]).toEqual(slackAppRow)

    w.vm.result = null
    api.testChannel.mockResolvedValueOnce({ success: false, status_code: 200, platform_error: 'not_in_channel' })
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testErr.notInChannel.title'))
    expect(q('[data-test="channel-test-retry"]')).not.toBeNull()

    w.vm.result = null
    api.testChannel.mockResolvedValueOnce({ success: false, status_code: 200, platform_error: 'weird_code' })
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testErr.other', { code: 'weird_code' }))
  })

  it('Slack 應用程式：200 帶 platform_error 依對照給句子（token 無效給「編輯通道」）；3xx 給不跟隨轉址的句子', async () => {
    api.testChannel.mockResolvedValueOnce({ success: false, status_code: 200, platform_error: 'invalid_auth' })
    const w = mountDialog(slackAppRow)
    await flushPromises()
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testErr.badToken.title'))
    expect(q('[data-test="channel-test-edit"]')).not.toBeNull()

    w.vm.result = null
    api.testChannel.mockResolvedValueOnce({ success: false, status_code: 302 })
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.deliveryReason.http3xx', { status: '302' }))
  })

  it.each([
    ['redirect_too_many', undefined, 'alerts.deliveryReason.redirectTooMany', {}],
    ['redirect_policy', undefined, 'alerts.deliveryReason.redirectPolicy', {}],
    ['redirect_not_followed', 307, 'alerts.deliveryReason.http3xx', { status: '307' }],
  ])('測試發送回 reason_code=%s：用原因句子，不說成連不上', async (code, status, key, params) => {
    api.testChannel.mockResolvedValue({ success: false, reason_code: code, ...(status ? { status_code: status } : {}) })
    const w = mountDialog(code === 'redirect_not_followed' ? slackAppRow : webhookRow)
    await flushPromises()
    await w.vm.send()
    await flushPromises()
    const text = q('[data-test="channel-test-result"]').textContent
    expect(text).toContain(t(key, params))
    expect(text).not.toContain(t('alerts.testErr.unreachableWebhook.title'))
    expect(text).not.toContain(t('alerts.testErr.unreachable.title'))
    expect(q('[data-test="channel-test-edit"]')).not.toBeNull()
  })

  it('Slack（Incoming Webhook）回 404：網址可能已失效，給「編輯通道」', async () => {
    api.testChannel.mockResolvedValue({ success: false, status_code: 404 })
    const w = mountDialog(slackRow)
    await flushPromises()
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.testErr.http404Slack.next'))
    expect(q('[data-test="channel-test-edit"]')).not.toBeNull()
  })
})

describe('投遞紀錄抽屜', () => {
  const mountDrawer = async (channel, res) => {
    api.getChannelDeliveries.mockResolvedValue(res)
    const w = mount(ChannelDeliveryDrawer, { props: { modelValue: false, channel }, attachTo: document.body, global: { plugins: [ElementPlus] } })
    await w.setProps({ modelValue: true })
    await flushPromises()
    await w.vm.load(1)
    await flushPromises()
    return w
  }

  it('從未投遞：空狀態並提示先測試', async () => {
    await mountDrawer({ ...slackAppRow, health: { abandoned_7d: 0 } }, { data: [], total: 0 })
    expect(api.getChannelDeliveries).toHaveBeenCalledWith(3, { page: 1, page_size: 50 })
    expect(q('[data-test="log-empty"]').textContent).toContain(t('alerts.log.emptyTitle'))
    expect(body()).toContain(t('alerts.health.neverOk'))
  })

  it('各狀態的說明句、快照標示與篩選後無結果', async () => {
    const rows = [
      { id: 9, category: 'system_security_alert', event_key: 'access_policy_relaxed', severity: 'high', state: 'retrying', attempts: 17,
        last_failed_at: '2026-11-20T09:05:00Z', next_attempt_at: '2026-11-20T11:05:00Z', reason_code: 'http_404', last_error: 'HTTP 404',
        created_at: '2026-11-20T00:48:29Z', snapshot_before_change: true },
      { id: 8, category: 'system_event', event_key: 'access_request.created', severity: 'medium', state: 'delivered', attempts: 3,
        delivered_at: '2026-11-16T00:43:00Z', created_at: '2026-11-16T00:40:00Z', snapshot_before_change: false },
      { id: 7, category: 'command_alert', event_key: '', severity: 'medium', state: 'abandoned', attempts: 48, end_reason: 'max_attempts',
        reason_code: 'http_404', last_error: 'HTTP 404', ended_at: '2026-11-20T00:21:00Z', created_at: '2026-11-17T02:02:00Z' },
    ]
    const w = await mountDrawer(slackRow, { data: rows, total: 3 })
    const items = document.querySelectorAll('[data-test="log-row"]')
    expect(items).toHaveLength(3)
    expect(items[0].querySelector('[data-test="log-snapshot"]').textContent).toBe(t('alerts.log.snapshotTag'))
    expect(items[1].querySelector('[data-test="log-snapshot"]')).toBeNull()
    expect(items[0].textContent).toContain(t('systemAlerts.types.access_policy_relaxed.name'))
    expect(items[0].textContent).toContain(t('alerts.deliveryReason.http404'))
    expect(items[0].querySelector('[data-test="log-desc"]').textContent).toContain('31')
    expect(items[1].textContent).toContain(t('alerts.log.event.access_request_created'))
    expect(items[2].textContent).toContain(t('alerts.log.category.command_alert'))

    // 篩選交給伺服器：已取消送 state=canceled，回空時顯示篩選後的空狀態
    api.getChannelDeliveries.mockResolvedValue({ data: [], total: 0 })
    w.vm.filter = 'canceled'
    await w.vm.load(1)
    await flushPromises()
    expect(api.getChannelDeliveries).toHaveBeenLastCalledWith(2, { page: 1, page_size: 50, state: 'canceled' })
    expect(document.querySelectorAll('[data-test="log-row"]')).toHaveLength(0)
    expect(q('[data-test="log-empty-filtered"]').textContent).toContain(t('alerts.log.emptyFilteredHint'))
    expect(q('[data-test="log-empty"]')).toBeNull()
  })

  it('失敗過才送到的列（delivered 帶 reason_code 與 last_error）仍是送達列；等待中與已取消用中性灰', async () => {
    const rows = [
      { id: 11, category: 'system_event', event_key: 'daily_review_overdue', severity: 'medium', state: 'delivered', attempts: 3,
        delivered_at: '2026-11-20T09:12:00Z', reason_code: 'http_5xx', last_error: 'HTTP 503', last_failed_at: '2026-11-20T09:10:00Z', created_at: '2026-11-20T09:09:00Z' },
      { id: 12, category: 'system_event', event_key: 'access_request.created', severity: 'medium', state: 'pending', attempts: 0,
        next_attempt_at: '2026-11-20T09:20:00Z', throttled_since: null, created_at: '2026-11-20T09:19:00Z' },
      { id: 13, category: 'command_alert', event_key: '', severity: 'high', state: 'canceled', attempts: 2, end_reason: 'channel_disabled',
        ended_at: '2026-11-20T09:32:00Z', created_at: '2026-11-20T09:20:00Z' },
    ]
    await mountDrawer(slackRow, { data: rows, total: 3 })
    const items = document.querySelectorAll('[data-test="log-row"]')
    const delivered = items[0]
    expect(delivered.querySelector('[data-test="log-state"]').textContent.trim()).toBe(t('alerts.log.status.delivered'))
    expect(delivered.querySelector('[data-test="log-desc"]').textContent.trim()).toBe(t('alerts.log.desc.deliveredNth', { at: formatLogTime('2026-11-20T09:12:00Z'), n: 3 }))
    expect(delivered.textContent).not.toContain(t('alerts.deliveryReason.http5xx', { status: '503' }))
    expect(delivered.querySelector('[data-test="log-state"]').classList.contains('ot-tag-neutral')).toBe(false)
    expect(items[1].querySelector('[data-test="log-state"]').classList.contains('ot-tag-neutral')).toBe(true)
    expect(items[2].querySelector('[data-test="log-state"]').classList.contains('ot-tag-neutral')).toBe(true)
  })

  it('「未送達」以 pending,retrying 交給伺服器；切換篩選即重新查詢；伺服器回的列原樣顯示', async () => {
    const pendingRow = { id: 5, category: 'system_event', event_key: 'access_request.created', severity: 'medium', state: 'pending', attempts: 0,
      next_attempt_at: '2026-11-19T14:04:00Z', throttled_since: '2026-11-19T14:02:00Z', created_at: '2026-11-19T14:02:00Z' }
    const w = await mountDrawer(slackAppRow, { data: [], total: 0 })
    api.getChannelDeliveries.mockClear()
    api.getChannelDeliveries.mockResolvedValue({ data: [pendingRow], total: 1 })
    // 走真實的切換：點「未送達」按鈕觸發 change
    const btn = [...document.querySelectorAll('[data-test="log-filter"] label')].find((n) => n.textContent.includes(t('alerts.log.filter.undelivered')))
    btn.querySelector('input').click()
    await flushPromises()
    expect(api.getChannelDeliveries).toHaveBeenCalledWith(3, { page: 1, page_size: 50, state: 'pending,retrying' })
    const items = document.querySelectorAll('[data-test="log-row"]')
    expect(items).toHaveLength(1)
    expect(items[0].querySelector('[data-test="log-desc"]').textContent).toContain('72')
    expect(document.body.textContent).not.toContain('篩選只套用在目前這一頁')
    expect(w.vm.filter).toBe('undelivered')
  })
})
