// 對個人派送的前端：通道表單的開關、說明、
// 關閉確認、衝突與允許清單；通道列表的標示；投遞紀錄的收件對象篩選、收件人與原因；
// 測試發送的「傳給我自己」。斷言以實際發出的請求與渲染出的文字為準。
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
// 測試用的電子郵件樣式：任何畫面都不得渲染出來（伺服端本來就不回，這裡多放一份確認畫面不會拼出來）
const EMAIL = 'reviewer@example.test'

const secOncall = {
  id: 3, name: 'sec-oncall', type: 'slack_app', url: DEFAULT_MASKED, target: 'C07QX4M2B9A', has_secret: true,
  enabled: true, language: 'zh-TW', min_severity: 'medium', destination_changed_at: null,
  direct_message_enabled: true, direct_message_url_allowed: true,
  health: { last_delivered_at: '2026-11-20T09:12:00Z', last_failed_at: '2026-11-19T14:03:00Z', last_failure_code: 'slack_rate', last_failure_reason: 'platform error: ratelimited', abandoned_7d: 1 },
}
const auditTeam = {
  ...secOncall, id: 4, name: 'audit-team', target: 'C08AUD1T5EE', direct_message_enabled: false, health: null,
}
const relayTest = {
  ...secOncall, id: 5, name: 'relay-test', url: 'https://slack-relay.example.com/****/api', target: 'C09RLY7T2AA',
  direct_message_enabled: false, direct_message_url_allowed: false,
}
const webhookRow = {
  id: 1, name: 'soc-webhook', type: 'webhook', url: 'https://soc.example.com/****hook', target: '', has_secret: true,
  enabled: true, language: 'zh-TW', min_severity: 'low', destination_changed_at: null,
  direct_message_enabled: false, direct_message_url_allowed: false, health: null,
}
const slackRow = { ...webhookRow, id: 2, name: 'ops-slack', type: 'slack', url: 'https://hooks.slack.com/****Q2xd', has_secret: false }

const mountPanel = async (rows = [webhookRow, slackRow, secOncall, auditTeam, relayTest]) => {
  api.getChannels.mockResolvedValue({ data: rows })
  const w = mount(NotificationChannelPanel, { attachTo: document.body, global: { plugins: [ElementPlus] } })
  await w.vm.refresh()
  await flushPromises()
  return w
}
const body = () => document.body.textContent
const q = (sel) => document.body.querySelector(sel)

beforeEach(() => {
  vi.clearAllMocks()
  document.body.innerHTML = ''
  api.updateChannel.mockResolvedValue({})
  api.createChannel.mockResolvedValue({})
  api.getChannelDeliveries.mockResolvedValue({ data: [], total: 0 })
})

describe('U1 通道表單：對個人派送開關', () => {
  it('開關只在能以個人為對象的型別出現（Slack 應用程式有；Webhook、Slack Incoming Webhook 沒有）', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(webhookRow)
    await flushPromises()
    expect(q('[data-test="channel-dm-item"]')).toBeNull()
    w.vm.channelDialogVisible = false
    w.vm.openChannelDialog(slackRow)
    await flushPromises()
    expect(q('[data-test="channel-dm-item"]')).toBeNull()
    w.vm.channelDialogVisible = false
    w.vm.openChannelDialog(auditTeam)
    await flushPromises()
    expect(q('[data-test="channel-dm-item"]').textContent).toContain(t('alerts.dm.label'))
    expect(q('[data-test="channel-dm-item"]').textContent).toContain(t('alerts.dm.hint'))
    // 關閉時不展開說明框
    expect(q('[data-test="channel-dm-how"]')).toBeNull()
  })

  it('打開時出現說明框（誰會收到、怎麼對應、權限、頻道照送、官方連結）；儲存送出 direct_message_enabled', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(auditTeam)
    await flushPromises()
    w.vm.channelForm.dm = true
    await flushPromises()
    const how = q('[data-test="channel-dm-how"]').textContent
    for (const key of ['howTitle', 'who1', 'who2', 'who3', 'linkNote', 'mapTitle', 'mapBody', 'scopeTitle', 'scopeBody', 'channelNote']) {
      expect(how).toContain(t(`alerts.dm.${key}`))
    }
    const links = [...q('[data-test="channel-dm-how"]').querySelectorAll('a')].map((a) => a.getAttribute('href'))
    expect(links).toEqual([
      'https://docs.slack.dev/reference/methods/users.lookupByEmail',
      'https://docs.slack.dev/reference/methods/chat.postMessage',
    ])
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    expect(api.updateChannel.mock.calls[0][1].direct_message_enabled).toBe(true)
  })

  it('沒有改動開關時編輯不送 direct_message_enabled（不帶＝不變）', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(secOncall)
    await flushPromises()
    w.vm.channelForm.minSeverity = 'high'
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect('direct_message_enabled' in api.updateChannel.mock.calls[0][1]).toBe(false)
  })

  it('新增 Slack 應用程式時照表單送出開關值', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog()
    await flushPromises()
    Object.assign(w.vm.channelForm, { name: 'new-app', type: 'slack_app', secret: 'xoxb-1', target: 'C01ABCDEF', dm: false })
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.createChannel.mock.calls[0][0].direct_message_enabled).toBe(false)
  })

  it('已有其他通道開啟：開關下方顯示後端回傳的通道名稱，不跳全域錯誤', async () => {
    api.updateChannel.mockRejectedValue({
      response: { status: 400, data: { code: 'VALIDATION_CHANNEL_DM_CONFLICT', params: { name: 'sec-oncall' }, error: 'x' } },
    })
    const w = await mountPanel()
    w.vm.openChannelDialog(auditTeam)
    await flushPromises()
    w.vm.channelForm.dm = true
    await w.vm.handleSaveChannel()
    await flushPromises()
    const err = q('[data-test="channel-dm-error"]').textContent
    expect(err).toBe(t('alerts.dm.conflict', { name: 'sec-oncall' }))
    expect(err).toContain('「sec-oncall」')
    // 有錯誤時收起說明框，錯誤緊接在開關下方
    expect(q('[data-test="channel-dm-how"]')).toBeNull()
    // 對話框仍開著，可修正
    expect(w.vm.channelDialogVisible).toBe(true)
  })

  it('關閉時出現確認框（不寫筆數）；按取消不送出，按確認才送出 false', async () => {
    const confirm = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValueOnce('cancel')
    const w = await mountPanel()
    w.vm.openChannelDialog(secOncall)
    await flushPromises()
    w.vm.channelForm.dm = false
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(confirm).toHaveBeenCalledTimes(1)
    expect(confirm.mock.calls[0][0]).toBe(t('alerts.dm.offBody', { name: 'sec-oncall' }))
    expect(confirm.mock.calls[0][1]).toBe(t('alerts.dm.offTitle'))
    expect(confirm.mock.calls[0][2].confirmButtonText).toBe(t('alerts.dm.offConfirm'))
    expect(confirm.mock.calls[0][0]).not.toMatch(/[0-9]+ ?(筆|則)/)
    expect(api.updateChannel).toHaveBeenCalledTimes(0)

    confirm.mockResolvedValueOnce('confirm')
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    expect(api.updateChannel.mock.calls[0][1].direct_message_enabled).toBe(false)
    confirm.mockRestore()
  })

  it('網址不在允許清單：開關停用並顯示說明，說明框不展開', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(relayTest)
    await flushPromises()
    expect(q('[data-test="channel-dm-not-allowed"]').textContent).toContain(t('alerts.dm.notAllowed'))
    expect(q('[data-test="channel-dm-switch"]').classList.contains('is-disabled')).toBe(true)
    expect(q('[data-test="channel-dm-how"]')).toBeNull()
  })

  it('開啟時伺服端回網址不在允許清單：開關下方顯示說明', async () => {
    api.createChannel.mockRejectedValue({ response: { status: 400, data: { code: 'VALIDATION_CHANNEL_DM_URL_NOT_ALLOWED', error: 'x' } } })
    const w = await mountPanel()
    w.vm.openChannelDialog()
    await flushPromises()
    Object.assign(w.vm.channelForm, { name: 'n', type: 'slack_app', secret: 'xoxb-1', target: 'C01ABCDEF', dm: true, url: 'https://relay.example.com/api' })
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(q('[data-test="channel-dm-error"]').textContent).toBe(t('alerts.dm.notAllowed'))
  })

  it('已開啟、改網址到不能確定在清單內的主機：出現自動關閉提示（網址原因），儲存不另跳確認框', async () => {
    const confirm = vi.spyOn(ElMessageBox, 'confirm')
    const w = await mountPanel()
    w.vm.openChannelDialog(secOncall)
    await flushPromises()
    expect(q('[data-test="channel-dm-auto-off"]')).toBeNull()
    w.vm.channelForm.url = 'https://slack-relay.example.com/api'
    w.vm.channelForm.secret = 'xoxb-2'
    await flushPromises()
    const notice = q('[data-test="channel-dm-auto-off"]').textContent
    // 改網址：是否在允許清單內畫面無從得知，標題用條件句，不用確定句
    expect(notice).toContain(t('alerts.dm.autoOffWarnHost'))
    expect(notice).not.toContain(t('alerts.dm.autoOffWarn'))
    expect(notice).toContain(t('alerts.dm.autoOffReasonHost'))
    expect(q('[data-test="channel-dm-how"]')).toBeNull()
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect(confirm).toHaveBeenCalledTimes(0)
    expect(api.updateChannel).toHaveBeenCalledTimes(1)
    confirm.mockRestore()
  })

  it('改網址但仍是 Slack 官方主機：不提示自動關閉', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(secOncall)
    await flushPromises()
    w.vm.channelForm.url = 'https://slack.com/api/'
    await flushPromises()
    expect(q('[data-test="channel-dm-auto-off"]')).toBeNull()
  })

  it('已開啟、改成 Webhook：出現自動關閉提示（型別原因），儲存不送 direct_message_enabled', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(secOncall)
    await flushPromises()
    w.vm.channelForm.type = 'webhook'
    w.vm.onTypeChange('webhook')
    w.vm.channelForm.url = 'https://soc.example.com/hook'
    await flushPromises()
    const notice = q('[data-test="channel-dm-auto-off"]').textContent
    // 改型別：必定關閉，標題維持確定句
    expect(notice).toContain(t('alerts.dm.autoOffWarn'))
    expect(notice).not.toContain(t('alerts.dm.autoOffWarnHost'))
    expect(notice).toContain(t('alerts.dm.autoOffReasonType'))
    expect(q('[data-test="channel-dm-item"]')).toBeNull()
    await w.vm.handleSaveChannel()
    await flushPromises()
    expect('direct_message_enabled' in api.updateChannel.mock.calls[0][1]).toBe(false)
  })

  it('原本沒開的通道改網址或型別：不提示自動關閉', async () => {
    const w = await mountPanel()
    w.vm.openChannelDialog(auditTeam)
    await flushPromises()
    w.vm.channelForm.url = 'https://slack-relay.example.com/api'
    await flushPromises()
    expect(q('[data-test="channel-dm-auto-off"]')).toBeNull()
  })
})

describe('U3 通道列表', () => {
  it('開了對個人派送的通道名稱下有標籤；送達狀況欄下方說明只統計頻道', async () => {
    const w = await mountPanel()
    const tags = document.querySelectorAll('[data-test="channel-dm-tag"]')
    expect(tags).toHaveLength(1)
    expect(tags[0].closest('tr').textContent).toContain('sec-oncall')
    expect(tags[0].textContent).toContain(t('alerts.dm.tag'))
    expect(q('[data-test="channel-health-dm-hint"]').textContent).toContain(t('alerts.health.channelOnlyHint'))
    w.unmount()
  })

  it('沒有能以個人為對象的通道時不顯示那句說明', async () => {
    await mountPanel([webhookRow, slackRow])
    expect(q('[data-test="channel-health-dm-hint"]')).toBeNull()
  })
})

describe('U4 投遞紀錄抽屜', () => {
  const at = '2026-11-20T09:02:00Z'
  const rows = [
    { id: 11, category: 'system_event', event_key: 'access_request_created', severity: 'medium', state: 'delivered', attempts: 1, delivered_at: at, created_at: at, audience: 'user', recipient_username: 'lin.mei', recipient_slack_id: 'U07LM4K2Q9B' },
    { id: 12, category: 'system_event', event_key: 'access_request_created', severity: 'medium', state: 'canceled', attempts: 1, last_failed_at: at, reason_code: 'http_5xx', last_error: 'HTTP 503', end_reason: 'request_resolved', ended_at: '2026-11-20T09:06:00Z', created_at: at, audience: 'user', recipient_username: 'wang.jie', recipient_slack_id: 'U07WJ8R1T3C' },
    { id: 13, category: 'system_event', event_key: 'access_request_created', severity: 'medium', state: 'abandoned', attempts: 0, end_reason: 'no_email', ended_at: at, created_at: at, audience: 'user', recipient_username: 'huang.yu' },
    { id: 14, category: 'system_event', event_key: 'access_request_created', severity: 'medium', state: 'delivered', attempts: 1, delivered_at: at, created_at: at, audience: 'channel' },
  ]
  const mountDrawer = async (channel, res = { data: rows, total: rows.length }) => {
    api.getChannelDeliveries.mockResolvedValue(res)
    const w = mount(ChannelDeliveryDrawer, { props: { modelValue: false, channel }, attachTo: document.body, global: { plugins: [ElementPlus] } })
    await w.setProps({ modelValue: true })
    await flushPromises()
    return w
  }

  it('收件對象篩選：全部不帶參數、頻道與個人以 audience 交給伺服器', async () => {
    const w = await mountDrawer(secOncall)
    expect(api.getChannelDeliveries).toHaveBeenLastCalledWith(3, { page: 1, page_size: 50 })
    expect(q('[data-test="log-audience"]').textContent).toContain(t('alerts.log.audienceUser'))
    w.vm.audience = 'user'
    await w.vm.load(1)
    expect(api.getChannelDeliveries).toHaveBeenLastCalledWith(3, { page: 1, page_size: 50, audience: 'user' })
    w.vm.audience = 'channel'
    w.vm.filter = 'canceled'
    await w.vm.load(1)
    expect(api.getChannelDeliveries).toHaveBeenLastCalledWith(3, { page: 1, page_size: 50, state: 'canceled', audience: 'channel' })
  })

  it('個人訊息列：收件人帳號與 Slack 帳號；尚未對應時寫「尚未對應」；頻道列沒有收件人行', async () => {
    await mountDrawer(secOncall)
    const list = [...document.querySelectorAll('[data-test="log-row"]')]
    expect(list).toHaveLength(4)
    expect(list[0].querySelector('[data-test="log-recipient"]').textContent).toContain('lin.mei')
    expect(list[0].querySelector('[data-test="log-recipient"]').textContent).toContain('U07LM4K2Q9B')
    expect(list[2].querySelector('[data-test="log-recipient"]').textContent).toContain(t('alerts.log.recipientUnmapped'))
    expect(list[3].querySelector('[data-test="log-recipient"]')).toBeNull()
    expect(list[0].querySelector('[data-test="log-audience-tag"]').textContent).toContain(t('alerts.log.audienceUser'))
    expect(list[3].querySelector('[data-test="log-audience-tag"]').textContent).toContain(t('alerts.log.audienceChannel'))
  })

  it('私訊特有的原因：放棄寫原因句；取消前試過的寫次數與最近原因，再接原因句', async () => {
    await mountDrawer(secOncall)
    const list = [...document.querySelectorAll('[data-test="log-row"]')]
    const canceled = list[1].querySelector('[data-test="log-desc"]').textContent
    expect(canceled).toContain(t('alerts.log.endReason.request_resolved'))
    expect(canceled).toContain(formatLogTime('2026-11-20T09:06:00Z'))
    expect(canceled).toContain(t('alerts.deliveryReason.http5xx', { status: '503' }))
    expect(list[2].querySelector('[data-test="log-desc"]').textContent).toBe(t('alerts.log.endReason.no_email'))
  })

  it.each(['email_ambiguous', 'recipient_not_found'])('放棄原因 %s', async (reason) => {
    await mountDrawer(secOncall, { data: [{ ...rows[2], end_reason: reason }], total: 1 })
    expect(q('[data-test="log-desc"]').textContent).toBe(t(`alerts.log.endReason.${reason}`))
  })

  it.each(['recipient_ineligible', 'direct_message_disabled'])('取消原因 %s（沒試過）', async (reason) => {
    await mountDrawer(secOncall, { data: [{ ...rows[1], attempts: 0, last_failed_at: null, end_reason: reason }], total: 1 })
    const text = q('[data-test="log-desc"]').textContent
    expect(text).toBe(t('alerts.log.desc.canceledAt', { at: formatLogTime('2026-11-20T09:06:00Z') }) + t(`alerts.log.endReason.${reason}`))
  })

  it('摘要卡標明只統計頻道，說明句提到不顯示電子郵件；不渲染任何電子郵件欄位', async () => {
    await mountDrawer(secOncall, { data: rows.map((r) => ({ ...r, email: EMAIL, recipient_email: EMAIL })), total: 4 })
    expect(q('[data-test="log-card-ok"]').textContent).toContain(t('alerts.log.sumChannelSuffix'))
    expect(q('[data-test="log-card-abandoned"]').textContent).toContain(t('alerts.log.sumChannelSuffix'))
    expect(body()).toContain(t('alerts.log.introExtraDm'))
    expect(body()).not.toContain(EMAIL)
    expect(body()).not.toContain('@example')
  })

  it('Webhook 通道沒有收件對象篩選、摘要卡不加後綴（沿用地基的說明句）', async () => {
    await mountDrawer(webhookRow, { data: [rows[3]], total: 1 })
    expect(q('[data-test="log-audience"]')).toBeNull()
    expect(q('[data-test="log-card-ok"]').textContent).not.toContain(t('alerts.log.sumChannelSuffix'))
    expect(body()).toContain(t('alerts.log.introExtra'))
  })
})

describe('U5 測試發送：傳給我自己', () => {
  const mountDialog = (channel) =>
    mount(ChannelTestDialog, { props: { modelValue: true, channel }, attachTo: document.body, global: { plugins: [ElementPlus] } })

  it('Slack 應用程式有兩個選項、預設送到頻道（送出不帶本文）；對話框沒有任何位址或收件人欄位', async () => {
    api.testChannel.mockResolvedValue({ success: true, status_code: 200 })
    const w = mountDialog(secOncall)
    await flushPromises()
    expect(q('[data-test="channel-test-kind-channel"]').textContent).toContain(t('alerts.test.toChannel'))
    expect(q('[data-test="channel-test-kind-self"]').textContent).toContain(t('alerts.test.toSelf'))
    expect(document.querySelectorAll('[data-test="channel-test-dialog"] input:not([type="radio"]), [data-test="channel-test-dialog"] textarea')).toHaveLength(0)
    await w.vm.send()
    await flushPromises()
    expect(api.testChannel).toHaveBeenCalledWith(3)
  })

  it('選「傳給我自己」送出的本文只有 to_self；成功時顯示 Slack 顯示名稱', async () => {
    api.testChannel.mockResolvedValue({ success: true, result: 'delivered', display_name: 'IT Admin' })
    const w = mountDialog(secOncall)
    await flushPromises()
    w.vm.kind = 'self'
    await w.vm.send()
    await flushPromises()
    expect(api.testChannel).toHaveBeenCalledWith(3, { to_self: true })
    expect(Object.keys(api.testChannel.mock.calls[0][1])).toEqual(['to_self'])
    const text = q('[data-test="channel-test-result"]').textContent
    expect(text).toContain(t('alerts.test.toSelfResult.delivered'))
    expect(text).toContain(t('alerts.test.selfOkBody', { display_name: 'IT Admin' }))
  })

  it.each([
    ['no_email', 'selfNoEmailNext'],
    ['email_ambiguous', 'selfAmbiguousNext'],
    ['recipient_not_found', 'selfNotFoundNext'],
  ])('結果 %s：標題與下一步', async (result, nextKey) => {
    api.testChannel.mockResolvedValue({ success: false, result })
    const w = mountDialog(secOncall)
    await flushPromises()
    w.vm.kind = 'self'
    await w.vm.send()
    await flushPromises()
    const text = q('[data-test="channel-test-result"]').textContent
    expect(text).toContain(t(`alerts.test.toSelfResult.${result}`))
    expect(text).toContain(t(`alerts.test.${nextKey}`))
  })

  it('平台錯誤：缺 users:read.email 給專屬句與「編輯通道」；其他碼給錯誤碼句與「再測一次」', async () => {
    api.testChannel.mockResolvedValueOnce({ success: false, result: 'platform_error', platform_error: 'missing_scope', status_code: 200 })
    const w = mountDialog(secOncall)
    await flushPromises()
    w.vm.kind = 'self'
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.test.selfScopeTitle'))
    expect(q('[data-test="channel-test-edit"]')).not.toBeNull()

    w.vm.result = null
    api.testChannel.mockResolvedValueOnce({ success: false, result: 'platform_error', platform_error: 'odd_error', status_code: 200 })
    await w.vm.send()
    await flushPromises()
    const text = q('[data-test="channel-test-result"]').textContent
    expect(text).toContain(t('alerts.testErr.other', { code: 'odd_error' }))
    expect(text).toContain(t('alerts.test.platformErrorNext'))
    expect(q('[data-test="channel-test-retry"]')).not.toBeNull()
  })

  it('網址不在允許清單：「傳給我自己」停用並寫原因，不能選', async () => {
    mountDialog(relayTest)
    await flushPromises()
    const self = q('[data-test="channel-test-kind-self"]')
    expect(self.classList.contains('is-disabled')).toBe(true)
    expect(self.textContent).toContain(t('alerts.test.toSelfNotAllowed'))
    expect(self.textContent).not.toContain(t('alerts.test.toSelfDesc'))
  })

  it('伺服端拒絕（網址不在清單）時顯示同一句', async () => {
    api.testChannel.mockRejectedValue({ response: { status: 400, data: { code: 'VALIDATION_CHANNEL_DM_URL_NOT_ALLOWED' } } })
    const w = mountDialog(secOncall)
    await flushPromises()
    w.vm.kind = 'self'
    await w.vm.send()
    await flushPromises()
    expect(q('[data-test="channel-test-result"]').textContent).toContain(t('alerts.test.toSelfNotAllowed'))
  })

  it('Webhook 與 Slack Incoming Webhook 沒有「傳給我自己」', async () => {
    mountDialog(slackRow)
    await flushPromises()
    expect(q('[data-test="channel-test-kind-self"]')).toBeNull()
  })
})
