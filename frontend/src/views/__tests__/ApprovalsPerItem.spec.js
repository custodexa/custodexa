import i18n from '@/i18n'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Approvals from '../Approvals.vue'
import Review from '@/components/access-request/PerItemApproval.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
const api = vi.hoisted(() => ({ asset: vi.fn(), pending: vi.fn(), approve: vi.fn(), reject: vi.fn(), accounts: vi.fn() }))
vi.mock('@/api/accessRequests', async original => ({ ...(await original()), getPendingAccessRequests: api.pending, approveAccessRequest: api.approve, rejectAccessRequestItem: api.reject }))
vi.mock('@/api/assets', () => ({ getAsset: api.asset }))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: api.accounts }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
enableAutoUnmount(afterEach)
const request = () => ({ id: 23, requester_id: 5, requester: { id: 5, username: 'worker', kind: 'agent', owner_user_id: 2 }, status: 'pending', requested_duration_minutes: 240, requested_date_start: '2099-01-01T00:00:00Z', items: [{ id: 1, asset_id: 1, accounts: ['ops', 'deploy'], status: 'pending' }, { id: 2, asset_id: 2, accounts: ['db'], status: 'pending' }] })
beforeEach(() => { vi.clearAllMocks(); api.asset.mockResolvedValue({ name: 'db-host', protocol: 'ssh' }); api.pending.mockResolvedValue({ data: [request()] }); api.approve.mockResolvedValue({ items: [{ id: 1, status: 'approved' }] }); api.reject.mockResolvedValue({}); api.accounts.mockResolvedValue({ data: [{ username: 'ops' }, { username: 'deploy' }] }) })
const open = (data = request()) => mount(Review, { props: { request: data, actorId: 9 }, global: { plugins: [ElementPlus] } })
describe('逐項審核', () => {
  // 回歸：整張單同時攤開時，第二項的決策控制與送出列落在可見範圍外要捲才看得到
  it('一次只展開一項，決定完接續下一個待決項', async () => {
    const w = open()
    await flushPromises()
    // v-show 以行內 display 收合；未掛進文件的節點 isVisible() 判不出來，直接讀樣式
    const shown = () => w.findAll('[data-test="item-body"]').map(b => b.attributes('style') !== 'display: none;')
    expect(shown()).toEqual([true, false])
    await w.findAll('[data-test="toggle-item"]')[1].trigger('click')
    await flushPromises()
    expect(shown()).toEqual([false, true])
  })
  it('展開後每項各自可決定', async () => {
    const w = mount(Approvals, { global: { plugins: [ElementPlus] } }); await flushPromises()
    await w.get('.el-table__expand-icon').trigger('click'); await flushPromises()
    const review = w.getComponent(Review)
    expect(review.findAll('[data-test="decision-item"]')).toHaveLength(2)
    expect(review.findAllComponents({ name: 'ElRadioGroup' })).toHaveLength(2)
    review.vm.forms[1].action = 'approve'; review.vm.forms[2].action = 'reject'; review.vm.forms[2].note = 'no access'; await flushPromises()
    await review.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    expect(api.approve).toHaveBeenCalledWith(23, expect.objectContaining({ item_id: 1 }))
    expect(api.reject).toHaveBeenCalledWith(23, 2, 'no access')
  })
  // 回歸：送出後畫面留在舊的 radio、頁籤待審數又已經變了，同一頁兩個矛盾答案
  it('送出後以 API 回傳寫回該列狀態，該列留在原位不被重抓掉', async () => {
    api.approve.mockResolvedValue({ items: [{ id: 1, status: 'approved' }] })
    const w = mount(Approvals, { global: { plugins: [ElementPlus] } }); await flushPromises()
    await w.get('.el-table__expand-icon').trigger('click'); await flushPromises()
    const review = w.getComponent(Review)
    review.vm.forms[1].action = 'approve'; review.vm.forms[1].accounts = ['ops']; review.vm.forms[1].duration = 30
    await flushPromises()
    api.pending.mockResolvedValue({ data: [] })
    const events = []
    window.addEventListener('ot-approvals-changed', () => events.push(1))
    await review.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    // 剛決定的單不得立刻消失：審核者要看得到自己做了什麼，並能直達該申請單
    expect(api.pending).toHaveBeenCalledTimes(1)
    expect(events).toHaveLength(1)
    expect(review.get('[data-test="decision-result"]').exists()).toBe(true)
    expect(review.get('[data-test="open-request-link"]').attributes('href')).toBe('/approvals?request=23')
  })
  it('單項決定後該項改以已決定狀態呈現，不再留可改的選項', async () => {
    const w = open()
    w.vm.forms[1].action = 'approve'; w.vm.forms[1].accounts = ['ops']; w.vm.forms[1].duration = 30
    await w.vm.submit(); await flushPromises()
    const items = w.findAll('[data-test="decision-item"]')
    expect(items[0].find('[data-test="item-decided-state"]').exists()).toBe(true)
    expect(items[0].findComponent({ name: 'ElRadioGroup' }).exists()).toBe(false)
  })
  it('單頭直接答出誰申請、替誰做', async () => {
    const text = open().get('[data-test="review-header"]').text()
    expect(text).toContain('worker')
    expect(text).toMatch(/自主|autonom|自律/)
  })
  it('agent 申請單標示主體類型與負責人', async () => {
    const w = mount(Approvals, { global: { plugins: [ElementPlus] } }); await flushPromises()
    expect(w.getComponent(PrincipalBadge).text()).toContain('AI agent')
    expect(w.getComponent(PrincipalBadge).text()).toContain('負責人：未提供')
  })
  it('時長與帳號選項不可上調', async () => {
    const w = open(); w.vm.forms[1].action = 'approve'; await flushPromises()
    expect(w.getComponent({ name: 'ElInputNumber' }).props('max')).toBe(240)
    expect(w.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).toEqual(['ops', 'deploy'])
    w.vm.forms[1].duration = 241; await w.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
    w.vm.forms[1].duration = 30; w.vm.forms[1].accounts = ['root']; await w.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
    w.vm.forms[1].accounts = ['ops']; w.vm.forms[1].start = new Date('2098-01-01T00:00:00Z'); await w.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
  })
  it('帳號範圍可下修為子集', async () => {
    const w = open(); w.vm.forms[1].action = 'approve'; w.vm.forms[1].accounts = ['ops']; w.vm.forms[1].duration = 30
    await w.vm.submit(); expect(api.approve).toHaveBeenCalledWith(23, { item_id: 1, accounts: ['ops'], duration_minutes: 30, note: '' })
    const data = request(); data.items[0].accounts = ['@ALL']; const all = open(data)
    await all.vm.narrowAll(data.items[0]); all.vm.forms[1].accounts = ['ops']; all.vm.scopeChanged(data.items[0]); all.vm.forms[1].action = 'approve'; await flushPromises()
    expect(all.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).not.toContain('@ALL')
  })
  it('送出前呈現逐項摘要', async () => {
    const w = open(); w.vm.forms[1].action = 'approve'; w.vm.forms[1].duration = 30; w.vm.forms[1].accounts = ['ops']; w.vm.forms[2].action = 'remove'; w.vm.forms[2].note = 'not needed'; await flushPromises()
    const text = w.get('[data-test="decision-summary"]').text()
    expect(text).toContain('db-host'); expect(text).not.toContain('項目 #1'); expect(text).toContain('30 分鐘'); expect(text).toContain('ops'); expect(text).toContain('移除（拒絕）'); expect(api.approve).not.toHaveBeenCalled()
    expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0)
  })
  it('部分失敗時逐項回報', async () => {
    const w = open(); w.vm.forms[1].action = 'approve'; w.vm.forms[2].action = 'reject'; w.vm.forms[2].note = 'no'
    api.reject.mockRejectedValue({ response: { status: 409, data: { code: 'CONFLICT_ACCESS_REQUEST_STATE' } } })
    await w.vm.submit(); await flushPromises()
    expect(w.findAll('[data-test="decision-result"]')).toHaveLength(2)
    expect(w.vm.results[1].ok).toBe(true); expect(w.vm.results[2].ok).toBe(false)
    expect(w.text()).toContain('此項決定已儲存')
    await w.vm.submit(); expect(api.approve).toHaveBeenCalledTimes(1); expect(api.reject).toHaveBeenCalledTimes(2)
  })
})

it('執行者投影與 decision_bounds 由真欄位呈現', async () => {
  const data = request(); data.requester.kind = 'human'; data.executor_user_id = 10; data.executor = { id: 10, username: 'executor', kind: 'agent', owner_user_id: 4, owner_username: 'responsible' }
  data.items[0].decision_bounds = { max_duration: 30, earliest_start: '2099-02-01T00:00:00Z', accounts: ['ops'] }
  api.pending.mockResolvedValue({ data: [data] }); const w = mount(Approvals, { global: { plugins: [ElementPlus] } }); await flushPromises()
  expect(w.get('[data-test="executor-principal"]').text()).toContain('responsible')
  const review = open(data); review.vm.forms[1].action = 'approve'; await flushPromises()
  expect(review.getComponent({ name: 'ElInputNumber' }).props('max')).toBe(30)
  expect(review.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).toEqual(['ops'])
  review.vm.forms[1].start = new Date('2099-01-02T00:00:00Z'); await review.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
})
it('範圍外的項可見但不可決定：依 11:20 裁決於明確後端拒絕後停用', async () => {
  const w = open(); w.vm.forms[1].action = 'approve'
  api.approve.mockRejectedValue({ response: { status: 403, data: { code: 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER' } } })
  await w.vm.submit(); await flushPromises()
  expect(w.findAll('[data-test="decision-item"]')).toHaveLength(2)
  expect(w.findAllComponents({ name: 'ElRadioGroup' })[0].props('disabled')).toBe(true)
  expect(w.findAllComponents({ name: 'ElRadioGroup' })[1].props('disabled')).toBe(false)
  expect(w.get('[data-test="decision-result"]').text()).not.toContain('RULE_ACCESS_REQUEST')
})

it.each(['zh-TW', 'en-US', 'ja-JP'])('畫面 3 三語 DOM：項目與確認同層 %s', async locale => { i18n.global.locale.value = locale; const w = open(); w.vm.forms[1].action = 'approve'; await flushPromises(); expect(w.findAll('[data-test="decision-item"]')).toHaveLength(2); expect(w.find('[data-test="decision-summary"]').exists()).toBe(true); expect(w.text()).not.toMatch(/itemReview\.|multiRequest\.|approvals\./); expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0) })

it('polish 6–8：逐項資產名稱、常駐移除說明與待審關鍵欄可見', async () => {
  const data = request(); data.asset_id = 1; data.asset = { name: 'app-host' }; api.pending.mockResolvedValue({ data: [data] })
  const w = mount(Approvals, { global: { plugins: [ElementPlus] } }); await flushPromises()
  const table = w.get('[data-test="pending-table"]')
  for (const label of ['申請人', '資產', '申請理由', '申請時間', '操作']) expect(table.findAll('th').some(th => th.text().includes(label) && th.isVisible())).toBe(true)
  const columns = w.getComponent('[data-test="pending-table"]').findAllComponents({ name: 'ElTableColumn' })
  expect(columns.reduce((sum, col) => sum + Number(col.props('width') || col.props('minWidth') || 48), 0)).toBeLessThanOrEqual(1000)
  await w.get('.el-table__expand-icon').trigger('click'); await flushPromises()
  const items = w.findAll('[data-test="decision-item"]')
  expect(items[0].get('h3').text()).toBe('app-host')
  expect(items[1].get('h3').text()).toBe('db-host')
  expect(api.asset).not.toHaveBeenCalledWith(1, expect.anything())
  expect(items[0].get('[data-test="remove-explanation"]').text()).toContain('審核紀錄仍會保留')
})

it('polish2：待審申請人就是執行者時合併同一組主體，姓名只顯示一次', async () => {
  const data = request()
  data.executor_user_id = data.requester_id
  data.executor = { ...data.requester, owner_username: 'admin' }
  api.pending.mockResolvedValue({ data: [data] })
  const w = mount(Approvals, { global: { plugins: [ElementPlus] } }); await flushPromises()
  const table = w.get('[data-test="pending-table"]')
  expect(table.findAll('.principal-badge')).toHaveLength(1)
  expect(table.text().split('負責人：admin')).toHaveLength(2)
  expect(table.text()).not.toContain('負責人：未提供')
  expect(table.find('[data-test="executor-principal"]').exists()).toBe(false)
})

describe('自主執行的 agent 不被寫成代表其 owner', () => {
  it('無 on_behalf_of 時顯示自主執行並附負責人', async () => {
    const w = open({ ...request(), requester: { id: 5, username: 'worker', kind: 'agent', owner_user_id: 2, owner_username: 'owner-a' } })
    await flushPromises()
    const line = w.get('[data-test="review-representation"]').text()
    expect(line).toContain('自主執行')
    expect(line).toContain('owner-a')
    expect(line).not.toContain('代表：')
  })
  it('有 on_behalf_of 時才寫代表', async () => {
    const w = open({ ...request(), on_behalf_of_username: 'human-b' })
    await flushPromises()
    expect(w.get('[data-test="review-representation"]').text()).toBe('代表：human-b')
  })
})
