import i18n from '@/i18n'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import Approvals from '../Approvals.vue'
import Review from '@/components/access-request/PerItemApproval.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'

// 展開區：預設唯讀、底部一組拒絕與核准；逐項調整是明確進入、可退出的模式
const api = vi.hoisted(() => ({ asset: vi.fn(), pending: vi.fn(), approve: vi.fn(), reject: vi.fn(), accounts: vi.fn(), count: vi.fn() }))
vi.mock('@/api/accessRequests', async original => ({
  ...(await original()),
  getPendingAccessRequests: api.pending,
  getPendingAccessRequestCount: api.count,
  approveAccessRequest: api.approve,
  rejectAccessRequestItem: api.reject,
}))
vi.mock('@/api/assets', () => ({ getAsset: api.asset }))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: api.accounts }))
class Observer { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', Observer)
vi.setConfig({ testTimeout: 20_000 })
enableAutoUnmount(afterEach)
afterEach(() => { ElMessage.closeAll(); document.body.querySelectorAll('.el-message').forEach(n => n.remove()) })

const request = () => ({
  id: 23,
  requester_id: 5,
  requester: { id: 5, username: 'worker', kind: 'agent', owner_user_id: 2 },
  status: 'pending',
  reason: 'patch window',
  requested_duration_minutes: 240,
  requested_date_start: '2099-01-01T00:00:00Z',
  created_at: '2026-11-23T02:10:00Z',
  items: [
    { id: 1, asset_id: 1, asset_name: 'app-host', accounts: ['ops', 'deploy'], status: 'pending' },
    { id: 2, asset_id: 2, asset_name: 'db-host', accounts: ['db'], status: 'pending' },
  ],
})
beforeEach(() => {
  vi.clearAllMocks()
  api.asset.mockRejectedValue({ response: { status: 404 } })
  api.pending.mockResolvedValue({ data: [request()] })
  api.count.mockResolvedValue({ count: 1, review_count: 0 })
  api.approve.mockResolvedValue({ items: [{ id: 1, status: 'approved' }] })
  api.reject.mockResolvedValue({})
  api.accounts.mockResolvedValue({ data: [{ username: 'ops' }, { username: 'deploy' }] })
  localStorage.setItem('user', JSON.stringify({ id: 9, username: 'appr', roles: ['user', 'approver'] }))
})
const open = (data = request(), props = {}) => mount(Review, { props: { request: data, actorId: 9, ...props }, global: { plugins: [ElementPlus] } })
const adjust = (data = request()) => open(data, { adjusting: true })
const radios = (w, index) => w.findAll('[data-test="decision-item"]')[index].findAll('input[type="radio"]')
const mountView = () => mount(Approvals, { global: { plugins: [ElementPlus] }, attachTo: document.body })
// 照瀏覽器的鍵盤行為：先把焦點放到元素上，對焦點所在派送 Enter；沒有被處理且焦點是按鈕時，瀏覽器會按下該按鈕
async function pressEnterOn(el) {
  el.focus()
  expect(document.activeElement).toBe(el)
  const event = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })
  el.dispatchEvent(event)
  if (!event.defaultPrevented && el.tagName === 'BUTTON') el.click()
  await flushPromises()
}
const tabTo = async (w, name) => { await w.get(`#tab-${name}`).trigger('click'); await flushPromises() }

describe('展開區唯讀與調整模式', () => {
  it('唯讀：逐台列出資產、帳號、時長與開始，底部只有一組拒絕與核准，沒有任何選項', () => {
    const w = open()
    const rows = w.findAll('[data-test="detail-item"]')
    expect(rows).toHaveLength(2)
    expect(rows[1].text()).toContain('db-host')
    expect(rows[1].text()).toContain('db')
    expect(w.findAll('[data-test="detail-approve"]')).toHaveLength(1)
    expect(w.findAll('[data-test="detail-reject"]')).toHaveLength(1)
    expect(w.find('input[type="radio"]').exists()).toBe(false)
    expect(w.text()).toContain('patch window')
  })

  it('核准、拒絕與進入調整都交給頁面處理（唯讀狀態不送出任何請求）', async () => {
    const w = open()
    await w.get('[data-test="detail-approve"]').trigger('click')
    await w.get('[data-test="detail-reject"]').trigger('click')
    await w.get('[data-test="enter-adjust"]').trigger('click')
    expect(w.emitted('approve')).toHaveLength(1)
    expect(w.emitted('reject')).toHaveLength(1)
    expect(w.emitted('adjust')).toHaveLength(1)
    expect(api.approve).not.toHaveBeenCalled()
  })

  it('調整連結：多台寫「只核准其中幾台」，單台只寫縮短時間或縮小帳號', () => {
    expect(open().get('[data-test="enter-adjust"]').text()).toContain('只核准其中幾台')
    const one = request(); one.items = [one.items[0]]
    expect(open(one).get('[data-test="enter-adjust"]').text()).toBe('縮短時間或縮小帳號')
  })

  it('調整模式每台只有核准與拒絕兩個選項，沒有刪除項目', () => {
    const w = adjust()
    const values = w.findAll('[data-test="decision-item"]').map(item => item.findAll('input[type="radio"]').map(r => r.element.value))
    expect(values).toEqual([['approve', 'reject'], ['approve', 'reject']])
    expect(w.text()).not.toMatch(/移除|remove/i)
  })

  it('取消調整不送出，再進入時沒有預選（在頁面裡實際操作）', async () => {
    const w = mountView(); await flushPromises()
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    await w.get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    await radios(w, 0)[0].setValue(true)
    await radios(w, 1)[1].setValue(true)
    await w.get('[data-test="cancel-adjust"]').trigger('click'); await flushPromises()
    expect(w.getComponent(Review).attributes('data-mode')).toBe('read')
    await w.get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    expect(w.getComponent(Review).attributes('data-mode')).toBe('adjust')
    expect(w.findAll('input[type="radio"]:checked')).toHaveLength(0)
    expect(w.find('[data-test="decision-chip"]').exists()).toBe(false)
    expect(api.approve).not.toHaveBeenCalled()
    expect(api.reject).not.toHaveBeenCalled()
  })

  it('換頁籤再回來：離開逐項調整，沒有送出的選擇不保留', async () => {
    const w = mountView(); await flushPromises()
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    await w.get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    await radios(w, 0)[0].setValue(true)
    await tabTo(w, 'history')
    await tabTo(w, 'pending')
    const review = w.findComponent(Review)
    if (review.exists()) {
      expect(review.attributes('data-mode')).toBe('read')
      await review.get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
      expect(w.findAll('input[type="radio"]:checked')).toHaveLength(0)
    }
    expect(api.approve).not.toHaveBeenCalled()
  })

  it('沒選就按送出：沒有請求、出現說明；送出鈕在 Tab 順序內（沒有 disabled）', async () => {
    const w = adjust()
    const submit = w.get('[data-test="submit-decisions"]')
    expect(submit.attributes('disabled')).toBeUndefined()
    expect(submit.text()).toBe('送出決定')
    await submit.trigger('click')
    expect(w.get('[data-test="adjust-status"]').text()).toBe('選好至少一台的決定後才能送出')
    expect(w.get('[data-test="adjust-status"]').attributes('role')).toBe('alert')
    expect(api.approve).not.toHaveBeenCalled()
  })

  it('第二台選拒絕沒填理由：沒有任何請求，第二台展開、理由欄標紅並取得焦點', async () => {
    const w = mount(Review, { props: { request: request(), actorId: 9, adjusting: true }, global: { plugins: [ElementPlus] }, attachTo: document.body })
    await radios(w, 0)[0].setValue(true)
    await radios(w, 1)[1].setValue(true)
    // 先把第二台收合：第一個出錯的台要自動展開
    w.vm.editing = 1
    await flushPromises()
    expect(w.findAll('[data-test="decision-chip"]')).toHaveLength(1)
    await w.get('[data-test="submit-decisions"]').trigger('click')
    await flushPromises()
    expect(api.approve).not.toHaveBeenCalled()
    expect(api.reject).not.toHaveBeenCalled()
    const second = w.findAll('[data-test="decision-item"]')[1]
    expect(second.classes()).toContain('item-review__row--error')
    expect(second.text()).toContain('拒絕要填理由，申請人會看到這段說明。')
    expect(document.activeElement?.id).toBe('item-2-note')
    expect(w.get('[data-test="adjust-status"]').text()).toContain('有 1 個地方要修正')
  })

  it('收合的台以徽章標示已選的決定（縮短時間寫在徽章上）', async () => {
    const w = adjust()
    await radios(w, 0)[0].setValue(true)
    w.vm.forms[1].duration = 30
    await radios(w, 1)[1].setValue(true)
    const chip = w.get('[data-test="decision-chip"]').text()
    expect(chip).toBe('核准 · 縮短為 30 分鐘')
    expect(w.get('[data-test="submit-decisions"]').text()).toBe('送出決定（2 項）')
  })

  it('送出請求本文從不含 remove；核准帶下修值、拒絕走逐項拒絕', async () => {
    const w = adjust()
    await radios(w, 0)[0].setValue(true)
    w.vm.forms[1].accounts = ['ops']; w.vm.forms[1].duration = 30
    await radios(w, 1)[1].setValue(true)
    w.vm.forms[2].note = 'no access'
    await w.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    expect(api.approve).toHaveBeenCalledWith(23, { item_id: 1, accounts: ['ops'], duration_minutes: 30, note: '' }, { skipErrorToast: true })
    expect(api.reject).toHaveBeenCalledWith(23, 2, 'no access', { skipErrorToast: true })
    for (const [, body] of api.approve.mock.calls) expect(body).not.toHaveProperty('remove')
    const payload = w.emitted('decided')[0][0]
    expect(payload.results.map(r => r.kind)).toEqual(['approved', 'rejected'])
  })

  it('時長與帳號不可上調', async () => {
    const w = adjust()
    await radios(w, 0)[0].setValue(true)
    expect(w.getComponent({ name: 'ElInputNumber' }).props('max')).toBe(240)
    expect(w.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).toEqual(['ops', 'deploy'])
    w.vm.forms[1].duration = 241; await w.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
    w.vm.forms[1].duration = 30; w.vm.forms[1].accounts = ['root']; await w.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
    w.vm.forms[1].accounts = ['ops']; w.vm.forms[1].start = new Date('2098-01-01T00:00:00Z'); await w.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
  })

  it('全部帳號的項可收成具體清單，之後不能再改回全部帳號', async () => {
    const data = request(); data.items[0].accounts = ['@ALL']
    const w = adjust(data)
    await radios(w, 0)[0].setValue(true)
    await w.vm.narrowAll(data.items[0]); w.vm.forms[1].accounts = ['ops']; w.vm.scopeChanged(data.items[0]); await flushPromises()
    expect(w.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).not.toContain('@ALL')
  })

  it('部分失敗時逐項回報：成功與失敗的台分別可辨', async () => {
    const w = adjust()
    await radios(w, 0)[0].setValue(true)
    await radios(w, 1)[1].setValue(true)
    w.vm.forms[2].note = 'no'
    api.reject.mockRejectedValue({ response: { status: 403, data: { code: 'RULE_ACCESS_REQUEST_SELF_APPROVAL' } } })
    await w.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    const results = w.emitted('decided')[0][0].results
    expect(results.find(r => r.itemId === 1).kind).toBe('approved')
    expect(results.find(r => r.itemId === 2).kind).toBe('failed')
    expect(results.find(r => r.itemId === 2).text).not.toContain('RULE_ACCESS_REQUEST')
  })

  it('範圍外的項：後端明確拒絕後該台停用，其他台照常可決定', async () => {
    const w = adjust()
    await radios(w, 0)[0].setValue(true)
    api.approve.mockRejectedValue({ response: { status: 403, data: { code: 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER' } } })
    await w.vm.submit(); await flushPromises()
    expect(w.findAll('[data-test="decision-item"]')).toHaveLength(2)
    const groups = w.findAllComponents({ name: 'ElRadioGroup' })
    expect(groups[0].props('disabled')).toBe(true)
    expect(groups[1].props('disabled')).toBe(false)
  })

  it('已對其中一台投過核准票：說明核准只處理等你決定的台、拒絕會連同已核准的台一起拒絕', () => {
    const data = request()
    data.items = data.items.map((item) => ({ ...item, approvals_required: 2 }))
    data.items[0].approvals = [{ approver_id: 9, approver: { username: 'appr' } }]
    const w = open(data)
    expect(w.get('[data-test="scope-split"]').text()).toBe('核准只處理等你決定的 1 台；拒絕會一起拒絕還在待審的 2 台，包含你已核准的台')
    expect(w.find('[data-test="remaining-only"]').exists()).toBe(false)
    expect(w.find('[data-test="detail-approve"]').exists()).toBe(true)
    // 兩台都投過：沒有核准，拒絕的範圍照實寫
    data.items[1].approvals = [{ approver_id: 9 }]
    const all = open(data)
    expect(all.find('[data-test="detail-approve"]').exists()).toBe(false)
    expect(all.get('[data-test="nothing-left"]').text()).toContain('拒絕會一起拒絕還在待審的 2 台')
  })

  it('逐項核准遇到「已核准過」（409）：寫你已核准過這一台，不寫已不在待審', async () => {
    const data = request()
    api.approve.mockRejectedValue({ response: { status: 409, data: { code: 'CONFLICT_ACCESS_REQUEST_ALREADY_APPROVED' } } })
    const w = adjust(data)
    await radios(w, 0)[0].setValue(true)
    w.vm.forms[1].accounts = ['ops']
    w.vm.forms[1].options = ['ops', 'deploy']
    w.vm.forms[1].allAllowed = false
    await w.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    const [{ results }] = w.emitted('decided')[0]
    expect(results[0].kind).toBe('failed')
    expect(results[0].text).toBe('你已核准過這一台，這次沒有生效。')
  })

  it('已投過核准票的台：核准停用，仍可選拒絕', () => {
    const data = request(); data.items[0].approvals = [{ approver_id: 9 }]
    const w = adjust(data)
    const first = radios(w, 0)
    expect(first[0].element.disabled).toBe(true)
    expect(first[1].element.disabled).toBe(false)
  })

  it('單頭直接答出誰申請、替誰做', () => {
    const text = open().get('[data-test="review-header"]').text()
    expect(text).toContain('worker')
    expect(text).toMatch(/自主|autonom|自律/)
  })

  it.each(['zh-TW', 'en-US', 'ja-JP'])('三語：唯讀與調整模式沒有裸鍵 %s', async (locale) => {
    i18n.global.locale.value = locale
    try {
      expect(open().text()).not.toMatch(/itemReview\.|multiRequest\.|approvals\./)
      const w = adjust()
      await radios(w, 0)[0].setValue(true)
      expect(w.text()).not.toMatch(/itemReview\.|multiRequest\.|approvals\./)
      expect(w.findAllComponents({ name: 'ElDialog' })).toHaveLength(0)
    } finally {
      i18n.global.locale.value = 'zh-TW'
    }
  })
})

describe('多台的資產名稱取自待審回應', () => {
  it('第二台的名稱有值、資產讀取回 404：展開區與調整模式都顯示名稱，沒有另外查資產', async () => {
    const w = open()
    expect(w.findAll('[data-test="detail-item"]')[1].text()).toContain('db-host')
    const a = adjust()
    expect(a.findAll('[data-test="decision-item"]')[1].text()).toContain('db-host')
    await flushPromises()
    expect(api.asset).not.toHaveBeenCalled()
  })

  it('名稱為空時明說無法讀取並保留識別碼', () => {
    const data = request(); data.items[1].asset_name = ''
    expect(open(data).findAll('[data-test="detail-item"]')[1].text()).toContain('資產名稱無法讀取（資產 #2）')
  })
})

describe('在審核中心頁面裡', () => {
  it('展開後列上換成「在下方決定」，畫面上只有一組核准與拒絕', async () => {
    const w = mountView(); await flushPromises()
    expect(w.findAll('[data-test="row-approve"]')).toHaveLength(1)
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    expect(w.find('[data-test="row-approve"]').exists()).toBe(false)
    expect(w.find('[data-test="row-reject"]').exists()).toBe(false)
    expect(w.get('[data-test="ops-below"]').text()).toBe('在下方決定')
    expect(w.findAll('[data-test="detail-approve"]')).toHaveLength(1)
    expect(w.findAll('[data-test="detail-reject"]')).toHaveLength(1)
  })

  it('鍵盤：以 Enter 展開後唯讀，可再以鍵盤進入逐項調整', async () => {
    const w = mountView(); await flushPromises()
    await pressEnterOn(w.get('[data-test="toggle-items"]').element)
    const review = w.getComponent(Review)
    expect(review.attributes('data-mode')).toBe('read')
    await pressEnterOn(review.get('[data-test="enter-adjust"]').element)
    expect(w.getComponent(Review).attributes('data-mode')).toBe('adjust')
  })

  it('單資產逐項核准成功：重讀清單與計數、該列離開清單、頁籤數與計數一致、提示含申請人與資產名', async () => {
    const one = request(); one.items = [one.items[0]]; one.requester = { id: 5, username: 'chen.wei' }
    api.pending.mockResolvedValue({ data: [one] })
    const w = mountView(); await flushPromises()
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    await w.getComponent(Review).get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    const review = w.getComponent(Review)
    await review.findAll('input[type="radio"]')[0].setValue(true)
    review.vm.forms[1].accounts = ['ops']
    api.pending.mockClear(); api.count.mockClear()
    api.pending.mockResolvedValue({ data: [] })
    api.count.mockResolvedValue({ count: 0, review_count: 0 })
    const events = []
    const onChanged = () => events.push(1)
    window.addEventListener('ot-approvals-changed', onChanged)
    await review.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    window.removeEventListener('ot-approvals-changed', onChanged)
    expect(api.pending).toHaveBeenCalledTimes(1)
    expect(api.count).toHaveBeenCalled()
    expect(events).toHaveLength(1)
    expect(w.findAll('[data-test="toggle-items"]')).toHaveLength(0)
    expect(w.find('.el-tabs__header').text()).not.toContain('待審（')
    expect(w.get('[data-test="pending-loaded-of-total"]').text()).toContain('0')
    const toast = document.body.querySelector('.el-message')?.textContent || ''
    expect(toast).toContain('申請 #23 已處理完')
    expect(toast).toContain('app-host')
    expect(toast).toContain('看這張申請單')
    expect(document.body.textContent).not.toContain('此項決定已儲存')
  })

  it('逐項核准後仍在等其他審核人：列留著、核准不在、出現等待文字', async () => {
    const one = request(); one.items = [{ ...one.items[0], approvals_required: 2 }]
    api.pending.mockResolvedValue({ data: [one] })
    api.approve.mockResolvedValue({ items: [{ id: 1, status: 'pending', approvals_received: 1, approvals_required: 2 }] })
    const w = mountView(); await flushPromises()
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    await w.getComponent(Review).get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    const review = w.getComponent(Review)
    await review.findAll('input[type="radio"]')[0].setValue(true)
    review.vm.forms[1].accounts = ['ops']
    const voted = { ...one, items: [{ ...one.items[0], approvals: [{ approver_id: 9, approver: { username: 'appr' } }], approvals_received: 1, approvals_required: 2 }] }
    api.pending.mockResolvedValue({ data: [voted] })
    await review.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    // 收合後看列上的狀態
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    expect(w.find('[data-test="row-approve"]').exists()).toBe(false)
    expect(w.get('[data-test="row-waiting"]').text()).toBe('等其他 1 位審核人')
    // 已核准自己那一份後，仍可拒絕整張單
    expect(w.find('[data-test="row-reject"]').exists()).toBe(true)
    expect(document.body.querySelector('.el-message')?.textContent).toContain('已記下你的核准（1/2）')
  })

  it('全部台都已不在待審（409）：重讀、琥珀色提示不含任何使用者名稱、沒有可再按的送出鈕', async () => {
    const one = request(); one.items = [one.items[0]]; one.requester = { id: 5, username: 'chen.wei' }
    api.pending.mockResolvedValue({ data: [one] })
    api.approve.mockRejectedValue({ response: { status: 409, data: { code: 'CONFLICT_ACCESS_REQUEST_STATE' } } })
    const w = mountView(); await flushPromises()
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    await w.getComponent(Review).get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    const review = w.getComponent(Review)
    await review.findAll('input[type="radio"]')[0].setValue(true)
    review.vm.forms[1].accounts = ['ops']
    api.pending.mockClear()
    api.pending.mockResolvedValue({ data: [] })
    await review.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    expect(api.pending).toHaveBeenCalledTimes(1)
    expect(w.find('[data-test="submit-decisions"]').exists()).toBe(false)
    const node = document.body.querySelector('.el-message')
    expect(node.className).toContain('warning')
    expect(node.textContent).toContain('申請 #23 已不在待審，你的決定沒有生效')
    expect(node.textContent).toContain('可能已被核准、被撤回、逾期')
    expect(node.textContent).not.toContain('chen.wei')
    expect(node.textContent).not.toContain('appr')
  })

  it('兩台之中一台 409：另一台結果照常、那一台寫沒有生效，仍在待審的單沒有可再選的決定控件', async () => {
    const data = request()
    data.items[1].approvals_required = 2
    api.approve.mockResolvedValue({ items: [{ id: 1, status: 'approved' }] })
    api.reject.mockRejectedValue({ response: { status: 409, data: { code: 'CONFLICT_ACCESS_REQUEST_STATE' } } })
    api.pending.mockResolvedValue({ data: [data] })
    const w = mountView(); await flushPromises()
    await w.get('[data-test="toggle-items"]').trigger('click'); await flushPromises()
    await w.getComponent(Review).get('[data-test="enter-adjust"]').trigger('click'); await flushPromises()
    const review = w.getComponent(Review)
    await review.findAll('[data-test="decision-item"]')[0].findAll('input[type="radio"]')[0].setValue(true)
    review.vm.forms[1].accounts = ['ops']
    await review.findAll('[data-test="decision-item"]')[1].findAll('input[type="radio"]')[1].setValue(true)
    review.vm.forms[2].note = 'freeze'
    // 重讀後：第一台已核准、第二台已由別人處理但整張仍待審（還有第三台）
    const after = request()
    after.items = [
      { ...after.items[0], status: 'approved' },
      { ...after.items[1], status: 'rejected' },
      { id: 3, asset_id: 3, asset_name: 'cache-host', accounts: [], status: 'pending' },
    ]
    api.pending.mockResolvedValue({ data: [after] })
    await review.get('[data-test="submit-decisions"]').trigger('click'); await flushPromises()
    const results = w.findAll('[data-test="decision-result"]').map(n => n.text())
    expect(results.some(text => text.includes('已核准'))).toBe(true)
    expect(results.some(text => text.includes('你選的「拒絕」沒有生效'))).toBe(true)
    const rows = w.findAll('[data-test="detail-item"]')
    expect(rows).toHaveLength(3)
    expect(w.findAll('input[type="radio"]')).toHaveLength(0)
  })

  it('agent 申請單標示主體類型與負責人', async () => {
    const w = mountView(); await flushPromises()
    expect(w.getComponent(PrincipalBadge).text()).toContain('AI agent')
    expect(w.getComponent(PrincipalBadge).text()).toContain('負責人：未提供')
  })

  it('執行者投影與 decision_bounds 由真欄位呈現', async () => {
    const data = request(); data.requester.kind = 'human'; data.executor_user_id = 10; data.executor = { id: 10, username: 'executor', kind: 'agent', owner_user_id: 4, owner_username: 'responsible' }
    data.items[0].decision_bounds = { max_duration: 30, earliest_start: '2099-02-01T00:00:00Z', accounts: ['ops'] }
    api.pending.mockResolvedValue({ data: [data] }); const w = mountView(); await flushPromises()
    expect(w.get('[data-test="executor-principal"]').text()).toContain('responsible')
    const review = adjust(data); await radios(review, 0)[0].setValue(true)
    expect(review.getComponent({ name: 'ElInputNumber' }).props('max')).toBe(30)
    expect(review.findAllComponents({ name: 'ElOption' }).map(o => o.props('value'))).toEqual(['ops'])
    review.vm.forms[1].start = new Date('2099-01-02T00:00:00Z'); await review.vm.submit(); expect(api.approve).not.toHaveBeenCalled()
  })

  it('待審申請人就是執行者時合併同一組主體，姓名只顯示一次', async () => {
    const data = request()
    data.executor_user_id = data.requester_id
    data.executor = { ...data.requester, owner_username: 'admin' }
    api.pending.mockResolvedValue({ data: [data] })
    const w = mountView(); await flushPromises()
    const table = w.get('[data-test="pending-table"]')
    expect(table.findAll('.principal-badge')).toHaveLength(1)
    expect(table.text().split('負責人：admin')).toHaveLength(2)
    expect(table.find('[data-test="executor-principal"]').exists()).toBe(false)
  })
})

describe('自主執行的 agent 不被寫成代表其 owner', () => {
  it('無 on_behalf_of 時顯示自主執行並附負責人', () => {
    const w = open({ ...request(), requester: { id: 5, username: 'worker', kind: 'agent', owner_user_id: 2, owner_username: 'owner-a' } })
    const line = w.get('[data-test="review-representation"]').text()
    expect(line).toContain('自主執行')
    expect(line).toContain('owner-a')
    expect(line).not.toContain('代表：')
  })
  it('有 on_behalf_of 時才寫代表', () => {
    const w = open({ ...request(), on_behalf_of_username: 'human-b' })
    expect(w.get('[data-test="review-representation"]').text()).toBe('代表：human-b')
  })
})
