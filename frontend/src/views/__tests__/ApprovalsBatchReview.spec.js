import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage } from 'element-plus'
import Approvals from '../Approvals.vue'

// 審核中心的整張核決：列上的單張確認框與勾選多張的批次，前端逐張呼叫既有單張端點
enableAutoUnmount(afterEach)
afterEach(() => { ElMessage.closeAll(); document.body.querySelectorAll('.el-message').forEach(n => n.remove()) })

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const getPendingMock = vi.fn()
const getHistoryMock = vi.fn()
const approveMock = vi.fn()
const rejectMock = vi.fn()
const reviewMock = vi.fn()
const getReviewsMock = vi.fn()
const getCountMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequests: (...a) => getPendingMock(...a),
  getAccessRequestHistory: (...a) => getHistoryMock(...a),
  getActiveTickets: vi.fn().mockResolvedValue({ data: [] }),
  approveAccessRequest: (...a) => approveMock(...a),
  rejectAccessRequest: (...a) => rejectMock(...a),
  revokeAccessRequest: vi.fn(),
  reviewBreakGlass: (...a) => reviewMock(...a),
  getPendingReviews: (...a) => getReviewsMock(...a),
  getPendingAccessRequestCount: (...a) => getCountMock(...a),
  rejectAccessRequestItem: vi.fn(),
}))

vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))

const ME = 67
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

const item = (id, extra = {}) => ({
  id,
  asset_id: 20 + id,
  asset_name: `asset-${id}`,
  accounts: ['ops'],
  status: 'pending',
  approvals: [],
  ...extra,
})

const request107 = {
  id: 107,
  requester_id: 64,
  requester: { username: 'alice' },
  asset_id: 21,
  asset: { name: 'asset-1' },
  reason: '每日例行巡檢',
  requested_duration_minutes: 60,
  created_at: '2026-09-29T01:13:00Z',
  items: [item(1)],
}
const request108 = {
  id: 108,
  requester_id: 65,
  requester: { username: 'bob' },
  asset_id: 22,
  asset: { name: 'asset-2' },
  reason: '部署修補',
  requested_duration_minutes: 120,
  created_at: '2026-09-29T01:13:00Z',
  items: [item(2, { accounts: ['deploy'] }), item(3, { status: 'approved', accounts: ['deploy'] })],
}
const request111 = {
  id: 111,
  requester_id: 66,
  requester: { username: 'carol' },
  asset_id: 30,
  asset: { name: 'legacy-01' },
  reason: '舊式單',
  requested_duration_minutes: 30,
  created_at: '2026-09-29T01:13:00Z',
}
// 兩台、需要兩位審核人、還沒有人核准
const request120 = {
  id: 120,
  requester_id: 70,
  requester: { username: 'dave' },
  reason: '兩台',
  requested_duration_minutes: 30,
  created_at: '2026-09-29T01:13:00Z',
  items: [item(5, { approvals_required: 2 }), item(6, { approvals_required: 2, accounts: ['app', 'deploy'] })],
}

// 兩台、需要兩位審核人；這位審核人已對第一台投過核准票，第二台還等他決定
const request130 = {
  id: 130,
  requester_id: 71,
  requester: { username: 'erin' },
  reason: '兩台已投一台',
  requested_duration_minutes: 60,
  created_at: '2026-09-29T01:13:00Z',
  items: [
    item(7, { approvals_required: 2, approvals: [{ approver_id: ME, approver: { username: 'a4-batch-approver' } }] }),
    item(8, { approvals_required: 2 }),
  ],
}

const httpError = (status, code) => ({ response: { status, data: { code, error: code } } })

const mountView = () => mount(Approvals, { global: { plugins: [ElementPlus] }, attachTo: document.body })
const pendingCell = (w, id) => w.find(`[data-test="pending-select-cell"][data-id="${id}"] input`)
const pendingDialog = (w) => w.find('[data-test="pending-batch-dialog"]')
const singleDialog = (w) => w.find('[data-test="single-decision-dialog"]')
const reviewsDialog = (w) => w.find('[data-test="reviews-batch-dialog"]')
const rowButton = (w, kind, id) => w.find(`[data-test="row-${kind}"][data-id="${id}"]`)
// 照瀏覽器的鍵盤行為：對目前焦點所在派送 Enter；沒有被處理且焦點是按鈕時，瀏覽器會按下該按鈕
async function pressEnter() {
  const el = document.activeElement
  const event = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })
  el.dispatchEvent(event)
  if (!event.defaultPrevented && el.tagName === 'BUTTON') el.click()
  await flushPromises()
}

beforeEach(() => {
  vi.clearAllMocks()
  // mockImplementationOnce 佇列不隨 clearAllMocks 清掉：逐一 reset，避免前一測殘留
  for (const m of [getPendingMock, getHistoryMock, approveMock, rejectMock, reviewMock, getReviewsMock, getCountMock]) m.mockReset()
  localStorage.clear()
  sessionStorage.clear()
  localStorage.setItem('user', JSON.stringify({ id: ME, username: 'a4-batch-approver', roles: ['user', 'approver'] }))
  getPendingMock.mockResolvedValue({ data: [request107, request108, request111] })
  getHistoryMock.mockResolvedValue({ data: [], total: 0 })
  getReviewsMock.mockResolvedValue({ data: [] })
  getCountMock.mockResolvedValue({ count: 3, review_count: 0 })
})

describe('列上的整張核准與拒絕（單張確認框）', () => {
  it('單資產：按列上核准、確認，送出一個 approve，本文只有該項、沒有時長與帳號、不帶批次關聯碼', async () => {
    approveMock.mockResolvedValue({ ...request107, status: 'approved', items: [item(1, { status: 'approved' })] })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    const text = singleDialog(w).text()
    expect(text).toContain('核准申請 #107')
    expect(text).toContain('asset-1')
    expect(text).toContain('ops')
    expect(text).toContain('1 小時')
    expect(text).toContain('核准後，alice 可以在 1 小時內連線這台資產')
    getPendingMock.mockResolvedValue({ data: [request108, request111] })
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(approveMock).toHaveBeenCalledTimes(1)
    expect(approveMock.mock.calls[0]).toEqual([107, { items: [{ item_id: 1 }] }, { skipErrorToast: true }])
    // 照申請值：不帶任何下修欄位
    const body = approveMock.mock.calls[0][1]
    for (const key of ['duration_minutes', 'accounts', 'date_start', 'batch_id', 'remove']) expect(body).not.toHaveProperty(key)
    // 單資產兩次操作：列上核准、確認；之後清單重讀、該列離開、提示寫明申請人可以連線
    expect(w.find('[data-test="row-approve"][data-id="107"]').exists()).toBe(false)
    const toast = document.body.querySelector('.el-message')?.textContent || ''
    expect(toast).toContain('已核准申請 #107')
    expect(toast).toContain('alice 現在可以連線 asset-1')
  })

  it('兩台申請：確認框逐項列出兩台的帳號與時長，送出的 items 明列兩項', async () => {
    getPendingMock.mockResolvedValue({ data: [request120] })
    approveMock.mockResolvedValue({ ...request120, status: 'pending', items: [item(5, { approvals_received: 1, approvals_required: 2 }), item(6, { approvals_received: 1, approvals_required: 2 })] })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 120).trigger('click')
    await flushPromises()
    const lines = singleDialog(w).findAll('[data-test="single-items"] li').map((li) => li.text())
    expect(lines).toHaveLength(2)
    expect(lines[0]).toContain('asset-5')
    expect(lines[1]).toContain('asset-6')
    expect(lines[1]).toContain('app、deploy')
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(approveMock.mock.calls[0][1]).toEqual({ items: [{ item_id: 5 }, { item_id: 6 }] })
  })

  it('需要兩位審核人：確認框寫「你核准後還要 1 位」，確認後提示已記下（1/2），列留在清單且列上不再提供核准', async () => {
    const one = { ...request120, items: [request120.items[0]] }
    getPendingMock.mockResolvedValue({ data: [one] })
    approveMock.mockResolvedValue({ ...one, status: 'pending', items: [item(5, { approvals_received: 1, approvals_required: 2 })] })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 120).trigger('click')
    await flushPromises()
    expect(singleDialog(w).get('[data-test="single-threshold"]').text()).toContain('你核准後還要 1 位')
    const voted = { ...one, items: [item(5, { approvals_required: 2, approvals_received: 1, approvals: [{ approver_id: ME, approver: { username: 'me' } }] })] }
    getPendingMock.mockResolvedValue({ data: [voted] })
    getCountMock.mockResolvedValue({ count: 1, review_count: 0 })
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('.el-message')?.textContent).toContain('已記下你的核准（1/2）')
    expect(rowButton(w, 'approve', 120).exists()).toBe(false)
    expect(w.get('[data-test="row-waiting"]').text()).toBe('等其他 1 位審核人')
    expect(w.get('[data-test="you-approved"]').text()).toBe('你已核准')
    expect(w.find('.el-tabs__header').text()).toContain('待審（1）')
    expect(w.findAll('[data-test="toggle-items"]')).toHaveLength(1)
  })

  it('拒絕沒填理由：沒有任何請求並標示理由欄；填寫後送出一個 reject 帶 note', async () => {
    rejectMock.mockResolvedValue({ status: 'rejected' })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'reject', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(rejectMock).not.toHaveBeenCalled()
    expect(singleDialog(w).text()).toContain('請填寫拒絕理由，申請人會看到這段說明。')
    expect(singleDialog(w).find('.el-form-item.is-error').exists()).toBe(true)
    await singleDialog(w).find('[data-test="batch-note"] textarea').setValue('不在維護時段')
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(rejectMock).toHaveBeenCalledTimes(1)
    expect(rejectMock.mock.calls[0]).toEqual([107, '不在維護時段', { skipErrorToast: true }])
    expect(document.body.querySelector('.el-message')?.textContent).toContain('已拒絕申請 #107')
  })

  it('範圍外：框內說明整張沒有核准，列仍在，沒有任何一項被呈現為已核准', async () => {
    approveMock.mockRejectedValue(httpError(403, 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const result = singleDialog(w).get('[data-test="single-result"]').text()
    expect(result).toContain('整張沒有核准')
    expect(result).not.toContain('RULE_')
    expect(rowButton(w, 'approve', 107).exists()).toBe(true)
    expect(document.body.querySelector('.el-message')).toBeNull()
  })

  it('連線權限：框內說明並提供「拒絕這張申請」，按下後換成拒絕確認', async () => {
    approveMock.mockRejectedValue(httpError(403, 'RULE_ACCESS_REQUEST_CONNECT_REQUIRED'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(singleDialog(w).text()).toContain('申請人目前沒有這台資產的連線權限')
    await singleDialog(w).get('[data-test="single-reject-instead"]').trigger('click')
    await flushPromises()
    expect(singleDialog(w).text()).toContain('拒絕申請 #107')
    expect(singleDialog(w).find('[data-test="batch-note"]').exists()).toBe(true)
  })

  it('沒有收到回應：框內說明可能已生效並提供重新查詢，查詢前沒有可直接重送的按鈕', async () => {
    approveMock.mockRejectedValue(new Error('timeout'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(singleDialog(w).text()).toContain('這個核准可能已經生效')
    expect(singleDialog(w).find('[data-test="batch-recheck"]').exists()).toBe(true)
    expect(singleDialog(w).find('[data-test="batch-submit"]').exists()).toBe(false)
    expect(approveMock).toHaveBeenCalledTimes(1)
  })

  it('確認時已不在待審（409）：關框、重讀、琥珀色提示說沒有生效，不寫誰處理', async () => {
    approveMock.mockRejectedValue(httpError(409, 'CONFLICT_ACCESS_REQUEST_STATE'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    getPendingMock.mockClear()
    getPendingMock.mockResolvedValue({ data: [request108, request111] })
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(getPendingMock).toHaveBeenCalled()
    expect(singleDialog(w).exists() && singleDialog(w).isVisible()).toBe(false)
    const node = document.body.querySelector('.el-message')
    expect(node.className).toContain('warning')
    expect(node.textContent).toContain('申請 #107 已不在待審，你的決定沒有生效')
    expect(rowButton(w, 'approve', 107).exists()).toBe(false)
  })

  it('鍵盤：列上核准可聚焦、Enter 開確認框，焦點落在主要按鈕，再按 Enter 送出一次核准', async () => {
    approveMock.mockResolvedValue({ ...request107, status: 'approved', items: [item(1, { status: 'approved' })] })
    const w = mountView()
    await flushPromises()
    const button = rowButton(w, 'approve', 107)
    expect(button.attributes('disabled')).toBeUndefined()
    expect(button.attributes('tabindex')).not.toBe('-1')
    button.element.focus()
    await pressEnter()
    expect(singleDialog(w).text()).toContain('核准申請 #107')
    // 開框後的焦點就是送出鈕：Enter 經由焦點路徑送出，不需要再 Tab
    expect(document.activeElement).toBe(singleDialog(w).get('[data-test="batch-submit"]').element)
    await pressEnter()
    expect(approveMock).toHaveBeenCalledTimes(1)
    expect(approveMock.mock.calls[0][1]).toEqual({ items: [{ item_id: 1 }] })
  })

  it('鍵盤：焦點被移到對話框本身時按 Enter 也送出核准', async () => {
    approveMock.mockResolvedValue({ ...request107, status: 'approved', items: [item(1, { status: 'approved' })] })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    const dialogEl = document.body.querySelector('.el-dialog[data-test="single-decision-dialog"]') || singleDialog(w).element
    dialogEl.setAttribute('tabindex', '-1')
    dialogEl.focus()
    expect(document.activeElement).toBe(dialogEl)
    await pressEnter()
    expect(approveMock).toHaveBeenCalledTimes(1)
  })

  it('鍵盤：拒絕確認框開啟後焦點在理由欄', async () => {
    const w = mountView()
    await flushPromises()
    rowButton(w, 'reject', 107).element.focus()
    await pressEnter()
    expect(singleDialog(w).text()).toContain('拒絕申請 #107')
    expect(document.activeElement).toBe(singleDialog(w).get('[data-test="batch-note"] textarea').element)
    // 理由欄裡的 Enter 是換行，不送出
    await pressEnter()
    expect(rejectMock).not.toHaveBeenCalled()
  })

  it('改用逐項調整：關閉確認框、展開該列並直接進入調整模式，沒有任何請求', async () => {
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).get('[data-test="single-adjust"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="item-review"][data-mode="adjust"]').exists()).toBe(true)
    expect(approveMock).not.toHaveBeenCalled()
  })
})

describe('已對部分項目投過票的多項申請（門檻兩人以上）', () => {
  it('整張核准只列、只送還等你決定的那一台；門檻句不把自己算成已核准的人', async () => {
    getPendingMock.mockResolvedValue({ data: [request130] })
    approveMock.mockResolvedValue({ ...request130, status: 'pending', items: [item(7, { approvals_received: 1, approvals_required: 2 }), item(8, { approvals_received: 1, approvals_required: 2 })] })
    const w = mountView()
    await flushPromises()
    expect(rowButton(w, 'approve', 130).exists()).toBe(true)
    await rowButton(w, 'approve', 130).trigger('click')
    await flushPromises()
    const lines = singleDialog(w).findAll('[data-test="single-items"] li').map((li) => li.text())
    expect(lines).toHaveLength(1)
    expect(lines[0]).toContain('asset-8')
    const threshold = singleDialog(w).get('[data-test="single-threshold"]').text()
    expect(threshold).not.toContain('a4-batch-approver')
    expect(threshold).toContain('目前還沒有人核准。你核准後還要 1 位')
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(approveMock).toHaveBeenCalledTimes(1)
    expect(approveMock.mock.calls[0][1]).toEqual({ items: [{ item_id: 8 }] })
  })

  it('另一位已核准兩台、自己已核准其中一台：門檻句只寫另一位，核准後湊齊', async () => {
    const other = { approver_id: 500, approver: { username: 'wang.jie' } }
    const req = {
      ...request130,
      items: [
        item(7, { approvals_required: 2, approvals: [{ approver_id: ME, approver: { username: 'a4-batch-approver' } }, other] }),
        item(8, { approvals_required: 2, approvals: [other] }),
      ],
    }
    getPendingMock.mockResolvedValue({ data: [req] })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 130).trigger('click')
    await flushPromises()
    const threshold = singleDialog(w).get('[data-test="single-threshold"]').text()
    expect(threshold).toContain('wang.jie 已核准。你核准後就湊齊')
    expect(threshold).not.toContain('a4-batch-approver')
  })

  it('整張拒絕照實列出所有待審的台，並說明已核准過的那一台也會一起拒絕', async () => {
    getPendingMock.mockResolvedValue({ data: [request130] })
    rejectMock.mockResolvedValue({ status: 'rejected' })
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'reject', 130).trigger('click')
    await flushPromises()
    const lines = singleDialog(w).findAll('[data-test="single-items"] li').map((li) => li.text())
    expect(lines).toHaveLength(2)
    expect(singleDialog(w).get('[data-test="single-reject-includes-voted"]').text()).toBe('其中 1 台你已核准、還在等其他審核人；拒絕後這幾台也一起拒絕。')
    await singleDialog(w).find('[data-test="batch-note"] textarea').setValue('改期')
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(rejectMock.mock.calls[0]).toEqual([130, '改期', { skipErrorToast: true }])
  })

  it('後端回「已核准過」（409）：提示寫你已核准過，不寫已不在待審；單仍在清單', async () => {
    getPendingMock.mockResolvedValue({ data: [request130] })
    approveMock.mockRejectedValue(httpError(409, 'CONFLICT_ACCESS_REQUEST_ALREADY_APPROVED'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 130).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const toast = document.body.querySelector('.el-message')?.textContent || ''
    expect(toast).toContain('申請 #130 有你已核准過的台，這次沒有生效')
    expect(toast).not.toContain('已不在待審')
    expect(w.find('[data-test="toggle-items"][data-id="130"]').exists()).toBe(true)
  })

  it('409（狀態已變）但重讀後仍在待審：寫狀態有變動，不寫已不在待審', async () => {
    approveMock.mockRejectedValue(httpError(409, 'CONFLICT_ACCESS_REQUEST_STATE'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const toast = document.body.querySelector('.el-message')?.textContent || ''
    expect(toast).toContain('申請 #107 的狀態有變動，你的決定沒有生效')
    expect(toast).not.toContain('已不在待審')
  })

  it('批次核准對已投一台的單只送還等你決定的那一台', async () => {
    getPendingMock.mockResolvedValue({ data: [request107, request130] })
    approveMock.mockResolvedValue({ status: 'approved', items: [] })
    const w = mountView()
    await flushPromises()
    await w.find('[data-test="pending-select-all"] input').setValue(true)
    await flushPromises()
    await w.find('[data-test="batch-approve-open"]').trigger('click')
    await flushPromises()
    const sheet = pendingDialog(w).find('[data-test="batch-sheet"][data-id="130"]').text()
    expect(sheet).toContain('asset-8')
    expect(sheet).not.toContain('asset-7')
    await pendingDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const call = approveMock.mock.calls.find((c) => c[0] === 130)
    expect(call[1].items).toEqual([{ item_id: 8 }])
  })
})

describe('沒有收到回應之後', () => {
  it('「可能已生效」框按關閉：重新查詢並重讀清單；查回沒有送達，提示可以再決定一次', async () => {
    approveMock.mockRejectedValue(new Error('timeout'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    getPendingMock.mockClear()
    await singleDialog(w).get('[data-test="single-close"]').trigger('click')
    await flushPromises()
    expect(getPendingMock.mock.calls.length).toBeGreaterThanOrEqual(2)
    expect(singleDialog(w).exists() && singleDialog(w).isVisible()).toBe(false)
    expect(document.body.querySelector('.el-message')?.textContent).toContain('申請 #107 沒有收到你的決定')
    expect(approveMock).toHaveBeenCalledTimes(1)
  })

  it('「可能已生效」框按右上角關閉、查詢也失敗：列上標「結果待確認」，不提供可照常再按的核准', async () => {
    approveMock.mockRejectedValue(new Error('timeout'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    getPendingMock.mockRejectedValue(new Error('network'))
    await singleDialog(w).get('.el-dialog__headerbtn').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="row-unconfirmed"]').text()).toContain('結果待確認')
    expect(rowButton(w, 'approve', 107).exists()).toBe(false)
    expect(document.body.querySelector('.el-message')?.textContent).toContain('申請 #107 的結果還無法確認')
    // 之後讀得到清單：標示清掉，清單本身就是事實
    getPendingMock.mockResolvedValue({ data: [request107, request108, request111] })
    await w.get('[data-test="row-recheck"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="row-unconfirmed"]').exists()).toBe(false)
  })

  it('重新查詢查回沒有送達：回到確認框並說明可以再送一次', async () => {
    approveMock.mockRejectedValueOnce(new Error('timeout'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 107).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    await singleDialog(w).get('[data-test="batch-recheck"]').trigger('click')
    await flushPromises()
    expect(singleDialog(w).get('[data-test="single-not-delivered"]').text()).toContain('上一次的決定沒有送達')
    expect(singleDialog(w).find('[data-test="batch-submit"]').exists()).toBe(true)
  })

  // 兩台：第一台先前已由本人核准，第二台這一次送出核准但請求沒有抵達，之後由另一位審核人拒絕
  const request140 = {
    id: 140,
    requester_id: 72,
    requester: { username: 'frank' },
    reason: '兩台一台已核准',
    requested_duration_minutes: 60,
    created_at: '2026-09-29T01:13:00Z',
    items: [item(11, { status: 'approved', decided_by: ME }), item(12)],
  }

  it('單張核准沒有回應、查回時送出的項目已被別人拒絕：不因同單另一項先前由本人核准而顯示成已核准', async () => {
    getPendingMock.mockResolvedValue({ data: [request140] })
    approveMock.mockRejectedValue(new Error('timeout'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 140).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(approveMock.mock.calls[0][1]).toEqual({ items: [{ item_id: 12 }] })
    getPendingMock.mockResolvedValue({ data: [] })
    getHistoryMock.mockResolvedValue({
      data: [{
        ...request140,
        status: 'rejected',
        approver_id: 99,
        approvals: [{ approver_id: ME, item_id: 11 }],
        items: [item(11, { status: 'approved', decided_by: ME }), item(12, { status: 'rejected', decided_by: 99 })],
      }],
      total: 1,
    })
    await singleDialog(w).get('[data-test="batch-recheck"]').trigger('click')
    await flushPromises()
    const toast = document.body.querySelector('.el-message')?.textContent || ''
    expect(toast).not.toContain('已核准申請 #140')
    expect(toast).toContain('申請 #140 已不在待審，你的決定沒有生效')
  })

  it('單張核准沒有回應、查回時送出的項目確實由本人核准：顯示已核准', async () => {
    getPendingMock.mockResolvedValue({ data: [request140] })
    approveMock.mockRejectedValue(new Error('timeout'))
    const w = mountView()
    await flushPromises()
    await rowButton(w, 'approve', 140).trigger('click')
    await flushPromises()
    await singleDialog(w).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    getPendingMock.mockResolvedValue({ data: [] })
    getHistoryMock.mockResolvedValue({
      data: [{
        ...request140,
        status: 'approved',
        approver_id: ME,
        items: [item(11, { status: 'approved', decided_by: ME }), item(12, { status: 'approved', decided_by: ME })],
      }],
      total: 1,
    })
    await singleDialog(w).get('[data-test="batch-recheck"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('.el-message')?.textContent).toContain('已核准申請 #140')
  })

  it('待確認的核准查回：只以這一次送出的項目與本人的票判定，資料不足時維持待確認', async () => {
    sessionStorage.setItem('ot-batch-review:approvals-pending', JSON.stringify({
      v: 1,
      batchId: '1c9f5d1f-3a2b-4c8d-8e4f-6a7b8c9d0e1f',
      kind: 'approve',
      userId: ME,
      params: {},
      items: [
        { id: 201, label: '申請 #201', state: 'inflight', message: '', meta: { itemIds: [22], hasItems: true } },
        { id: 202, label: '申請 #202', state: 'inflight', message: '', meta: { itemIds: [32], hasItems: true } },
        { id: 203, label: '申請 #203', state: 'inflight', message: '', meta: { itemIds: [42], hasItems: true } },
        { id: 204, label: '申請 #204', state: 'inflight', message: '', meta: { itemIds: [52], hasItems: true } },
        { id: 205, label: '申請 #205', state: 'inflight', message: '', meta: { itemIds: [62], hasItems: true } },
      ],
    }))
    getPendingMock.mockResolvedValue({
      data: [
        // 仍在待審、需兩位：這一次送出的項目已有本人的票，尚未達門檻
        { id: 205, requester_id: 75, requester: { username: 'ivan' }, reason: 'x', requested_duration_minutes: 30, created_at: '2026-09-29T01:13:00Z',
          items: [item(61, { approvals_required: 2 }), item(62, { approvals_required: 2, approvals: [{ approver_id: ME }] })] },
      ],
    })
    getHistoryMock.mockResolvedValue({
      data: [
        // 另一項先前由本人核准，這一次送出的項目被別人拒絕
        { id: 201, status: 'rejected', approver_id: 99, approvals: [{ approver_id: ME, item_id: 21 }],
          items: [item(21, { status: 'approved', decided_by: ME }), item(22, { status: 'rejected', decided_by: 99 })] },
        // 這一次送出的項目由本人核准
        { id: 202, status: 'approved', approver_id: ME, items: [item(32, { status: 'approved', decided_by: ME })] },
        // 需兩位：本人的票已記入，另一位補齊門檻
        { id: 203, status: 'approved', approver_id: 99, approvals: [{ approver_id: ME, item_id: 42 }, { approver_id: 99, item_id: 42 }],
          items: [item(42, { status: 'approved', decided_by: 99 })] },
        // 需兩位：本人的票已記入但未達門檻，之後逾期結束
        { id: 204, status: 'expired', approvals: [{ approver_id: ME, item_id: 52 }], items: [item(52, { status: 'revoked' })] },
      ],
      total: 4,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(approveMock).not.toHaveBeenCalled()
    const row = (id) => pendingDialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`)
    expect(row(201).attributes('data-state')).toBe('rejected')
    expect(row(201).text()).toContain('未生效：這張已不在待審')
    expect(row(202).attributes('data-state')).toBe('success')
    expect(row(202).text()).toContain('已核准')
    expect(row(203).attributes('data-state')).toBe('success')
    expect(row(204).attributes('data-state')).toBe('unconfirmed')
    expect(row(204).text()).toContain('歷史')
    expect(row(205).attributes('data-state')).toBe('success')
    expect(row(205).text()).toContain('已記下你的核准')
  })

  it('批次拒絕沒有回應、查回時送出的項目已由別人核准：不因同單另一項先前由本人拒絕而顯示成已拒絕', async () => {
    const request150 = {
      id: 150,
      requester_id: 73,
      requester: { username: 'grace' },
      reason: '兩台一台已拒絕',
      requested_duration_minutes: 60,
      created_at: '2026-09-29T01:13:00Z',
      items: [item(15, { status: 'rejected', decided_by: ME }), item(16)],
    }
    getPendingMock.mockResolvedValue({ data: [request150] })
    rejectMock.mockRejectedValue(new Error('timeout'))
    const wrapper = mountView()
    await flushPromises()
    await pendingCell(wrapper, 150).setValue(true)
    await flushPromises()
    await wrapper.find('[data-test="batch-reject-open"]').trigger('click')
    await flushPromises()
    await pendingDialog(wrapper).find('[data-test="batch-note"] textarea').setValue('本週凍結變更')
    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const row = () => pendingDialog(wrapper).find('[data-test="batch-item"][data-id="150"]')
    expect(row().attributes('data-state')).toBe('unconfirmed')
    getPendingMock.mockResolvedValue({ data: [] })
    getHistoryMock.mockResolvedValue({
      data: [{
        ...request150,
        status: 'approved',
        approver_id: 99,
        items: [item(15, { status: 'rejected', decided_by: ME }), item(16, { status: 'approved', decided_by: 99 })],
      }],
      total: 1,
    })
    await pendingDialog(wrapper).get('[data-test="batch-recheck"]').trigger('click')
    await flushPromises()
    expect(row().attributes('data-state')).toBe('rejected')
    expect(row().text()).toContain('未生效：這張已不在待審')
  })

  it('批次拒絕沒有回應、查回時送出的項目都由本人拒絕：顯示已拒絕', async () => {
    const request150 = {
      id: 150,
      requester_id: 73,
      requester: { username: 'grace' },
      reason: '兩台一台已核准',
      requested_duration_minutes: 60,
      created_at: '2026-09-29T01:13:00Z',
      items: [item(15, { status: 'approved', decided_by: 99 }), item(16)],
    }
    getPendingMock.mockResolvedValue({ data: [request150] })
    rejectMock.mockRejectedValue(new Error('timeout'))
    const wrapper = mountView()
    await flushPromises()
    await pendingCell(wrapper, 150).setValue(true)
    await flushPromises()
    await wrapper.find('[data-test="batch-reject-open"]').trigger('click')
    await flushPromises()
    await pendingDialog(wrapper).find('[data-test="batch-note"] textarea').setValue('本週凍結變更')
    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    getPendingMock.mockResolvedValue({ data: [] })
    getHistoryMock.mockResolvedValue({
      data: [{
        ...request150,
        status: 'approved',
        approver_id: 99,
        items: [item(15, { status: 'approved', decided_by: 99 }), item(16, { status: 'rejected', decided_by: ME })],
      }],
      total: 1,
    })
    await pendingDialog(wrapper).get('[data-test="batch-recheck"]').trigger('click')
    await flushPromises()
    const row = pendingDialog(wrapper).find('[data-test="batch-item"][data-id="150"]')
    expect(row.attributes('data-state')).toBe('success')
    expect(row.text()).toContain('已拒絕，已通知 grace')
  })
})

describe('Approvals 批次處理', () => {
  it('批次核准：逐張列出申請內容，body 只帶所有 pending 項目與 batch_id，不帶時長或帳號修改', async () => {
    approveMock
      .mockResolvedValueOnce({ ...request107, status: 'approved', items: [item(1, { status: 'approved' })] })
      .mockResolvedValueOnce({
        ...request108,
        status: 'pending',
        items: [
          item(2, { accounts: ['deploy'], approvals_received: 1, approvals_required: 2 }),
          item(3, { status: 'approved' }),
        ],
      })
      .mockRejectedValueOnce(httpError(403, 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER'))
    const wrapper = mountView()
    await flushPromises()

    await wrapper.find('[data-test="pending-select-all"] input').setValue(true)
    await flushPromises()
    const bar = wrapper.find('[data-test="pending-batch-bar"]').text()
    expect(bar).toContain('已選 3 張申請')
    expect(bar).toContain('各張照申請內容')
    expect(bar).toContain('核准所選（3 張）')
    await wrapper.find('[data-test="batch-approve-open"]').trigger('click')
    await flushPromises()

    const confirmText = pendingDialog(wrapper).text()
    expect(confirmText).toContain('申請 #107')
    expect(confirmText).toContain('alice')
    expect(confirmText).toContain('asset-1')
    expect(confirmText).toContain('ops')
    expect(confirmText).toContain('1 小時')
    expect(confirmText).toContain('一律照申請內容核准')
    // 已決定的項目不在這次核准範圍內
    expect(confirmText).not.toContain('asset-3')

    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()

    expect(approveMock).toHaveBeenCalledTimes(3)
    const [c1, c2, c3] = approveMock.mock.calls
    const batchId = c1[1].batch_id
    expect(batchId).toMatch(UUID_V4)
    expect(c1).toEqual([107, { items: [{ item_id: 1 }], batch_id: batchId }, { skipErrorToast: true }])
    expect(c2).toEqual([108, { items: [{ item_id: 2 }], batch_id: batchId }, { skipErrorToast: true }])
    expect(c3).toEqual([111, { batch_id: batchId }, { skipErrorToast: true }])

    const row = (id) => pendingDialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    expect(row(107)).toContain('已核准，alice 現在可以連線')
    expect(row(108)).toContain('已記下你的核准（1/2），還要 1 位審核人')
    expect(row(111)).toContain('未生效：有資產不在你的審核範圍，整張沒有核准')
    expect(pendingDialog(wrapper).text()).not.toContain('被拒')
    expect(pendingDialog(wrapper).find('[data-test="batch-summary"]').text())
      .toBe('已核准 1 張 · 已記下核准 1 張 · 未生效 1 張')
  })

  it('開啟確認時重讀：已不在待審的標「會略過」、按鈕只計會送出的、送出後只有兩個核准請求', async () => {
    approveMock.mockResolvedValue({ status: 'approved', items: [] })
    const wrapper = mountView()
    await flushPromises()
    await wrapper.find('[data-test="pending-select-all"] input').setValue(true)
    await flushPromises()
    // 勾選後 #108 已由其他審核人處理
    getPendingMock.mockResolvedValue({ data: [request107, request111] })
    await wrapper.find('[data-test="batch-approve-open"]').trigger('click')
    await flushPromises()
    const sheet = pendingDialog(wrapper).find('[data-test="batch-sheet"][data-id="108"]')
    expect(sheet.find('[data-test="batch-will-skip"]').text()).toBe('已不在待審，會略過')
    expect(pendingDialog(wrapper).find('[data-test="batch-submit"]').text()).toBe('核准 2 張')
    // 標題的張數同樣不算會略過的單
    expect(document.body.querySelector('.el-dialog[data-test="pending-batch-dialog"] .el-dialog__title')?.textContent).toBe('核准 2 張申請')
    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    expect(approveMock).toHaveBeenCalledTimes(2)
    expect(approveMock.mock.calls.map((c) => c[0])).toEqual([107, 111])
    const skipped = pendingDialog(wrapper).find('[data-test="batch-item"][data-id="108"]')
    expect(skipped.text()).toContain('略過：開啟確認框時已不在待審，沒有送出')
    expect(skipped.find('[data-test="batch-open-request"]').exists()).toBe(true)
    expect(pendingDialog(wrapper).find('[data-test="batch-summary"]').text()).toContain('略過 1 張')
  })

  it('送出時一張回 409：結果以「未生效」開頭、附看這張申請單，整個結果框找不到「被拒」', async () => {
    approveMock
      .mockResolvedValueOnce({ status: 'approved', items: [item(1, { status: 'approved' })] })
      .mockRejectedValueOnce(httpError(409, 'CONFLICT_ACCESS_REQUEST_STATE'))
      .mockResolvedValueOnce({ status: 'approved' })
    const wrapper = mountView()
    await flushPromises()
    await wrapper.find('[data-test="pending-select-all"] input').setValue(true)
    await flushPromises()
    await wrapper.find('[data-test="batch-approve-open"]').trigger('click')
    await flushPromises()
    // 送出後重讀：#108 已不在待審
    getPendingMock.mockResolvedValue({ data: [request111] })
    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    const gone = pendingDialog(wrapper).find('[data-test="batch-item"][data-id="108"]')
    expect(gone.find('.batch-progress__status').text().startsWith('未生效：')).toBe(true)
    expect(gone.text()).toContain('這張已不在待審（可能已核准、被撤回、逾期或由其他審核人處理）')
    expect(gone.find('[data-test="batch-open-request"]').exists()).toBe(true)
    expect(pendingDialog(wrapper).text()).not.toContain('被拒')
    expect(pendingDialog(wrapper).find('[data-test="batch-summary"]').text()).toContain('未生效 1 張')
  })

  it('已投票、等其他審核人的單：勾選框停用，全選不會選到，其他單照常可勾', async () => {
    const voted = { ...request108, items: [item(2, { approvals_required: 2, approvals: [{ approver_id: ME }] }), item(3, { status: 'approved' })] }
    getPendingMock.mockResolvedValue({ data: [request107, voted, request111] })
    const wrapper = mountView()
    await flushPromises()
    expect(pendingCell(wrapper, 108).element.disabled).toBe(true)
    expect(pendingCell(wrapper, 107).element.disabled).toBe(false)
    await wrapper.find('[data-test="pending-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.vm.pendingSelection.selected.value.map((r) => r.id)).toEqual([107, 111])
    expect(wrapper.find('[data-test="pending-batch-bar"]').text()).toContain('已選 2 張申請')
  })

  it('批次拒絕：理由必填，逐張送出 {note, batch_id}，不帶 item_id', async () => {
    rejectMock.mockResolvedValue({ status: 'rejected' })
    const wrapper = mountView()
    await flushPromises()

    await pendingCell(wrapper, 107).setValue(true)
    await pendingCell(wrapper, 108).setValue(true)
    await flushPromises()
    await wrapper.find('[data-test="batch-reject-open"]').trigger('click')
    await flushPromises()

    const submit = () => pendingDialog(wrapper).find('[data-test="batch-submit"]')
    expect(submit().attributes('disabled')).toBeDefined()
    expect(pendingDialog(wrapper).text()).toContain('拒絕 2 張')
    // 只列這次會被拒絕的待決項目；已核准的項目不受影響、不列
    expect(pendingDialog(wrapper).text()).toContain('asset-2')
    expect(pendingDialog(wrapper).text()).not.toContain('asset-3')
    await pendingDialog(wrapper).find('[data-test="batch-note"] textarea').setValue('本週凍結變更')
    await submit().trigger('click')
    await flushPromises()

    expect(rejectMock).toHaveBeenCalledTimes(2)
    const batchId = rejectMock.mock.calls[0][2].batchId
    expect(batchId).toMatch(UUID_V4)
    expect(rejectMock.mock.calls[0]).toEqual([107, '本週凍結變更', { batchId, skipErrorToast: true }])
    expect(rejectMock.mock.calls[1]).toEqual([108, '本週凍結變更', { batchId, skipErrorToast: true }])
    expect(pendingDialog(wrapper).find('[data-test="batch-item"][data-id="107"]').text()).toContain('已拒絕，已通知 alice')
  })

  it('批次完成後同樣重讀清單與計數', async () => {
    approveMock.mockResolvedValue({ status: 'approved', items: [] })
    const wrapper = mountView()
    await flushPromises()
    await pendingCell(wrapper, 107).setValue(true)
    await flushPromises()
    await wrapper.find('[data-test="batch-approve-open"]').trigger('click')
    await flushPromises()
    await pendingDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()
    getPendingMock.mockClear(); getCountMock.mockClear()
    await pendingDialog(wrapper).find('[data-test="batch-done"]').trigger('click')
    await flushPromises()
    expect(getPendingMock).toHaveBeenCalledTimes(1)
    expect(getCountMock).toHaveBeenCalled()
  })

  it('待審待確認：掛載時比對待審與歷史，查回實際狀態；他人處理的只寫已不在待審', async () => {
    sessionStorage.setItem('ot-batch-review:approvals-pending', JSON.stringify({
      v: 1,
      batchId: '0b8e4c0e-2f1a-4b7a-9c3d-5e6f7a8b9c0d',
      kind: 'approve',
      userId: ME,
      params: {},
      items: [
        { id: 107, label: '申請 #107 · alice', state: 'inflight', message: '', meta: { itemIds: [1] } },
        { id: 108, label: '申請 #108 · bob', state: 'inflight', message: '', meta: { itemIds: [2] } },
        { id: 109, label: '申請 #109 · carol', state: 'inflight', message: '', meta: { itemIds: [9] } },
        { id: 110, label: '申請 #110 · dave', state: 'inflight', message: '', meta: { itemIds: [10] } },
      ],
    }))
    getPendingMock.mockResolvedValue({
      data: [
        { ...request107, items: [item(1, { approvals: [{ approver_id: ME }] })] },
        request108,
      ],
    })
    getHistoryMock.mockResolvedValue({
      data: [{ id: 109, status: 'approved', approver_id: 99, approvals: [{ approver_id: 99 }], items: [item(9, { status: 'approved', decided_by: 99 })] }],
      total: 1,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(approveMock).not.toHaveBeenCalled()
    expect(getHistoryMock).toHaveBeenCalledWith({ page: 1, page_size: 100 }, { skipErrorToast: true })
    const row = (id) => pendingDialog(wrapper).find(`[data-test="batch-item"][data-id="${id}"]`).text()
    // 仍在待審但所選項目已有我的票：我的核准已記錄，單子還在等其他審核人
    expect(row(107)).toContain('已記下你的核准')
    expect(row(108)).toContain('未送出')
    expect(row(109)).toContain('未生效：這張已不在待審')
    expect(row(110)).toContain('待確認')
    expect(row(110)).toContain('歷史')
  })

  it('待補審：批次只提供確認無誤，理由必填，逐筆帶同一 batch_id；文字維持原樣', async () => {
    getReviewsMock.mockResolvedValue({
      data: [
        { id: 40, requester_id: 64, requester: { username: 'alice' }, asset: { name: 'k8s' }, reason: '事故', created_at: '2026-09-29T01:00:00Z', kind: 'break_glass' },
        { id: 41, requester_id: 65, requester: { username: 'bob' }, asset: { name: 'db' }, reason: '事故', created_at: '2026-09-29T01:00:00Z', kind: 'break_glass' },
      ],
    })
    reviewMock.mockRejectedValueOnce(httpError(409, 'CONFLICT_ACCESS_REQUEST_STATE')).mockResolvedValueOnce({})
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.activeTab = 'reviews'
    wrapper.vm.fetchCurrentTab()
    await flushPromises()

    await wrapper.find('[data-test="reviews-select-all"] input').setValue(true)
    await flushPromises()
    expect(wrapper.find('[data-test="reviews-batch-bar"]').text()).toContain('已選 2 筆')
    await wrapper.find('[data-test="batch-review-open"]').trigger('click')
    await flushPromises()

    // 批次只提供「確認無誤」：沒有處置選項可選
    expect(reviewsDialog(wrapper).find('input[type="radio"]').exists()).toBe(false)
    expect(reviewsDialog(wrapper).text()).toContain('確認無誤')
    expect(reviewsDialog(wrapper).find('[data-test="batch-submit"]').attributes('disabled')).toBeDefined()
    await reviewsDialog(wrapper).find('[data-test="batch-note"] textarea').setValue('皆為事故處理')
    await reviewsDialog(wrapper).find('[data-test="batch-submit"]').trigger('click')
    await flushPromises()

    expect(reviewMock).toHaveBeenCalledTimes(2)
    const opts = reviewMock.mock.calls[0][3]
    expect(opts.batchId).toMatch(UUID_V4)
    expect(reviewMock.mock.calls[0]).toEqual([40, 'confirmed', '皆為事故處理', { batchId: opts.batchId, skipErrorToast: true }])
    expect(reviewMock.mock.calls[1]).toEqual([41, 'confirmed', '皆為事故處理', { batchId: opts.batchId, skipErrorToast: true }])
    // 待補審的批次文字不在本次改動範圍：沿用原本的摘要與「被拒：」
    expect(reviewsDialog(wrapper).find('[data-test="batch-summary"]').text())
      .toContain('成功 1 筆 · 被拒 1 筆 · 未送出 0 筆 · 待確認 0 筆')
  })
})
