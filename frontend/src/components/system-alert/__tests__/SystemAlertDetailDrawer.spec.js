import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, DOMWrapper } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewAlertsSection from '@/components/daily-review/DailyReviewAlertsSection.vue'

// 系統告警明細的逐筆處置：從每日簽核抽屜的列「查看」打開，組內上一筆、下一筆，
// 處置走單筆端點（不帶批次關聯碼），處置後換到下一筆。替身端點，不打任何真實服務
enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const reviewAlertMock = vi.fn()
vi.mock('@/api/alerts', () => ({ reviewAlert: (...a) => reviewAlertMock(...a), searchAlerts: vi.fn() }))
const getDetailMock = vi.fn()
vi.mock('@/api/systemAlerts', () => ({ getSystemAlertDetail: (...a) => getDetailMock(...a) }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))

const ME = 7
const RouterLinkStub = { props: ['to'], template: '<a><slot /></a>' }
const alertRow = (id, extra = {}) => ({
  id,
  kind: 'system_security',
  rule_name: 'management_role_granted',
  reason_code: 'management_role_granted',
  severity: 'high',
  user_id: ME,
  username: 'admin',
  target_kind: 'user',
  target_id: String(20 + id),
  params: { recipient: `user-${id}` },
  triggered_at: `2026-11-13T12:${String(id).padStart(2, '0')}:00Z`,
  ...extra,
})
const detailOf = (id) => ({
  alert_id: id, alert_type: 'management_role_granted', severity: 'high', triggered_at: `2026-11-13T12:${String(id).padStart(2, '0')}:00Z`,
  actor: 'admin', target_kind: 'user', target_id: String(20 + id), params: { recipient: `user-${id}`, role_name: 'asset_admin' }, deliveries: [],
})

const body = () => new DOMWrapper(document.body)
const drawer = () => body().find('[data-test="system-alert-drawer"]')

async function mountSection(rows, canSign = true) {
  const w = mount(DailyReviewAlertsSection, {
    props: { alerts: rows, total: rows.length, timezone: 'Asia/Taipei', canSign },
    attachTo: document.body,
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub } },
  })
  await w.find('[data-test="dr-alert-group-toggle"]').trigger('click')
  await flushPromises()
  return w
}
async function view(w, id) {
  await w.find(`[data-test="dr-alert-${id}"] [data-test="dr-alert-view"]`).trigger('click')
  await flushPromises()
}
const shownId = () => getDetailMock.mock.calls.at(-1)?.[0]

beforeEach(() => {
  reviewAlertMock.mockReset()
  getDetailMock.mockReset()
  getDetailMock.mockImplementation(async (id) => detailOf(id))
  document.body.innerHTML = ''
  localStorage.setItem('user', JSON.stringify({ id: ME, username: 'admin', roles: ['auditor'] }))
})
afterEach(() => localStorage.clear())

describe('系統告警明細的逐筆處置', () => {
  it('本人觸發的一筆不填說明按送出：一個單筆審閱請求、不帶 batch_id；處置後換成同組下一筆', async () => {
    const rows = [alertRow(1), alertRow(2), alertRow(3)]
    const w = await mountSection(rows)
    await view(w, 2)
    expect(drawer().find('[data-test="sa-position"]').text()).toBe('這一組第 2／3 筆')
    reviewAlertMock.mockResolvedValue({})
    await drawer().find('[data-test="sa-review-submit"]').trigger('click')
    await flushPromises()
    expect(reviewAlertMock).toHaveBeenCalledTimes(1)
    const [id, payload] = reviewAlertMock.mock.calls[0]
    expect(id).toBe(2)
    expect(payload).toEqual({ disposition: 'benign', note: '' })
    expect(payload).not.toHaveProperty('batch_id')
    expect(w.emitted('reviewed')).toHaveLength(1)
    // 父層重取後這一筆離開清單：明細換成同一位置的下一筆，總數減一
    await w.setProps({ alerts: [rows[0], rows[2]] })
    await flushPromises()
    expect(shownId()).toBe(3)
    expect(drawer().find('[data-test="sa-position"]').text()).toBe('這一組第 2／2 筆')
  })

  it('第一筆沒有上一筆、最後一筆沒有下一筆；上一筆、下一筆在組內移動', async () => {
    const w = await mountSection([alertRow(1), alertRow(2), alertRow(3)])
    await view(w, 1)
    expect(drawer().find('[data-test="sa-prev"]').attributes('disabled')).toBeDefined()
    expect(drawer().find('[data-test="sa-next"]').attributes('disabled')).toBeUndefined()
    await drawer().find('[data-test="sa-next"]').trigger('click')
    await flushPromises()
    await drawer().find('[data-test="sa-next"]').trigger('click')
    await flushPromises()
    expect(shownId()).toBe(3)
    expect(drawer().find('[data-test="sa-position"]').text()).toBe('這一組第 3／3 筆')
    expect(drawer().find('[data-test="sa-next"]').attributes('disabled')).toBeDefined()
    expect(drawer().find('[data-test="sa-prev"]').attributes('disabled')).toBeUndefined()
  })

  it('選需升級處理並寫說明：照所填送出', async () => {
    const w = await mountSection([alertRow(1)])
    await view(w, 1)
    await drawer().find('[data-test="sa-review-escalated"] input').setValue(true)
    await drawer().find('textarea[data-test="sa-review-note"]').setValue(' 已請 lin 確認 ')
    reviewAlertMock.mockResolvedValue({})
    await drawer().find('[data-test="sa-review-submit"]').trigger('click')
    await flushPromises()
    expect(reviewAlertMock).toHaveBeenCalledWith(1, { disposition: 'escalated', note: '已請 lin 確認' })
  })

  it('只有查看權限：明細可以打開，但沒有處置區塊與送出鈕', async () => {
    const w = await mountSection([alertRow(1), alertRow(2)], false)
    await view(w, 1)
    expect(drawer().find('[data-test="sa-position"]').text()).toBe('這一組第 1／2 筆')
    expect(drawer().find('[data-test="sa-review"]').exists()).toBe(false)
    expect(drawer().find('[data-test="sa-review-submit"]').exists()).toBe(false)
  })
})
