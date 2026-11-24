import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewAlertsSection from '../DailyReviewAlertsSection.vue'

// 單日抽屜的告警區：分組、列上的觸發者與對象、全選、整組、黏住的批次列。替身端點，不打任何真實服務
enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

vi.mock('@/api/alerts', () => ({ reviewAlert: vi.fn(), searchAlerts: vi.fn() }))
vi.mock('@/api/systemAlerts', () => ({ getSystemAlertDetail: vi.fn().mockResolvedValue(null) }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))

const ME = 7
const TZ = 'Asia/Taipei'
let seq = 0
const at = (minute) => new Date(Date.UTC(2026, 10, 13, 12, 0) + minute * 60_000).toISOString()

// 系統告警：reason_code 留空，類型只能從 rule_name 讀出
const sys = (type, extra = {}) => ({
  id: ++seq,
  kind: 'system_security',
  rule_name: type,
  reason_code: '',
  severity: 'high',
  user_id: 99,
  username: 'chen.wei',
  asset_id: null,
  asset_name: '',
  target_kind: 'user_group',
  target_id: '4',
  params: { recipient: 'ops-team', role_name: 'asset_admin' },
  triggered_at: at(seq),
  ...extra,
})
const cmd = (extra = {}) => ({
  id: ++seq,
  kind: 'rule',
  rule_name: 'chmod 777 全開權限',
  reason_code: '',
  severity: 'medium',
  user_id: ME,
  username: 'admin',
  command: 'chmod -R 777 /data/app',
  asset_id: 3,
  asset_name: 'app-prod-02',
  target_kind: '',
  target_id: '',
  params: {},
  triggered_at: at(seq),
  ...extra,
})

// 75 筆分 4 類，其中本人 62 筆（畫稿 B 的 11-13）
function day75() {
  const rows = []
  for (let i = 0; i < 50; i += 1) rows.push(sys('management_role_granted', i < 44 ? { user_id: ME, username: 'admin' } : {}))
  for (let i = 0; i < 13; i += 1) rows.push(sys('privileged_api_token_created', i < 10 ? { user_id: ME, username: 'admin' } : {}))
  for (let i = 0; i < 8; i += 1) rows.push(sys('custom_secret_used', { severity: 'medium', ...(i < 4 ? { user_id: ME, username: 'admin' } : {}) }))
  for (let i = 0; i < 4; i += 1) rows.push(sys('notification_channel_changed', { severity: 'medium', user_id: ME, username: 'admin' }))
  return rows
}

function mountSection(alerts, props = {}) {
  return mount(DailyReviewAlertsSection, {
    props: { alerts, total: alerts.length, timezone: TZ, canSign: true, ...props },
    global: { plugins: [ElementPlus], stubs: { RouterLink: true, 'router-link': true } },
  })
}

const groupEl = (w, type) => w.findAll('[data-test="dr-alert-group"]').find((g) => g.attributes('data-key') === `system:${type}` || g.attributes('data-key') === type)
async function expand(group) {
  await group.find('[data-test="dr-alert-group-toggle"]').trigger('click')
  await flushPromises()
}
async function check(el) {
  await el.find('input').setValue(!el.find('input').element.checked)
  await flushPromises()
}

beforeEach(() => {
  seq = 0
  localStorage.setItem('user', JSON.stringify({ id: ME, username: 'admin', roles: ['auditor'] }))
})
afterEach(() => localStorage.clear())

describe('告警列看得出是什麼事', () => {
  it('發放管理類角色的系統告警：組名與列顯示類型譯名、觸發者與對象，不是「系統告警」泛稱', async () => {
    const w = mountSection([sys('management_role_granted')])
    const group = groupEl(w, 'management_role_granted')
    expect(group.find('[data-test="dr-alert-group-name"]').text()).toBe('發放管理類角色給他人')
    await expand(group)
    expect(w.find('[data-test="dr-alert-who"]').text()).toBe('chen.wei')
    expect(w.find('[data-test="dr-alert-detail"]').text()).toBe('目標：ops-team（使用者群組 #4）')
    expect(w.find('[data-test="dr-alert-view"]').exists()).toBe(true)
    expect(w.text()).not.toContain('系統告警')
  })

  it('觸發者是目前使用者時標「你」，組的第二行把本人寫在前面', async () => {
    const w = mountSection([sys('management_role_granted'), sys('management_role_granted', { user_id: ME, username: 'admin' })])
    const group = groupEl(w, 'management_role_granted')
    expect(group.find('[data-test="dr-alert-group-sub"]').text()).toMatch(/^你 1 筆 · chen\.wei 1 筆/)
    await expand(group)
    expect(w.findAll('[data-test="dr-alert-who"]').map((e) => e.text())).toContain('admin（你）')
  })

  it('指令告警：組名是規則名稱並標「指令告警」，列上有資產與指令原文，動作是「處置」', async () => {
    const w = mountSection([cmd()])
    const group = w.find('[data-test="dr-alert-group"]')
    expect(group.find('[data-test="dr-alert-group-name"]').text()).toBe('chmod 777 全開權限')
    expect(group.find('[data-test="dr-alert-group-rule-tag"]').text()).toBe('指令告警')
    await expand(group)
    expect(w.find('[data-test="dr-alert-who"]').text()).toBe('admin（你） · app-prod-02')
    expect(w.find('[data-test="dr-alert-detail"]').text()).toBe('chmod -R 777 /data/app')
    expect(w.find('[data-test="dr-alert-single"]').exists()).toBe(true)
    expect(w.find('[data-test="dr-alert-view"]').exists()).toBe(false)
  })
})

describe('分組、全選、整組、黏住的批次列', () => {
  it('75 筆分 4 組、預設收合；全選後批次列寫 75 筆、4 類與本人 62 筆，送出時帶出 75 筆', async () => {
    const w = mountSection(day75())
    expect(w.findAll('[data-test="dr-alert-group"]')).toHaveLength(4)
    expect(w.findAll('[data-test^="dr-alert-"][data-test$="0"]').filter((e) => e.element.tagName === 'LI')).toHaveLength(0)
    expect(w.find('[data-test="dr-alerts-pending"]').text()).toBe('75 筆要處置')
    await check(w.find('[data-test="dr-alerts-select-all"]'))
    expect(w.find('[data-test="dr-alerts-selected"]').text()).toBe('已選 75 筆（4 類，其中你觸發的 62 筆）')
    expect(w.find('[data-test="dr-alerts-batch-open"]').text()).toBe('處置所選（75 筆）')
    await w.find('[data-test="dr-alerts-batch-open"]').trigger('click')
    const [rows] = w.emitted('open-batch')[0]
    expect(rows).toHaveLength(75)
    expect(rows.filter((r) => r.user_id === ME)).toHaveLength(62)
  })

  it('勾某一組：只選取該組，筆數與類數隨之更新', async () => {
    const w = mountSection(day75())
    await check(groupEl(w, 'privileged_api_token_created').find('[data-test="dr-alert-group-select"]'))
    expect(w.find('[data-test="dr-alerts-selected"]').text()).toBe('已選 13 筆（1 類，其中你觸發的 10 筆）')
    await w.find('[data-test="dr-alerts-batch-open"]').trigger('click')
    const [rows] = w.emitted('open-batch')[0]
    expect(new Set(rows.map((r) => r.rule_name))).toEqual(new Set(['privileged_api_token_created']))
  })

  it('本人觸發的列勾選框可用，逐筆勾選有效', async () => {
    const w = mountSection([sys('management_role_granted', { user_id: ME, username: 'admin' })])
    await expand(w.find('[data-test="dr-alert-group"]'))
    const box = w.find('[data-test="dr-alert-select"]')
    expect(box.find('input').attributes('disabled')).toBeUndefined()
    await check(box)
    expect(w.find('[data-test="dr-alerts-selected"]').text()).toBe('已選 1 筆（1 類，其中你觸發的 1 筆）')
  })

  it('批次列黏在告警區頂端（sticky）', () => {
    const w = mountSection(day75())
    expect(w.find('[data-test="dr-alerts-batch-bar"]').attributes('style')).toContain('position: sticky')
  })

  it('612 筆全選：批次列說明單次上限，按鈕寫 500 筆', async () => {
    const rows = Array.from({ length: 612 }, (_, i) => sys(i < 410 ? 'notification_channel_changed' : 'custom_secret_used', { user_id: ME, username: 'admin', severity: 'medium' }))
    const w = mountSection(rows)
    await check(w.find('[data-test="dr-alerts-select-all"]'))
    expect(w.find('[data-test="dr-alerts-limit-hint"]').text()).toBe('一次最多 500 筆：這次會處置前 500 筆，剩下的 112 筆送完後再按一次')
    expect(w.find('[data-test="dr-alerts-batch-open"]').text()).toBe('處置所選（500 筆）')
  })

  it('重取後已處置的從選取移除，其餘維持勾選', async () => {
    const rows = day75()
    const w = mountSection(rows)
    await check(w.find('[data-test="dr-alerts-select-all"]'))
    await w.setProps({ alerts: rows.slice(50) })
    expect(w.find('[data-test="dr-alerts-selected"]').text()).toBe('已選 25 筆（3 類，其中你觸發的 18 筆）')
  })

  it('沒有處置權限：沒有勾選、批次列與處置動作', async () => {
    const w = mountSection([cmd(), sys('management_role_granted')], { canSign: false })
    expect(w.find('[data-test="dr-alerts-batch-bar"]').exists()).toBe(false)
    for (const g of w.findAll('[data-test="dr-alert-group-toggle"]')) await g.trigger('click')
    expect(w.find('[data-test="dr-alert-select"]').exists()).toBe(false)
    expect(w.find('[data-test="dr-alert-single"]').exists()).toBe(false)
  })
})
