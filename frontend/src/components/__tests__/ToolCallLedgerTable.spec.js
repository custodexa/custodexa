import { afterEach, describe, it, expect } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ToolCallLedgerTable from '../agent/ToolCallLedgerTable.vue'
import i18n, { t } from '@/i18n'
enableAutoUnmount(afterEach)
const rows = [
  { id: 1, seq: 11, session_id: 5, access_request_id: 8, tool: 'run_command', decision: 'allowed', denial_code: '', masked_count: 2, duration_ms: 105, result_status: 'ok', args_redacted: {}, created_at: '2026-09-22T06:41:02Z' },
  { id: 2, seq: 12, session_id: null, access_request_id: 8, tool: 'open_session', decision: 'denied', denial_code: 'AUTH_REQUEST_ITEM_MISMATCH', masked_count: 0, duration_ms: 8, result_status: 'error', args_redacted: {}, created_at: '2026-09-22T06:40:12Z' },
]
const targets = { 5: { asset: 'app-web-01', account: 'appuser' } }
const open = (props = {}) => mount(ToolCallLedgerTable, { props: { rows, targets, ...props }, global: { plugins: [ElementPlus] } })
describe('ToolCallLedgerTable', () => {
  it('七欄依序呈現，對象欄帶資產與帳號', () => {
    const w = open()
    expect(w.findAll('th').map(th => th.text())).toEqual(['時間', '動作', '對象', '判定', '遮罩', '耗時', '連結'])
    const cells = w.findAll('[data-test="ledger-target"]')
    expect(cells[0].text()).toContain('app-web-01'); expect(cells[0].text()).toContain('appuser')
    expect(cells[1].text()).toBe(t('agentLedger.noSession'))
  })
  it('拒絕列下方一行原因，且該列以拒絕樣式標示', () => {
    const w = open()
    const bodies = w.findAll('[data-test="ledger-row"]')
    expect(bodies[0].find('[data-test="denial-explanation"]').exists()).toBe(false)
    expect(bodies[1].get('[data-test="denial-explanation"]').text()).toBe(t('apiError.AUTH_REQUEST_ITEM_MISMATCH'))
    expect(bodies[1].get('.tool-ledger__summary').classes()).toContain('blocked')
  })
  it('連結欄依用途切換：任務頁指會話、會話頁指任務', () => {
    expect(open().get('[data-test="ledger-row"] a').attributes('href')).toBe('/sessions/5')
    expect(open({ linkMode: 'task' }).get('[data-test="ledger-row"] a').attributes('href')).toBe('/audit/agent-tasks/8')
  })
  it.each(['zh-TW', 'en-US', 'ja-JP'])('帳本表格三語 DOM 無裸 key：%s', locale => {
    i18n.global.locale.value = locale
    const w = open()
    expect(w.text()).not.toMatch(/agentLedger\.|agentTasks\.|common\./)
    i18n.global.locale.value = 'zh-TW'
  })
})
