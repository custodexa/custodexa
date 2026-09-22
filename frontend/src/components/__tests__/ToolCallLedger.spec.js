import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ToolCallLedger from '../agent/ToolCallLedger.vue'
import i18n, { t } from '@/i18n'
const api = vi.hoisted(() => ({ list: vi.fn() }))
vi.mock('@/api/agentTasks', () => ({ getAgentToolCalls: api.list }))
enableAutoUnmount(afterEach)
const row = { id: 1, seq: 4, user_id: 7, access_request_id: 8, session_id: null, tool: 'open_session', decision: 'denied', denial_code: 'AUTH_REQUEST_ITEM_MISMATCH', masked_count: 2, duration_ms: 12, result_status: 'error', result_digest: 'sha256-fixture', result_excerpt: '<script>excerpt</script>', args_redacted: { password: '[REDACTED]' }, created_at: '2026-09-22T00:00:00Z' }
beforeEach(() => { vi.clearAllMocks(); api.list.mockResolvedValue({ data: [row], total: 1 }) })
const open = async (props = {}) => { const w = mount(ToolCallLedger, { props: { query: { access_request_id: 8 }, ...props }, global: { plugins: [ElementPlus] } }); await flushPromises(); return w }
describe('ToolCallLedger', () => {
  it('被拒列呈現原因碼與說明文字', async () => { const w = await open(); expect(w.get('code').text()).toBe(row.denial_code); expect(w.get('[data-test="denial-explanation"]').text()).toBe(t('apiError.AUTH_REQUEST_ITEM_MISMATCH')); expect(w.text()).toContain('sha256-fixture'); expect(w.text()).toContain('[REDACTED]'); expect(w.find('script').exists()).toBe(false) })
  it('判定五值各自可辨', async () => { const values = ['pending', 'allowed', 'denied', 'breaker', 'rate_limited']; api.list.mockResolvedValue({ data: values.map((decision, id) => ({ ...row, id, decision })), total: 5 }); const w = await open(); const labels = w.findAll('[data-test="ledger-decision"]').map(n => n.text()); expect(labels).toEqual(values.map(v => t(`agentLedger.decisions.${v}`))); expect(new Set(labels).size).toBe(5) })
  it('任務帳本含未建立會話的呼叫', async () => { const w = await open(); expect(api.list).toHaveBeenCalledWith({ access_request_id: 8, offset: 0, limit: 20 }); expect(w.findAll('[data-test="ledger-row"]')).toHaveLength(1); expect(w.text()).toContain(t('agentLedger.noSession')); expect(w.find('a').exists()).toBe(false) })
  it('待定列呈現為已送出而結果未知：契約 §9.13 修正為是否送出亦未知', async () => { api.list.mockResolvedValue({ data: [{ ...row, decision: 'pending', denial_code: '', result_status: '' }], total: 1 }); const w = await open(); expect(w.text()).toContain('已記錄，是否送出與結果皆未知'); expect(w.text()).not.toContain('已送出'); expect(w.text()).not.toContain('成功'); expect(w.text()).not.toContain('失敗') })
  it('回傳節錄標示為節錄非全文', async () => { const w = await open(); expect(w.get('[data-test="excerpt-boundary"]').text()).toContain('並非回傳全文'); expect(w.text()).toContain('<script>excerpt</script>') })
  it('區塊說明只出現一次', async () => { api.list.mockResolvedValue({ data: [row, { ...row, id: 2 }], total: 2 }); const w = await open(); expect(w.findAll('[data-test="ledger-boundary"]')).toHaveLength(1); expect(w.text().split(t('agentLedger.boundary'))).toHaveLength(2) })
  it('區塊說明不宣稱為 agent 收到的全文', async () => { const w = await open(); expect(w.get('[data-test="ledger-boundary"]').text()).toBe('錄影保留原始畫面、帳本保留回傳摘要與雜湊'); expect(w.text()).not.toContain('agent 收到') })
  it('遮罩筆數非零列免展開可辨', async () => { const w = await open(); expect(w.get('[data-test="masked-count"]').text()).toBe('遮罩 2 筆'); expect(w.get('[data-test="masked-count"]').element.closest('details')).toBeNull(); expect(w.get('details').attributes('open')).toBeUndefined() })
  it('分頁與判定送伺服器並保留任務條件，接受核准的會話查詢', async () => { const w = await open(); w.vm.changePage(2); await flushPromises(); expect(api.list).toHaveBeenLastCalledWith({ access_request_id: 8, offset: 20, limit: 20 }); w.vm.decision = 'denied'; w.vm.resetPage(); await flushPromises(); expect(api.list).toHaveBeenLastCalledWith({ access_request_id: 8, decision: 'denied', offset: 0, limit: 20 }); api.list.mockClear(); await w.setProps({ query: { session_id: 99 } }); await flushPromises(); expect(api.list).toHaveBeenLastCalledWith({ session_id: 99, offset: 0, limit: 20 }); expect(w.text()).not.toContain(t('agentLedger.unsupportedQuery')) })
})

it.each(['zh-TW', 'en-US', 'ja-JP'])('polish 9：十種操作使用自然語、工具碼只在細節 %s', async locale => {
  i18n.global.locale.value = locale
  const tools = ['list_assets', 'request_access', 'check_request', 'open_session', 'run_command', 'send_keys', 'query', 'read_screen', 'close_session', 'close_task']
  api.list.mockResolvedValue({ data: tools.map((tool, id) => ({ ...row, id, tool })), total: 10 })
  const w = await open()
  for (const [index, entry] of w.findAll('[data-test="ledger-row"]').entries()) {
    const tool = tools[index]
    expect(i18n.global.te(`agentLedger.tools.${tool}`, locale)).toBe(true)
    expect(entry.get('[data-test="tool-action"]').text()).toBe(t(`agentLedger.tools.${tool}`))
    expect(entry.get('[data-test="tool-action"]').text()).not.toBe(tool)
    expect(entry.get('.tool-ledger__summary').find('code').exists()).toBe(false)
    expect(entry.get('details').text()).toContain(tool)
    expect(entry.get('details').attributes('open')).toBeUndefined()
  }
})
