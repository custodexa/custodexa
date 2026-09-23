import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ToolCallLedgerTable from '../agent/ToolCallLedgerTable.vue'
import { t } from '@/i18n'

const reveal = vi.hoisted(() => vi.fn())
vi.mock('@/api/agentTasks', () => ({ getAgentToolCallArguments: reveal }))
enableAutoUnmount(afterEach)

const row = {
  id: 5, seq: 3, session_id: 118, tool: 'run_command', decision: 'denied',
  denial_code: 'RULE_COMMAND_BLOCKED', masked_count: 1, args_retained: true,
  args_redacted: { command: '[REDACTED]', session_handle: 'fp:abcd1234' },
  created_at: '2026-09-23T03:00:00Z', duration_ms: 1,
}
const open = (rows = [row]) => mount(ToolCallLedgerTable, {
  props: { rows },
  attachTo: document.body,
  global: { plugins: [ElementPlus] },
})
const button = (name) => document.querySelector(`[data-test="${name}"]`)

beforeEach(() => {
  reveal.mockReset()
  localStorage.setItem('user', JSON.stringify({ roles: ['auditor'] }))
})
afterEach(() => localStorage.clear())

describe('ToolCallLedgerTable sensitive arguments', () => {
  it('marks an old row as not retained and offers no reveal action', () => {
    const wrapper = open([{ ...row, args_retained: false }])
    expect(wrapper.get('[data-test="arguments-not-retained"]').text()).toBe(t('agentLedger.argumentsNotRetained'))
    expect(wrapper.text()).not.toContain('[REDACTED]')
    expect(wrapper.find('[data-test="reveal-arguments"]').exists()).toBe(false)
  })

  it('keeps a denied command and code readable, with a nonreversible handle fingerprint', () => {
    const wrapper = open()
    expect(wrapper.get('[data-test="denial-code"]').text()).toBe('RULE_COMMAND_BLOCKED')
    expect(wrapper.get('[data-test="denied-command-preview"]').text()).toBe('[REDACTED]')
    expect(wrapper.get('[data-test="denied-reason-code-preview"]').text()).toBe('RULE_COMMAND_BLOCKED')
    expect(wrapper.get('[data-test="ledger-arguments"]').text()).toContain('[REDACTED]')
    expect(wrapper.get('.handle-fingerprint code').text()).toBe('fp:abcd1234')
    expect(wrapper.get('.handle-fingerprint .help-tip').attributes('aria-label')).toBe(t('agentLedger.handleFingerprint'))
    const plain = open([{ ...row, masked_count: 0, args_redacted: { command: 'ssh 10.0.0.9' } }])
    expect(plain.get('[data-test="denied-command-preview"]').text()).toBe('ssh 10.0.0.9')
  })

  it('requires a nonblank reason before requesting the original', async () => {
    const wrapper = open()
    await wrapper.get('[data-test="reveal-arguments"]').trigger('click')
    await flushPromises()
    expect(button('reveal-submit').disabled).toBe(true)
    await wrapper.get('textarea').setValue('   ')
    expect(button('reveal-submit').disabled).toBe(true)
    await wrapper.get('textarea').setValue('界'.repeat(334))
    expect(button('reveal-submit').disabled).toBe(true)
    expect(reveal).not.toHaveBeenCalled()
  })

  it('replaces the masked arguments after one audited request and marks the row', async () => {
    reveal.mockResolvedValue({ data: { id: 5, arguments: { command: 'ssh 10.0.0.9' } } })
    const wrapper = open()
    await wrapper.get('[data-test="reveal-arguments"]').trigger('click')
    await wrapper.get('textarea').setValue('  incident 7  ')
    await wrapper.get('[data-test="reveal-submit"]').trigger('click')
    await flushPromises()
    expect(reveal).toHaveBeenCalledWith(5, 'incident 7')
    expect(wrapper.get('[data-test="ledger-arguments"]').text()).toContain('ssh 10.0.0.9')
    expect(wrapper.get('[data-test="arguments-revealed"]').text()).toBe(t('agentLedger.revealed'))
    expect(wrapper.find('[data-test="reveal-arguments"]').exists()).toBe(false)
  })

  it('shows the resolved API error and does not reveal on failure', async () => {
    reveal.mockRejectedValue({ response: { status: 404, data: { code: 'NOTFOUND_TOOL_CALL_ARGUMENTS' } } })
    const wrapper = open()
    await wrapper.get('[data-test="reveal-arguments"]').trigger('click')
    await wrapper.get('textarea').setValue('incident 7')
    await wrapper.get('[data-test="reveal-submit"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="reveal-error"]').text()).toBe(t('apiError.NOTFOUND_TOOL_CALL_ARGUMENTS'))
    expect(wrapper.get('[data-test="ledger-arguments"]').text()).toContain('[REDACTED]')
  })
})
