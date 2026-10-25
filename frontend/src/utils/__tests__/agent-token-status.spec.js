import { describe, it, expect } from 'vitest'
import { agentTokenState, agentTokenTagClass, agentTokenTagType, AGENT_TOKEN_STATES } from '../agentTokenStatus'

const future = '2999-01-01T00:00:00Z'

describe('agentTokenState', () => {
  it('還原後失效的鑰匙是獨立狀態，即使其他欄位顯示有效', () => {
    expect(agentTokenState({ expires_at: future, restore_invalidated: true })).toBe('restore_invalidated')
    expect(AGENT_TOKEN_STATES).toContain('restore_invalidated')
  })
  it('撤銷與停用的優先序高於還原失效，到期低於還原失效', () => {
    expect(agentTokenState({ revoked_at: 'x', restore_invalidated: true })).toBe('revoked')
    expect(agentTokenState({ suspended_at: 'x', restore_invalidated: true })).toBe('suspended')
    expect(agentTokenState({ expires_at: '2000-01-01T00:00:00Z', restore_invalidated: true })).toBe('restore_invalidated')
  })
  it('沒有失效標記的鑰匙行為不變', () => {
    expect(agentTokenState({ expires_at: future })).toBe('valid')
    expect(agentTokenState({ expires_at: '2000-01-01T00:00:00Z' })).toBe('expired')
  })
  it('終局狀態用中性彩標', () => {
    expect(agentTokenTagType('restore_invalidated')).toBe('info')
    expect(agentTokenTagClass('restore_invalidated')).toBe('ot-tag-neutral')
  })
})
