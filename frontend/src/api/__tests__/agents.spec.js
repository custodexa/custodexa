import { describe, it, expect, vi } from 'vitest'
import * as agents from '../agents'
const request = vi.hoisted(() => vi.fn())
vi.mock('../request', () => ({ default: request }))
describe('agents API 呼叫路徑與參數', () => {
  it.each([
    ['listAgentPrincipals', [{ page: 2 }], { url: '/users', method: 'get', params: { page: 2, include_agents: true } }],
    ['createAgentPrincipal', [{ username: 'worker', owner_user_id: 7, roles: ['user'] }], { url: '/users', method: 'post', data: { username: 'worker', owner_user_id: 7, roles: ['user'], kind: 'agent' }, skipErrorToast: true }],
    ['getMyAgents', [], { url: '/my/agents', method: 'get', skipErrorToast: true }],
    ['createMyAgent', [{ username: 'worker', purpose: 'reports' }], { url: '/my/agents', method: 'post', data: { username: 'worker', purpose: 'reports' }, skipErrorToast: true }],
    ['getAgentTokens', [5], { url: '/users/5/agent-tokens', method: 'get', skipErrorToast: true }],
    ['createAgentToken', [5, { name: 'daily', expires_at: '2027-01-01T00:00:00Z' }], { url: '/users/5/agent-tokens', method: 'post', data: { name: 'daily', expires_at: '2027-01-01T00:00:00Z' }, skipErrorToast: true }],
    ['revokeAgentToken', [5, 9, 'rotation'], { url: '/users/5/agent-tokens/9', method: 'delete', data: { note: 'rotation' }, skipErrorToast: true }],
    ['releaseAgentBreaker', [5, 'reviewed'], { url: '/users/5/agent-breaker/release', method: 'post', data: { reason: 'reviewed' }, skipErrorToast: true }],
  ])('%s 保留回應原形', async (name, args, expected) => {
    const raw = { data: [{ id: 9 }], total: 1, token: 'one-time-fixture' }
    request.mockResolvedValueOnce(raw)
    expect(await agents[name](...args)).toBe(raw)
    expect(request).toHaveBeenLastCalledWith(expected)
  })
})

it('熔斷事件只以主體端點與分頁條件讀取', async () => {
  const params = { offset: 20, limit: 20 }; await agents.getAgentBreakerEvents(5, params)
  expect(request).toHaveBeenLastCalledWith({ url: '/users/5/agent-breaker/events', method: 'get', params, skipErrorToast: true })
})
