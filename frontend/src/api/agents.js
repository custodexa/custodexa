import request from './request'

// Preserve response envelopes; display composition belongs to the view.
export const listAgentPrincipals = (params = {}) => request({ url: '/users', method: 'get', params: { ...params, include_agents: true } })
export const createAgentPrincipal = data => request({ url: '/users', method: 'post', data: { ...data, kind: 'agent' }, skipErrorToast: true })
export const getMyAgents = () => request({ url: '/my/agents', method: 'get', skipErrorToast: true })
export const createMyAgent = data => request({ url: '/my/agents', method: 'post', data, skipErrorToast: true })
export const getAgentTokens = id => request({ url: `/users/${id}/agent-tokens`, method: 'get', skipErrorToast: true })
export const createAgentToken = (id, data) => request({ url: `/users/${id}/agent-tokens`, method: 'post', data, skipErrorToast: true })
export const revokeAgentToken = (id, tokenId, note = '') => request({ url: `/users/${id}/agent-tokens/${tokenId}`, method: 'delete', data: { note }, skipErrorToast: true })
export const releaseAgentBreaker = (id, reason) => request({ url: `/users/${id}/agent-breaker/release`, method: 'post', data: { reason }, skipErrorToast: true })

export const getAgentBreakerEvents = (id, params) => request({ url: `/users/${id}/agent-breaker/events`, method: 'get', params, skipErrorToast: true })
