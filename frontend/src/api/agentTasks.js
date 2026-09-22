import request from './request'

// Preserve backend response envelopes and server-side filters.
export const getAgentToolCalls = params => request({ url: '/agent-tool-calls', method: 'get', params })
export const getAgentTaskReports = requestId => request({ url: `/access-requests/${requestId}/reports`, method: 'get' })

export const getAgentTasks = params => request({ url: '/agent-tasks', method: 'get', params })
export const getAgentTask = (id, params) => request({ url: `/agent-tasks/${id}`, method: 'get', params })
