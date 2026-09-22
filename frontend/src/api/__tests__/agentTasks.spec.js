import { describe, it, expect, vi } from 'vitest'
import { getAgentToolCalls, getAgentTaskReports } from '../agentTasks'
import { createAccessRequest, approveAccessRequest, rejectAccessRequestItem, revokeAccessRequestItem } from '../accessRequests'
const request = vi.hoisted(() => vi.fn())
vi.mock('../request', () => ({ default: request }))
describe('agentTasks API 呼叫路徑與參數', () => {
  it('tool call 查詢沿現有參數原樣傳遞且保留回應', async () => {
    const params = { user_id: 5, access_request_id: 23, decision: 'pending', from: '2026-09-01T00:00:00Z', to: '2026-09-02T00:00:00Z', offset: 20, limit: 20 }
    const raw = { data: [{ id: 42, result_status: '' }], total: 21 }
    request.mockResolvedValueOnce(raw)
    expect(await getAgentToolCalls(params)).toBe(raw)
    expect(request).toHaveBeenLastCalledWith({ url: '/agent-tool-calls', method: 'get', params })
  })
  it('報告版本原形', async () => {
    const raw = { data: [{ version: 2 }, { version: 1 }] }
    request.mockResolvedValueOnce(raw)
    expect(await getAgentTaskReports(23)).toBe(raw)
    expect(request).toHaveBeenLastCalledWith({ url: '/access-requests/23/reports', method: 'get' })
  })
  it('多資產與逐項決定不改單資產契約', async () => {
    const data = { items: [{ asset_id: 1, accounts: ['ops'] }, { asset_id: 2, accounts: ['db'] }], reason: 'work', duration_minutes: 20, executor_user_id: 5 }
    await createAccessRequest(data)
    expect(request).toHaveBeenLastCalledWith({ url: '/access-requests', method: 'post', data, skipErrorToast: false })
    const decision = { item_id: 2, accounts: ['db'], duration_minutes: 10, date_start: '2026-09-22T00:00:00Z', note: 'scope' }
    await approveAccessRequest(23, decision)
    expect(request).toHaveBeenLastCalledWith({ url: '/access-requests/23/approve', method: 'post', data: decision })
    await rejectAccessRequestItem(23, 2, 'no')
    expect(request).toHaveBeenLastCalledWith({ url: '/access-requests/23/reject', method: 'post', data: { item_id: 2, note: 'no' } })
    await revokeAccessRequestItem(23, 2, 'done')
    expect(request).toHaveBeenLastCalledWith({ url: '/access-requests/23/revoke', method: 'post', data: { item_id: 2, note: 'done' } })
  })
})

it('任務列表與單筆詳情使用真端點與原形回應', async () => {
  const { getAgentTasks, getAgentTask } = await import('../agentTasks')
  const query = { subject: 5, owner: 2, report_status: 'missing', limit: 20 }
  await getAgentTasks(query); expect(request).toHaveBeenLastCalledWith({ url: '/agent-tasks', method: 'get', params: query })
  const raw = { request: { id: 23 }, session_ids: [], reports: { versions: [] } }
  request.mockResolvedValueOnce(raw); expect(await getAgentTask(23, { limit: 20 })).toBe(raw)
  expect(request).toHaveBeenLastCalledWith({ url: '/agent-tasks/23', method: 'get', params: { limit: 20 } })
})
