import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import {
  searchAlerts,
  getAlertRules,
  createAlertRule,
  updateAlertRule,
  deleteAlertRule,
} from '../alerts'

describe('alerts API methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('exposes all alert methods as functions', () => {
    expect(typeof searchAlerts).toBe('function')
    expect(typeof getAlertRules).toBe('function')
    expect(typeof createAlertRule).toBe('function')
    expect(typeof updateAlertRule).toBe('function')
    expect(typeof deleteAlertRule).toBe('function')
  })

  it('searchAlerts requests GET /command-alerts with query params', () => {
    const params = {
      severity: 'high',
      user_id: 1,
      asset_id: 2,
      start_time: '2026-06-01T00:00:00Z',
      end_time: '2026-06-12T00:00:00Z',
      page: 1,
      page_size: 20,
    }
    searchAlerts(params)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/command-alerts',
      method: 'get',
      params,
    })
  })

  it('getAlertRules requests GET /alert-rules', () => {
    getAlertRules()
    expect(requestMock).toHaveBeenCalledWith({
      url: '/alert-rules',
      method: 'get',
    })
  })

  it('createAlertRule requests POST /alert-rules with rule payload', () => {
    const data = {
      name: '刪除根目錄',
      pattern: 'rm\\s+-rf\\s+/',
      severity: 'high',
      enabled: true,
    }
    createAlertRule(data)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/alert-rules',
      method: 'post',
      data,
    })
  })

  it('updateAlertRule requests PUT /alert-rules/:id with rule payload', () => {
    const data = {
      name: '格式化磁碟',
      pattern: 'mkfs',
      severity: 'medium',
      enabled: false,
    }
    updateAlertRule(5, data)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/alert-rules/5',
      method: 'put',
      data,
    })
  })

  it('deleteAlertRule requests DELETE /alert-rules/:id', () => {
    deleteAlertRule(7)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/alert-rules/7',
      method: 'delete',
    })
  })
})
