import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))
vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import {
  startInventoryScan,
  getAssetInventory,
  ignoreInventoryFinding,
  reopenInventoryFinding,
  listGlobalInventoryFindings,
} from '../hostInventory'

describe('hostInventory API', () => {
  beforeEach(() => vi.clearAllMocks())

  it('發起：POST scans，錯誤就地呈現', () => {
    startInventoryScan(7)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/assets/7/account-inventory/scans',
      method: 'post',
      skipErrorToast: true,
    })
  })

  it('單台讀取：GET 帶篩選與分頁參數', () => {
    getAssetInventory(7, { privileged: true, page: 2, page_size: 50 })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/assets/7/account-inventory',
      method: 'get',
      params: { privileged: true, page: 2, page_size: 50 },
      skipErrorToast: true,
    })
  })

  it('忽略：POST ignore 帶 reason', () => {
    ignoreInventoryFinding(7, 9, '供應商帳號')
    expect(requestMock).toHaveBeenCalledWith({
      url: '/assets/7/account-inventory/findings/9/ignore',
      method: 'post',
      data: { reason: '供應商帳號' },
      skipErrorToast: true,
    })
  })

  it('重新開啟：POST reopen', () => {
    reopenInventoryFinding(7, 9)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/assets/7/account-inventory/findings/9/reopen',
      method: 'post',
      skipErrorToast: true,
    })
  })

  it('全域清單：GET /account-inventory/findings', () => {
    listGlobalInventoryFindings({ page: 1 })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/account-inventory/findings',
      method: 'get',
      params: { page: 1 },
      skipErrorToast: true,
    })
  })
})
