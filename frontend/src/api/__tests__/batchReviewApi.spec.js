import { describe, it, expect, vi, beforeEach } from 'vitest'

// 批次審閱沿用既有單筆端點：只多帶 batch_id 與（呼叫端要求時）skipErrorToast，
// 既有單筆呼叫的請求設定必須維持原樣
const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import { searchAlerts, reviewAlert } from '../alerts'
import {
  approveAccessRequest,
  rejectAccessRequest,
  reviewBreakGlass,
  getPendingAccessRequests,
  getAccessRequestHistory,
  getPendingReviews,
} from '../accessRequests'

const BATCH_ID = '0b8e4c0e-2f1a-4b7a-9c3d-5e6f7a8b9c0d'

describe('批次審閱 API 用法', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('searchAlerts 以 ids 查指定告警，並可關閉全域 toast', () => {
    searchAlerts({ ids: '1,2', page: 1, page_size: 2 }, { skipErrorToast: true })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/command-alerts',
      method: 'get',
      params: { ids: '1,2', page: 1, page_size: 2 },
      skipErrorToast: true,
    })
  })

  it('reviewAlert 批次呼叫帶 batch_id；單筆呼叫設定不變', () => {
    reviewAlert(3, { disposition: 'benign', note: 'n', batch_id: BATCH_ID }, { skipErrorToast: true })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/command-alerts/3/review',
      method: 'post',
      data: { disposition: 'benign', note: 'n', batch_id: BATCH_ID },
      skipErrorToast: true,
    })
    reviewAlert(3, { disposition: 'benign', note: '' })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/command-alerts/3/review',
      method: 'post',
      data: { disposition: 'benign', note: '' },
    })
  })

  it('approveAccessRequest 批次 body 原樣送出', () => {
    approveAccessRequest(107, { items: [{ item_id: 1 }], batch_id: BATCH_ID }, { skipErrorToast: true })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/access-requests/107/approve',
      method: 'post',
      data: { items: [{ item_id: 1 }], batch_id: BATCH_ID },
      skipErrorToast: true,
    })
  })

  it('rejectAccessRequest 帶 batchId 時 body 加 batch_id，不帶 item_id；單張呼叫不變', () => {
    rejectAccessRequest(108, '凍結', { batchId: BATCH_ID, skipErrorToast: true })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/access-requests/108/reject',
      method: 'post',
      data: { note: '凍結', batch_id: BATCH_ID },
      skipErrorToast: true,
    })
    rejectAccessRequest(108, '凍結')
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/access-requests/108/reject',
      method: 'post',
      data: { note: '凍結' },
    })
  })

  it('reviewBreakGlass 帶 batchId 時 body 加 batch_id；單筆呼叫不變', () => {
    reviewBreakGlass(40, 'confirmed', '事故', { batchId: BATCH_ID, skipErrorToast: true })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/access-requests/40/review',
      method: 'post',
      data: { disposition: 'confirmed', note: '事故', batch_id: BATCH_ID },
      skipErrorToast: true,
    })
    reviewBreakGlass(40, 'violation', '違規')
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/access-requests/40/review',
      method: 'post',
      data: { disposition: 'violation', note: '違規' },
    })
  })

  it('收尾查詢用的清單端點可關閉全域 toast，預設呼叫不帶旗標', () => {
    getPendingAccessRequests({ skipErrorToast: true })
    expect(requestMock).toHaveBeenLastCalledWith({ url: '/access-requests/pending', method: 'get', skipErrorToast: true })
    getPendingAccessRequests()
    expect(requestMock).toHaveBeenLastCalledWith({ url: '/access-requests/pending', method: 'get' })
    getAccessRequestHistory({ page: 1, page_size: 100 }, { skipErrorToast: true })
    expect(requestMock).toHaveBeenLastCalledWith({
      url: '/access-requests/history',
      method: 'get',
      params: { page: 1, page_size: 100 },
      skipErrorToast: true,
    })
    getPendingReviews()
    expect(requestMock).toHaveBeenLastCalledWith({ url: '/access-requests/reviews/pending', method: 'get' })
  })
})
