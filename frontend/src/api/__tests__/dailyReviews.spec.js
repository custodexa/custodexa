import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import {
  getDailyReviewStatus,
  signDailyReview,
  getDailyReviews,
} from '../dailyReviews'

describe('dailyReviews API methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('getDailyReviewStatus requests GET /daily-reviews/status', () => {
    getDailyReviewStatus()
    expect(requestMock).toHaveBeenCalledWith({
      url: '/daily-reviews/status',
      method: 'get',
    })
  })

  it('signDailyReview requests POST /daily-reviews with note payload', () => {
    signDailyReview({ note: '審閱無異常' })
    expect(requestMock).toHaveBeenCalledWith({
      url: '/daily-reviews',
      method: 'post',
      data: { note: '審閱無異常' },
    })
  })

  it('getDailyReviews requests GET /daily-reviews with pagination params', () => {
    const params = { page: 2, page_size: 10 }
    getDailyReviews(params)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/daily-reviews',
      method: 'get',
      params,
    })
  })
})
