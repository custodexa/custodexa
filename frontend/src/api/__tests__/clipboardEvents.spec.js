import { describe, it, expect, vi, beforeEach } from 'vitest'

const requestMock = vi.fn(() => Promise.resolve({}))

vi.mock('../request', () => ({
  default: (...args) => requestMock(...args),
}))

import {
  getSessionClipboardEvents,
  getClipboardEventContent,
} from '../clipboardEvents'

describe('clipboardEvents API methods', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('exposes all clipboard event methods as functions', () => {
    expect(typeof getSessionClipboardEvents).toBe('function')
    expect(typeof getClipboardEventContent).toBe('function')
  })

  it('getSessionClipboardEvents requests GET /sessions/:id/clipboard-events', () => {
    getSessionClipboardEvents('abc-123')
    expect(requestMock).toHaveBeenCalledWith({
      url: '/sessions/abc-123/clipboard-events',
      method: 'get',
    })
  })

  it('getClipboardEventContent requests GET /sessions/:id/clipboard-events/:eventID/content', () => {
    getClipboardEventContent('abc-123', 42)
    expect(requestMock).toHaveBeenCalledWith({
      url: '/sessions/abc-123/clipboard-events/42/content',
      method: 'get',
    })
  })
})
