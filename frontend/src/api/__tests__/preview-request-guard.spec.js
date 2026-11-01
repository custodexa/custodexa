import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('element-plus', () => ({
  ElMessage: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}))

import { ElMessage } from 'element-plus'
import request, { resetPreviewNoticeForTests } from '../request'
import { logout } from '../auth'
import i18n from '@/i18n'
import { PREVIEW_ALLOWED_NON_GET } from '@/utils/previewOverlay'
import { applyPreviewResponse, beginPreviewRequest, cancelPreview } from '@/composables/useRolePreview'
import { resetCapabilities } from '@/composables/useCapabilities'
import { refreshAccessToken, resetSessionForTests, setAccessToken } from '@/utils/session'

// 預覽中的請求層攔截：非 GET／HEAD／OPTIONS 不送出、單一訊息、不加標頭、例外清單與續期登出照常。
const t = (k) => i18n.global.t(k)
const adapter = vi.fn(async (config) => ({ data: { ok: true }, status: 200, statusText: 'OK', headers: {}, config }))

const enterPreview = () => {
  const r = applyPreviewResponse(beginPreviewRequest(), {
    role: { id: 7, name: 'R7' },
    previewable: true,
    permissions: ['asset:view'],
    entry_states: [],
  })
  expect(r).toEqual({ entered: true })
}

beforeEach(() => {
  resetSessionForTests()
  resetCapabilities()
  resetPreviewNoticeForTests()
  adapter.mockClear()
  vi.clearAllMocks()
  request.defaults.adapter = adapter
})
afterEach(() => {
  cancelPreview()
  vi.unstubAllGlobals()
})

describe('預覽中的寫入攔截', () => {
  it('POST、PUT、PATCH、DELETE 各一例未到達 adapter，呼叫端收到預覽拒絕，訊息只出現一次且不是請求失敗', async () => {
    enterPreview()
    for (const method of ['post', 'put', 'patch', 'delete']) {
      await expect(request({ url: '/assets/1', method, data: {} })).rejects.toMatchObject({ isPreviewBlocked: true })
    }
    expect(adapter).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
    expect(ElMessage.error.mock.calls[0][0].message).toBe(t('rolePreview.blocked'))
    expect(ElMessage.error.mock.calls[0][0].message).not.toBe(t('api.requestFailed'))
  })

  it('簽發類端點逐一未到達', async () => {
    enterPreview()
    const urls = [
      '/connect-tokens',
      '/sessions/1/recording/token',
      '/sessions/1/monitor-token',
      '/sessions/share/token',
    ]
    for (const url of urls) {
      await expect(request({ url, method: 'post', data: {} })).rejects.toMatchObject({ isPreviewBlocked: true })
    }
    expect(adapter).not.toHaveBeenCalled()
  })

  it('例外清單逐條到達，且與凍結內容逐字相同', async () => {
    expect(PREVIEW_ALLOWED_NON_GET.map((e) => `${e.method} ${e.path}`)).toEqual([
      'POST /schedules/next-runs',
      'POST /role-definitions/summary',
      'POST /role-assignment-previews',
    ])
    enterPreview()
    for (const e of PREVIEW_ALLOWED_NON_GET) {
      await request({ url: e.path, method: e.method.toLowerCase(), data: {} })
    }
    expect(adapter).toHaveBeenCalledTimes(PREVIEW_ALLOWED_NON_GET.length)
    // 完整比對、不做前綴比對
    await expect(request({ url: '/schedules/next-runs/extra', method: 'post' })).rejects.toMatchObject({ isPreviewBlocked: true })
  })

  it('GET 請求的標頭集合與非預覽時相同（不加任何標頭）', async () => {
    setAccessToken('tok')
    await request({ url: '/assets', method: 'get' })
    const plain = { ...adapter.mock.calls[0][0].headers.toJSON() }
    adapter.mockClear()
    enterPreview()
    await request({ url: '/assets', method: 'get' })
    expect(adapter).toHaveBeenCalledTimes(1)
    expect({ ...adapter.mock.calls[0][0].headers.toJSON() }).toEqual(plain)
  })

  it('覆蓋不存在時同一組非 GET 全部到達', async () => {
    for (const method of ['post', 'put', 'patch', 'delete']) {
      await request({ url: '/assets/1', method, data: {} })
    }
    for (const url of ['/connect-tokens', '/sessions/1/recording/token']) {
      await request({ url, method: 'post', data: {} })
    }
    expect(adapter).toHaveBeenCalledTimes(6)
    expect(ElMessage.error).not.toHaveBeenCalled()
  })

  it('續期在預覽中仍送出；登出先清覆蓋再送出，不被攔截', async () => {
    enterPreview()
    const fetchSpy = vi.fn(async () => ({ ok: true, status: 200, statusText: 'OK', json: async () => ({ access_token: 'new' }) }))
    vi.stubGlobal('fetch', fetchSpy)
    await refreshAccessToken('').catch(() => {})
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    // 登出流程：先 cancelPreview 再呼叫 logout
    cancelPreview()
    await logout()
    expect(adapter).toHaveBeenCalledTimes(1)
    expect(adapter.mock.calls[0][0].url).toBe('/auth/logout')
  })
})
